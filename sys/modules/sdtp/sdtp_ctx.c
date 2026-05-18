/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include <sys/param.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockopt.h>
#include <sys/ktls.h>
#include <sys/uio.h>

#include <opencrypto/cryptodev.h>
#include <opencrypto/ktls.h>

#include "sdtp_os.h"
#include "sdtp_ctx.h"
#include "sdtp_debug.h"
#include "sdtp_structs.h"

extern struct sdtp_zones zones;

static inline uint32_t
ms_rthash(const uint32_t addr, const uint16_t port)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0;
	const uint8_t *p;

	p = (const uint8_t *)&port;
	b += p[1] << 16;
	b += p[0] << 8;
	p = (const uint8_t *)&addr;
	b += p[3];
	a += p[2] << 24;
	a += p[1] << 16;
	a += p[0] << 8;

	a -= b; a -= c; a ^= (c >> 13);
	b -= c; b -= a; b ^= (a << 8);
	c -= a; c -= b; c ^= (b >> 13);
	a -= b; a -= c; a ^= (c >> 12);
	b -= c; b -= a; b ^= (a << 16);
	c -= a; c -= b; c ^= (b >> 5);
	a -= b; a -= c; a ^= (c >> 3);
	b -= c; b -= a; b ^= (a << 10);
	c -= a; c -= b; c ^= (b >> 15);

	return c;
}

static inline struct sdtp_ctx_list *
sdtp_get_ctx_bucket(struct sdtp_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	int idx = ms_rthash(peer_addr_be, peer_port_be) & (SDTP_SERVER_RPC_BUCKETS - 1);
	return (&pcb->ctx_map.buckets[idx]);
}

static struct sdtp_ctx *
__sdtp_find_ctx(struct sdtp_ctx_list *bucket, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	KASSERT(bucket != NULL, ("%s: bucket must be valid", __func__));

	struct sdtp_ctx *ctx;
	
	if (LIST_EMPTY(bucket)) {
		return (NULL);
	}

	LIST_FOREACH(ctx, bucket, hash_links) {
		if (ctx->addr_be == peer_addr_be && ctx->port_be == peer_port_be) {
			sdtp_ctx_hold(ctx);
			return (ctx);
		}
	}

	return (NULL);
}

static struct sdtp_ctx *
sdtp_find_ctx(struct sdtp_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct sdtp_ctx_list *bucket;

	bucket = sdtp_get_ctx_bucket(pcb, peer_addr_be, peer_port_be);
	return __sdtp_find_ctx(bucket, peer_addr_be, peer_port_be);
}

static struct sdtp_ctx *
sdtp_get_ctx(struct sdtp_inpcb *pcb, uint32_t peer_addr_be, uint16_t peer_port_be, int *error)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct sdtp_ctx_list *bucket;
	struct sdtp_ctx *ctx;

	bucket = sdtp_get_ctx_bucket(pcb, peer_addr_be, peer_port_be);
	ctx = __sdtp_find_ctx(bucket, peer_addr_be, peer_port_be);
	if (ctx == NULL) {
		ctx = sdtp_pool_alloc_ctx();
		if (ctx == NULL) {
			*error = ENOMEM;
			return (NULL);
		}
		LIST_INSERT_HEAD(bucket, ctx, hash_links);
		sdtp_ctx_hold(ctx);
	}

	return ctx;
}

static void
sdtp_free_tls_state(struct sdtp_tls_state *state)
{
	if (state->active) {
		ktls_cleanup_tls_enable(&state->en);
		state->active = false;

		if (state->session != NULL) {
			ktls_free(state->session);
			state->session = NULL;
		}
	}
}

void
sdtp_free_ctx(struct sdtp_ctx *ctx)
{
	KASSERT(ctx != NULL, ("%s: ctx must be valid", __func__));

	LIST_REMOVE(ctx, hash_links);
	sdtp_free_tls_state(&ctx->tx);
	sdtp_free_tls_state(&ctx->rx);
	explicit_bzero(ctx, sizeof(*ctx));
	sdtp_pool_free_ctx(ctx);
}

int
sdtp_rpc_ctx_init(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
	VALID_PCB_ASSERT(pcb);
	VALID_RPC_ASSERT(rpc);

	return (0);
}

static int
sdtp_ktls_copyin_tls_enable(struct sockopt *sopt, struct sdtp_tls_enable *sen)
{
	int error;

	error = sooptcopyin(sopt, sen, sizeof(*sen), sizeof(*sen));
	if (error != 0) {
		return (error);
	}

	return __ktls_copyin_tls_enable(sopt, &sen->tls);
}

static int
sdtp_validate_tls_enable(struct sdtp_inpcb *pcb, struct sdtp_tls_enable *sen)
{
	int error = 0;

	if (sen->tls.tls_vmajor != TLS_MAJOR_VER_ONE) {
		sdtp_pcb_debug(pcb, "tls_vmajor invalid: %d", sen->tls.tls_vmajor);
		error = EINVAL;
		goto sdtp_validate_tls_enable_out;
	}

	switch (sen->tls.tls_vminor) {
	case TLS_MINOR_VER_TWO:
		break;
	case TLS_MINOR_VER_THREE:
		sdtp_pcb_debug(pcb, "TLS 1.3 isn't supported yet");
		error = EINVAL;
		goto sdtp_validate_tls_enable_out;
	default:
		sdtp_pcb_debug(pcb, "tls_vminor invalid: %d", sen->tls.tls_vmajor);
		error = EINVAL;
		goto sdtp_validate_tls_enable_out;
	}

	if (sen->tls.cipher_algorithm != CRYPTO_AES_NIST_GCM_16 ||
	    sen->tls.cipher_key_len != 16) {

		sdtp_pcb_debug(pcb, "Algorithm not supported: %d, %d",
		 sen->tls.cipher_algorithm, sen->tls.auth_algorithm);
		error = EINVAL;
		goto sdtp_validate_tls_enable_out;
	}

sdtp_validate_tls_enable_out:
	return error;
}

// TODO: improve these two functions!!!

static int
sdtp_new_ktls(struct sdtp_inpcb *pcb, struct sdtp_tls_enable *sen, struct ktls_session **ktls, int direction)
{
	int error = 0;

	error = ktls_create_session(sdtp_so(pcb), &sen->tls, ktls, direction);
	if (error != 0) {
		sdtp_pcb_debug(pcb, "failed to create session: %d", error);
		return (error);
	}

	error = ktls_ocf_try(*ktls, direction);
	if (error != 0) {
		sdtp_pcb_debug(pcb, "failed to ocf session: %d", error);
		return (error);
	}

	error = ktls_try_ifnet(sdtp_so(pcb), *ktls, direction, false);
	if (error) {
		sdtp_pcb_debug(pcb, "failed ktls ifnet offload: %d", error);
		ktls_use_sw(*ktls);
		error = 0;
	}

	return (error);
}

static void
sdtp_assign_reuse_ctx(struct sdtp_inpcb *pcb, struct sdtp_ctx *ctx)
{
	if (pcb->ctx_map.reuse_ctx == ctx) {
		return;
	}

	if (pcb->ctx_map.reuse_ctx != NULL) {
		sdtp_ctx_put(pcb->ctx_map.reuse_ctx);
	}

	pcb->ctx_map.reuse_ctx = ctx;
	sdtp_ctx_hold(ctx);
}

int
sdtp_ctx_enable(struct sdtp_inpcb *pcb, struct sockopt *sopt, bool is_tx)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_NOTOWNED(pcb);

	bool moved_en = false;
	int error = 0, direction = (is_tx) ? KTLS_TX : KTLS_RX;
	struct sdtp_tls_enable sen;
	struct sdtp_ctx *ctx = NULL;
	struct ktls_session *ktls = NULL;
	struct sdtp_tls_state *slot = NULL;

	if (!ktls_offload_enabled()) {
		return (ENOTSUP);
	}

	error = sdtp_ktls_copyin_tls_enable(sopt, &sen);
	if (error != 0) {
		sdtp_pcb_debug(pcb, "ktls copyin failed: %d", error);
		/* don't go to out because sen.tls is invalid */
		return (error);
	}

	error = sdtp_validate_tls_enable(pcb, &sen);
	if (error != 0) {
		sdtp_pcb_debug(pcb, "sdtp_tls_enable validation failed: %d", error);
		goto sdtp_ctx_enable_out;
	}

	sdtp_pcb_lock(pcb);
	ctx = sdtp_get_ctx(pcb, sen.peer_addr_be, sen.peer_port_be, &error);
	if (ctx == NULL) {
		sdtp_pcb_debug(pcb, "failed getting ctx: %d", error);
		goto sdtp_ctx_enable_locked;
	}

	slot = (is_tx) ? &ctx->tx : &ctx->rx;
	if (!slot->active) {
		sdtp_pcb_unlock(pcb);
		error = sdtp_new_ktls(pcb, &sen, &ktls, direction);
		sdtp_pcb_lock(pcb);

		if (error != 0) {
			sdtp_ctx_put(ctx);
			goto sdtp_ctx_enable_locked;
		}

		// we dropped the lock so we need to check again
		slot = (is_tx) ? &ctx->tx : &ctx->rx;
		if (slot->active) {
			error = EALREADY;
			sdtp_ctx_put(ctx);
			goto sdtp_ctx_enable_locked;
		}

		slot->en = sen.tls;
		moved_en = true;
		slot->session = ktls;
		ktls = NULL;
		slot->active = true;

	}

	if ((sen.peer_addr_be == 0) && (sen.peer_port_be == 0)) {
		sdtp_assign_reuse_ctx(pcb, ctx);
	}

	sdtp_pcb_debug(pcb, "ktls %s enabled", (is_tx) ? "tx" : "rx");
	sdtp_ctx_put(ctx);

sdtp_ctx_enable_locked:
	sdtp_pcb_unlock(pcb);

sdtp_ctx_enable_out:
	if (ktls != NULL) {
		ktls_free(ktls);
	}
	if (!moved_en) {
		ktls_cleanup_tls_enable(&sen.tls);
	}
	return (error);
}
