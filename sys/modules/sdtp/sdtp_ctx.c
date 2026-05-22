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

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_private.h>
#include <net/if_types.h>
#include <net/route/nhop.h>
#include <netinet/in.h>
#include <netinet/ip.h>

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
		if (!state->copy) {
			ktls_cleanup_tls_enable(&state->en);
		}

		if (state->session != NULL) {
			ktls_free(state->session);
			state->session = NULL;
		}

		state->active = false;
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

/*
 * This is a shallow clone, ktls_session won't be cloned,
 * instead it will be lazily created when it will be used.
 */
static struct sdtp_ctx *
sdtp_clone_reuse_ctx(struct sdtp_inpcb *pcb, uint32_t addr_be, uint16_t port_be, int *error)
{
	VALID_PCB_ASSERT(pcb);
	PCB_LOCK_OWNED(pcb);

	struct sdtp_ctx *reuse_ctx, *ctx;

	reuse_ctx = pcb->ctx_map.reuse_ctx;
	if (reuse_ctx == NULL) {
		return (NULL);
	}
	KASSERT(reuse_ctx->tx.active || reuse_ctx->rx.active, ("at least one direction must be active"));

	ctx = sdtp_get_ctx(pcb, addr_be, port_be, error);
	if (ctx == NULL) {
		return (NULL);
	}

	ctx->tx = reuse_ctx->tx;
	ctx->rx = reuse_ctx->rx;
	ctx->addr_be = reuse_ctx->addr_be;
	ctx->port_be = reuse_ctx->port_be;

	if (ctx->tx.active) {
		ctx->tx.copy = true;
		ctx->tx.session = NULL;

		struct tls_enable *en = &ctx->tx.en;
		KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
			("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
			 en->cipher_algorithm));
		KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
			("tls major version must be 1, instead: %d",
			 en->tls_vmajor));
		KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
			("tls minor version must be 2, instead: %d",
			 en->tls_vminor));
	}
	if (ctx->rx.active) {
		ctx->rx.copy = true;
		ctx->rx.session = NULL;

		struct tls_enable *en = &ctx->rx.en;
		KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
			("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
			 en->cipher_algorithm));
		KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
			("tls major version must be 1, instead: %d",
			 en->tls_vmajor));
		KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
			("tls minor version must be 2, instead: %d",
			 en->tls_vminor));
	}

	sdtp_pcb_debug(pcb, "cloned ctx with rx: %d, tx: %d", ctx->rx.active, ctx->tx.active);
	return (ctx);
}

int
sdtp_rpc_ctx_init(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
	VALID_PCB_ASSERT(pcb);
	VALID_RPC_ASSERT(rpc);
	PCB_LOCK_OWNED(pcb);
	KASSERT(pcb->ctx_map.active == true, ("pcb must have ctx map"));

	struct sdtp_ctx *ctx;
	int error = 0;
	uint32_t addr_be;
	uint16_t port_be, mtu;

	ipv6_to_ipv4(&rpc->peer->addr, (struct in_addr *) &addr_be);
	port_be = htons(rpc->dport);

	ctx = sdtp_find_ctx(pcb, addr_be, port_be);
	if (ctx == NULL) {
	        ctx = sdtp_clone_reuse_ctx(pcb, addr_be, port_be, &error);
	        if (ctx == NULL) {
	                return (error);
	        }
	}

	KASSERT(NH_IS_VALID(rpc->peer->nh), ("nh must be valid"));
	mtu = rpc->peer->nh->nh_mtu;

	rpc->crypto.ctx = ctx;
	rpc->crypto.offset = 0;
	rpc->crypto.max = mtu -
	    IP_SDTP_HEADER_SIZE(rpc->sdtpcb, struct sdtp_data_header);

	sdtp_rpc_debug(rpc, "successful ctx init");

	return (0);
}

static int
sdtp_ktls_copyin_tls_enable(struct sockopt *sopt, struct sdtp_tls_args *sen)
{
	int error;

	error = sooptcopyin(sopt, sen, sizeof(*sen), sizeof(*sen));
	if (error != 0) {
		return (error);
	}

	return __ktls_copyin_tls_enable(sopt, &sen->tls);
}

static int
sdtp_validate_tls_enable(struct sdtp_inpcb *pcb, struct sdtp_tls_args *sen)
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
sdtp_new_ktls(struct sdtp_inpcb *pcb, struct sdtp_tls_args *sen, struct ktls_session **ktls, int direction)
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

	/*
	 * Making it possible to change reuse ctx means
	 * that we'll have a lot of invalid refs.
	 */
	if (pcb->ctx_map.reuse_ctx != NULL) {
		KASSERT(0, ("changing reuse_ctx not implemented yet"));
		// sdtp_ctx_put(pcb->ctx_map.reuse_ctx);
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
	struct sdtp_tls_args sen;
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
		sdtp_pcb_debug(pcb, "sdtp_tls_args validation failed: %d", error);
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
		slot->copy = false;
	}

	if ((sen.peer_addr_be == 0) && (sen.peer_port_be == 0)) {
		sdtp_assign_reuse_ctx(pcb, ctx);
	}

	sdtp_pcb_debug(pcb, "ktls %s enabled", (is_tx) ? "tx" : "rx");
	sdtp_ctx_put(ctx);

	pcb->ctx_map.active = true;

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

static inline uint8_t
sdtp_extra_ip_id(struct sdtp_data_header *header)
{
	return (header->retransmit >> 4) & 0x0F;
}

static inline uint16_t
sdtp_logical_ip_id(struct sdtp_data_header *header, struct ip *ip_header)
{
	if (header->retransmit & 0x1) {
		return sdtp_extra_ip_id(header);
	}

	return ntohs(ip_header->ip_id);
}

static inline uint32_t
sdtp_gso_offset(struct sdtp_data_header *header)
{
	return ((uint8_t) header->padding[0] << 16)
		| ((uint8_t) header->padding[1] << 8)
		| ((uint8_t) header->padding[2]);
}

/*
 * For sdtp_pre_len and sdtp_post_len we cannot use the ktls_session
 * parameters because we don't have the guarantee that they are present.
 */

static inline int
sdtp_pre_len(struct sdtp_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("ctx must be valid"));

	/*
	KASSERT(rpc->crypto.ctx->rx.session != NULL, ("RX session must be valid"));
	struct ktls_session *session = rpc->crypto.ctx->rx.session;
	int len = session->params.tls_hlen;
	*/

	struct tls_enable *en = &rpc->crypto.ctx->rx.en;

	KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
		("cipher algorithm must be CRYPTO_AES_NIST_GCM_16, instead: %d",
		 en->cipher_algorithm));
	KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
		("tls major version must be 1, instead: %d",
		 en->tls_vmajor));
	KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
		("tls minor version must be 2, instead: %d",
		 en->tls_vminor));

	int len = sizeof(struct tls_record_layer) + sizeof(uint64_t);
	KASSERT(len > 0, ("%s: len must be positive: %d", __func__, len));
	return (len);
}

static inline int
sdtp_post_len(struct sdtp_rpc *rpc)
{
	VALID_RPC_ASSERT(rpc);
	KASSERT(rpc->crypto.ctx != NULL, ("ctx must be valid"));

	/*
	KASSERT(rpc->crypto.ctx->rx.session != NULL, ("RX session must be valid"));
	struct ktls_session *session = rpc->crypto.ctx->rx.session;
	int len = session->params.tls_tlen;
	*/

	struct tls_enable *en = &rpc->crypto.ctx->rx.en;

	KASSERT(en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16,
		("cipher algorithm must be CRYPTO_AES_NIST_GCM_16"));
	KASSERT(en->tls_vmajor == TLS_MAJOR_VER_ONE,
		("tls major version must be 1"));
	KASSERT(en->tls_vminor == TLS_MINOR_VER_TWO,
		("tls minor version must be 2"));

	int len = AES_GMAC_HASH_LEN;
	KASSERT(len > 0, ("%s: len must be positive: %d", __func__, len));
	return (len);
}

static inline int
sdtp_logical_offset(struct sdtp_rpc *rpc, uint16_t ip_id, uint32_t gso_offset)
{
	VALID_RPC_ASSERT(rpc);

	int max = rpc->crypto.max, extra_len = sdtp_pre_len(rpc) + sdtp_post_len(rpc);
	int offset = (int)(ip_id * max + gso_offset);

	if (ip_id != 0) {
		offset -= extra_len;
	}

	KASSERT(offset >= 0, ("offset must be not negative: %d", offset));
	return (offset);
}

static inline int
sdtp_logical_data_bytes(struct sdtp_rpc *rpc, struct mbuf *m, int iphlen, uint16_t ip_id)
{
	VALID_RPC_ASSERT(rpc);

	int len = sdtp_payload_len(m, iphlen);
	int post_len = sdtp_post_len(rpc);
	int extra_len = sdtp_pre_len(rpc) + post_len;

	if (ip_id == 0) {
		len -= extra_len;
	}
	KASSERT(len > 0, ("%s: len must be positive: %d", __func__, len));

	if (len + sizeof(struct sdtp_data_segment) > post_len) {
		return len;
	}
	return len + sizeof(struct sdtp_data_segment);
}

static inline bool
sdtp_trailer_only(struct sdtp_rpc *rpc, int data_bytes, uint16_t ip_id)
{
	VALID_RPC_ASSERT(rpc);

	if (ip_id == 0) {
		return false;
	}

	return (data_bytes <= sdtp_post_len(rpc));
}

struct sdtp_rx_logical_info
sdtp_calc_rx_logical_info(struct sdtp_rpc *rpc, struct mbuf *m)
{
	VALID_RPC_ASSERT(rpc);
	VALID_PCB_ASSERT(rpc->sdtpcb);
	KASSERT(m != NULL, ("m must be valid"));

	int iphlen = rpc->sdtpcb->iphlen;
	int payload_len = sdtp_payload_len(m, iphlen);
	int record_len, max_frame_data;
	MBUF_LEN_AT_LEAST(m, sizeof(struct sdtp_data_header) - sizeof(struct sdtp_data_segment)
		   + iphlen + sizeof(struct tls_record_layer));

	struct sdtp_data_header *header = SDTP_MTOD(m, struct sdtp_data_header *, iphlen);
	struct ip *ip_header = mtod(m, struct ip *);
	uint8_t *record_header;

	struct sdtp_rx_logical_info info;
	uint16_t ip_id = sdtp_logical_ip_id(header, ip_header);
	uint32_t gso_offset = sdtp_gso_offset(header);

	info.start = sdtp_logical_offset(rpc, ip_id, gso_offset);
	info.length = sdtp_logical_data_bytes(rpc, m, iphlen, ip_id);
	info.end = info.start + info.length;
	info.trailer_only = sdtp_trailer_only(rpc, info.length, ip_id);

	if (ip_id != 0 || payload_len + sizeof(struct sdtp_data_header) < sdtp_pre_len(rpc)) {
		goto sdtp_calc_rx_logical_info_out;
	}

	info.record_data_offset = info.start;
	record_header = SDTP_MTOD(m, uint8_t *, iphlen) + sizeof(struct sdtp_data_header)
		- sizeof(struct sdtp_data_segment);

	if ((record_header[0] != 0x17) || (record_header[1] != 0x03) || (record_header[2] != 0x03)) {
		sdtp_rpc_debug(rpc, "invalid TLS record: %d, %d, %d",
		 record_header[0], record_header[1], record_header[2]);
		goto sdtp_calc_rx_logical_info_out;
	}

	record_len = (((uint16_t) record_header[3]) << 8) | (record_header[4] & 0xFF);
	if (record_len <= 0) {
		sdtp_rpc_debug(rpc, "TLS record len not positive: %d", record_len);
		goto sdtp_calc_rx_logical_info_out;
	}

	info.record_data_len = record_len + sizeof(struct tls_record_layer) - sdtp_post_len(rpc);
	max_frame_data = rpc->crypto.max + sizeof(struct sdtp_data_segment);
	info.record_data_len -= ((info.record_data_len + max_frame_data - 1) / max_frame_data)
		* sizeof(struct sdtp_data_segment);
	info.record_data_len -= sdtp_pre_len(rpc);

	sdtp_rpc_debug(rpc, "start: %d, length: %d, end: %d, trailer_only: %d, record_data_offset: %d, record_data_len: %d",
		info.start, info.length, info.end, info.trailer_only, info.record_data_offset, info.record_data_len);
	return info;

sdtp_calc_rx_logical_info_out:
	info.record_data_offset = -1;
	info.record_data_len = -1;
	return info;
}
