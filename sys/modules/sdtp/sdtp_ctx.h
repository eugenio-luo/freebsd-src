/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_CTX_H_
#define _SDTP_CTX_H_

#include <sys/ktls.h>

#include "sdtp_common.h"
#include "sdtp_utils.h"

struct sdtp_inpcb;
struct sdtp_rpc;

struct sdtp_tls_enable {
	uint32_t          peer_addr_be;
	uint16_t          peer_port_be;
	uint32_t          local_addr_be;
	struct tls_enable tls;
};

struct sdtp_tls_state {
	struct tls_enable    en;

	/*
	 * session can be NULL even if state is active,
	 * when the state is cloned, the session won't be
	 * cloned, and it should be lazily initialized when
	 * the user tries to recv or send.
	 */
	struct ktls_session *session;

	bool                 active;
};

struct sdtp_ctx {
	struct sdtp_tls_state tx;
	struct sdtp_tls_state rx;

	uint32_t addr_be;
	uint16_t port_be;

	sdtp_ref_t refs;

	LIST_ENTRY(sdtp_ctx) hash_links;
};

struct sdtp_rpc_crypto {
	struct sdtp_ctx *ctx;

	unsigned int max;
	int offset;
};

struct sdtp_ctx_map {
	struct sdtp_ctx_list buckets[SDTP_SERVER_RPC_BUCKETS];
	struct sdtp_ctx *reuse_ctx;
	bool active;
};

int sdtp_rpc_ctx_init(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc);
int sdtp_ctx_enable(struct sdtp_inpcb *pcb, struct sockopt *sopt, bool is_tx);
void sdtp_free_ctx(struct sdtp_ctx *ctx);

static inline void
sdtp_ctx_hold(struct sdtp_ctx *ctx)
{
	refcount_acquire(&ctx->refs);
}

static inline void
sdtp_ctx_put(struct sdtp_ctx *ctx)
{
	KASSERT(refcount_load(&ctx->refs) > 0,
	    ("ctx cannot have negative refs"));

	if (refcount_release(&ctx->refs)) {
		sdtp_free_ctx(ctx);
	}
}

#endif
