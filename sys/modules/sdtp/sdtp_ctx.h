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

struct sdtp_inpcb;
struct sdtp_rpc;

struct sdtp_ctx {
	uint8_t tx_conf:3;
	uint8_t rx_conf:3;

	struct tls_enable tls_send;
	struct tls_enable tls_recv;

	uint32_t addr_be;
	uint32_t port_be;

	void *offload_tx;
	void *offload_rx;
};

struct sdtp_ctx_map {
	struct sdtp_ctx_list buckets[SDTP_SERVER_RPC_BUCKETS];
	struct sdtp_ctx *reuse_ctx;
};

int sdtp_rpc_ctx_init(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc);
int sdtp_ctx_enable(struct sdtp_inpcb *pcb, struct sockopt *sopt, bool is_tx);

#endif
