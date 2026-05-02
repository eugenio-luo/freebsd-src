/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_OUTPUT_H_
#define _SDTP_OUTPUT_H_

#include "sdtp.h"
#include "sdtp_rpc.h"

void sdtp_resend_data(struct sdtp_rpc *rpc, int start, int end, int priority);
void sdtp_send_unknown(struct sdtp_inpcb *pcb, struct mbuf *m,
    struct in6_addr *source);
int sdtp_send_control(struct sdtp_rpc *rpc, enum sdtp_pkt_type type, void *data,
    size_t len);
int sdtp_message_out(struct sdtp_rpc *rpc, struct uio *uio,
    bool immediate_send);
int sdtp_send_control_buf(struct sdtp_inpcb *pcb, struct sdtp_peer *peer,
    void *data, size_t len);

#endif
