/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp.h"
#include "sdtp_input.h"

int
sdtp_input(struct mbuf **mp, int *offp, int proto)
{
    struct mbuf *m;
    struct ip *ip_header;
    struct sdtp_common_header *sdtp_header;
    int offset, iphlen;
    uint16_t dport;

    m = *mp;
    iphlen = *offp;

    offset = iphlen + sizeof(struct sdtp_common_header);
    if (m->m_len < offset) {
        m = m_pullup(m, offset);
        if (m == NULL) {
            return IPPROTO_DONE;
        }
    }
    ip_header = mtod(m, struct ip *);
    sdtp_header = (struct sdtp_common_header *)((caddr_t)ip_header + iphlen);

    if (sdtp_header->type < SDTP_DATA || sdtp_header->type > SDTP_ACK) {
        return IPPROTO_DONE;
    }

    dport = ntohs(sdtp_header->dport_be);

    uprintf("sdtp_header type: %d, dport: %d\n", sdtp_header->type, dport);

    return IPPROTO_DONE;
}

int
sdtp6_input(struct mbuf **mp, int *offp, int proto)
{
    return IPPROTO_DONE;
}

void
sdtp_ctlinput(struct icmp *icmp)
{
    return;
}

void
sdtp6_ctlinput(struct ip6ctlparam *ip6cp)
{
    return;
}
