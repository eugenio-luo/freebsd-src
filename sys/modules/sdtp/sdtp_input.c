/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp.h"
#include "sdtp_pcb.h"
#include "sdtp_structs.h"
#include "sdtp_input.h"
#include "sdtp_debug.h"

#include <netinet/ip_icmp.h>

#ifdef INET6
#include <netinet6/icmp6.h>
#endif

extern struct sdtp *sdtp;

static struct sdtp_inpcb *
check_headers(struct mbuf *m, int iphlen, bool *should_send_icmp)
{
    KASSERT(iphlen > 0, ("IP header length must be positive"));
    KASSERT(m != NULL, ("m must be valid"));
    MBUF_LEN_AT_LEAST(m, iphlen + sizeof(struct sdtp_common_header));
    KASSERT(*should_send_icmp == false, ("should_send_icmp must be false"));

    struct ip *ip_header;
    struct sdtp_common_header *sdtp_header;
    struct sdtp_inpcb *pcb;
    uint16_t dport;

    ip_header = mtod(m, struct ip *);
    sdtp_header = (struct sdtp_common_header *)((caddr_t)ip_header + iphlen);

    if (sdtp_header->type < SDTP_DATA || sdtp_header->type > SDTP_ACK) {
        return NULL;
    }

    if (m->m_pkthdr.len < sdtp_header_lengths[sdtp_header->type - SDTP_DATA]) {
        return NULL;
    }

    // TODO: Implement FREEZE packet here?

    dport = ntohs(sdtp_header->dport_be);

    mtx_lock_spin(&sdtp->port_map.write_spinlock);
    pcb = sdtp_find_inpcb(&sdtp->port_map, dport);
    mtx_unlock_spin(&sdtp->port_map.write_spinlock);

    if (pcb == NULL || pcb->socket == NULL) {
        *should_send_icmp = true;
    }
    return pcb;
}

int
sdtp_input(struct mbuf **mp, int *offp, int proto)
{
    struct sdtp_inpcb *pcb = NULL;
    struct mbuf *m;
    struct ip *ip_header;
    struct in6_addr addr;
    int offset, iphlen;
    bool is_buffer_consumed = false, should_send_icmp = false;

    m = *mp;
    iphlen = *offp;
    offset = iphlen + sizeof(struct sdtp_common_header);

    m = m_pullup(m, offset);
    if (m == NULL) {
        goto sdtp_input_done;
    }

    ip_header = mtod(m, struct ip *);

    pcb = check_headers(m, iphlen, &should_send_icmp);
    if (pcb == NULL) {
        if (should_send_icmp) {
            KASSERT(ip_header->ip_v == IPVERSION, ("ip version must be IP_VERSION"));
            icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
            is_buffer_consumed = true;
        }

        goto sdtp_input_done;
    }

    ipv4_to_ipv6(&ip_header->ip_src, &addr);

    /* Adjust the buffer so we don't have the ip header */
    m_adj(m, iphlen);
    m = m_pullup(m, sizeof(struct sdtp_common_header));
    if (!m) {
        goto sdtp_input_done;
    }

    is_buffer_consumed = sdtp_handle_packet(m, &addr, pcb);

sdtp_input_done:
    // TODO: add sdtp_send_grants(sdtp);

    if (pcb) {
        mtx_assert(&pcb->spinlock, MA_NOTOWNED);
        mtx_assert(&pcb->sdtp->port_map.write_spinlock, MA_NOTOWNED);
        mtx_assert(&pcb->sdtp->peers.write_spinlock, MA_NOTOWNED);
    }

    if (is_buffer_consumed) {
        *mp = NULL;
    }
    return IPPROTO_DONE;
}

int
sdtp6_input(struct mbuf **mp, int *offp, int proto)
{

/*
#ifdef INET6
        if (ip_header->ip_v == (IPV6_VERSION >> 4)) {
            icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, 0, 0);
        }
#endif
*/

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
