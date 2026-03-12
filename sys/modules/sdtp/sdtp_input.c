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

static bool
sdtp_check_conditions(const struct sdtp_common_header * const header, const struct mbuf * const m)
{
    KASSERT(header != NULL, ("header must be valid"));
    KASSERT(m != NULL, ("m must be valid"));
    MBUF_LEN_ASSERT(m, struct sdtp_common_header);

    if (header->type < SDTP_DATA || header->type > SDTP_ACK) {
        return false;
    }

    if (m->m_pkthdr.len < sdtp_header_lengths[header->type - SDTP_DATA]) {
        return false;
    }

    return true;
}

static struct sdtp_inpcb *
sdtp_get_pcb(const struct sdtp_common_header * const header)
{
    KASSERT(header != NULL, ("header must be valid"));
    KASSERT(sdtp != NULL, ("sdtp struct must be valid"));

    uint16_t dport;
    struct sdtp_inpcb *pcb;

    dport = ntohs(header->dport_be);

    mtx_lock_spin(&sdtp->port_map.write_spinlock);
    pcb = sdtp_find_inpcb(&sdtp->port_map, dport);
    mtx_unlock_spin(&sdtp->port_map.write_spinlock);

    if (pcb) {
        VALID_PCB_ASSERT(pcb);
    }
    return (pcb != NULL && pcb->socket != NULL) ? pcb : NULL;
}

static void
check_pcb_locks(struct sdtp_inpcb *pcb)
{
    mtx_assert(&pcb->spinlock, MA_NOTOWNED);
    mtx_assert(&pcb->sdtp->port_map.write_spinlock, MA_NOTOWNED);
    mtx_assert(&pcb->sdtp->peers.write_spinlock, MA_NOTOWNED);
}

int
sdtp_input(struct mbuf **mp, int *offp, int proto)
{
    struct sdtp_inpcb *pcb = NULL;
    struct mbuf *m;
    struct ip *ip_header;
    struct sdtp_common_header *sdtp_header;
    struct in6_addr addr;
    int offset, iphlen;

    m = *mp;
    iphlen = *offp;
    offset = iphlen + sizeof(struct sdtp_common_header);

    m = m_pullup(m, offset);
    if (m == NULL) {
        goto sdtp_input_consumed_error;
    }

    ip_header = mtod(m, struct ip *);
    sdtp_header = (struct sdtp_common_header *)((caddr_t)ip_header + iphlen);
    ipv4_to_ipv6(&ip_header->ip_src, &addr);

    if (!sdtp_check_conditions(sdtp_header, m)) {
        goto sdtp_input_error;
    }

    pcb = sdtp_get_pcb(sdtp_header);
    if (pcb == NULL) {
        icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
        goto sdtp_input_consumed_error;
    }

    m_adj(m, iphlen);
    m = m_pullup(m, sdtp_header_lengths[sdtp_header->type - SDTP_DATA]);
    if (m == NULL) {
        goto sdtp_input_consumed_error;
    }

    sdtp_handle_packet(m, &addr, pcb);
    // TODO: add sdtp_send_grants(sdtp);
    if (pcb) {
        check_pcb_locks(pcb);
    }
    return IPPROTO_DONE;

sdtp_input_error:
    m_freem(m);

sdtp_input_consumed_error:
    if (pcb) {
        check_pcb_locks(pcb);
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
