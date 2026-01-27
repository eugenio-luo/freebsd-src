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

#include <netinet/ip_icmp.h>

#ifdef INET6
#include <netinet6/icmp6.h>
#endif

extern struct sdtp *sdtp;

int
sdtp_input(struct mbuf **mp, int *offp, int proto)
{
    struct sdtp_inpcb *pcb;
    struct mbuf *m;
    struct ip *ip_header;
    struct sdtp_common_header *sdtp_header;
    struct in6_addr addr;
    int offset, iphlen;
    uint16_t dport;

    m = *mp;
    iphlen = *offp;

    offset = iphlen + sizeof(struct sdtp_common_header);
    if (m->m_len < offset) {
        m = m_pullup(m, offset);
        if (m == NULL) {
            goto sdtp_input_done;
        }
    }
    ip_header = mtod(m, struct ip *);
    sdtp_header = (struct sdtp_common_header *)((caddr_t)ip_header + iphlen);

    if (sdtp_header->type < SDTP_DATA || sdtp_header->type > SDTP_ACK) {
        goto sdtp_input_done;
    }

    // TODO: Implement FREEZE packet here?

    dport = ntohs(sdtp_header->dport_be);

    mtx_lock_spin(&sdtp->port_map.write_spinlock);
    pcb = sdtp_find_inpcb(&sdtp->port_map, dport);
    mtx_unlock_spin(&sdtp->port_map.write_spinlock);

    if (!pcb) {
        if (ip_header->ip_v == IPVERSION) {
            icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_PORT, 0, 0);
        }

        goto sdtp_input_done;
    }

    ipv4_to_ipv6(&ip_header->ip_src, &addr);

    /* Adjust the buffer so we don't have the ip header anymore!! */
    m_adj(m, iphlen);
    m = m_pullup(m, sizeof(struct sdtp_common_header));
    if (!m) {
        goto sdtp_input_done;
    }
    sdtp_handle_packet(m, &addr, pcb);

sdtp_input_done:
    // TODO: add sdtp_send_grants(sdtp);

    // TODO: free only if there is an error, we should give &m as argument instead
    // of m so when reference is taken, m becomes NULL
    if (m) {
        mtx_assert(&pcb->spinlock, MA_NOTOWNED);
        mtx_assert(&pcb->sdtp->port_map.write_spinlock, MA_NOTOWNED);

        //m_free(m);
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
