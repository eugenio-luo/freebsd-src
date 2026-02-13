/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/uio.h>
#include <sys/epoch.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#include <net/route/nhop.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/if_private.h>

#include <machine/in_cksum.h>

#include "sdtp.h"
#include "sdtp_output.h"
#include "sdtp_rpc.h"
#include "sdtp_pcb.h"
#include "sdtp_debug.h"
#include "sdtp_peer.h"
#include "sdtp_structs.h"
#include "sdtp_os.h"

extern struct sdtp_zones zones;

// TODO: fix this
static int
sdtp_send_control_buf(struct sdtp_inpcb *pcb, struct sdtp_peer *peer, void *data, size_t len)
{
    struct mbuf *m;
    int error = 0, family = pcb->socket->so_proto->pr_domain->dom_family;
    size_t iplen = (family == AF_INET) ? sizeof(struct ip) : sizeof(struct ip6_hdr);
    size_t payload_len = max(len, SDTP_MIN_PKT_LENGTH);
    size_t extra_len = max(SDTP_MIN_PKT_LENGTH - len, 0);

    KASSERT(len + iplen + max_linkhdr < MHLEN,
            ("header size (%lu) + iplen (%lu) and linklen (%u) should be less than mbuf header buffer size (%d)",
             len, iplen, max_linkhdr, MHLEN));

    MGETHDR(m, M_NOWAIT, MT_HEADER);
    if (!m) {
        error = ENOBUFS;
        goto sdtp_send_control_buf_error;
    }

    sdtp_debug("m->m_pkthdr size: %d\n", m->m_pkthdr.len);
    sdtp_debug("payload_len: %lu\n", payload_len);
    sdtp_debug("extra_len: %lu\n", extra_len);

sdtp_send_control_buf_error:
    if (m) {
        sdtp_free_mbuf(m);
    }
    return error;
}

int
sdtp_send_control(struct sdtp_rpc *rpc,
                  enum sdtp_pkt_type type,
                  void *data,
                  size_t len)
{
    KASSERT(len >= sizeof(struct sdtp_common_header),
        ("The buffer of size %lu should have at least size of common header (%lu bytes)",
        len, sizeof(struct sdtp_common_header)));

    struct sdtp_common_header *header = (struct sdtp_common_header *) data;
    header->type = type;
    header->sport_be = htons(rpc->sdtpcb->port);
    header->dport_be = htons(rpc->dport);
    header->sender_id_be = htobe64(rpc->id);
    return sdtp_send_control_buf(rpc->sdtpcb, rpc->peer, data, len);
}

static void
sdtp_msgout_init(struct sdtp_rpc *rpc, struct uio *uio)
{
    KASSERT(uio != NULL, ("uio must be valid"));
    KASSERT(uio->uio_resid > 0, ("uio resid must be positive"));

    rpc->msgout.length = uio->uio_resid;
    rpc->msgout.num_bufs = 0;
    rpc->msgout.next_xmit = NULL;
	rpc->msgout.next_xmit_offset = 0;
	atomic_store_int(&rpc->msgout.active_xmits_atomic, 0);
	rpc->msgout.sched_priority = 0;
}

static int
calc_unscheduled(struct sdtp_rpc *rpc)
{
    VALID_RPC_ASSERT(rpc);

    KASSERT(rpc->msgout.length > 0, ("rpc->msgout.length must be positive"));
    KASSERT(rpc->sdtpcb->sdtp->unsched_bytes > 0, ("unsched_bytes must be positive"));
    KASSERT(rpc->msgout.pkt_data > 0, ("rpc->msgout.pkt_data must be positive"));

    int unsched;
    int length = rpc->msgout.length;
    int unsched_allow = rpc->sdtpcb->sdtp->unsched_bytes;
    int pkt_data = rpc->msgout.pkt_data;

    unsched = (unsched_allow + pkt_data) - (unsched_allow % pkt_data) - 1; 
    if (unsched > length) {
        unsched = length;
    }

    KASSERT(unsched > 0, ("we must able to send positive amount of unscheduled bytes"));
    return unsched;
}

struct packet_mbuf_result {
    struct mbuf *buf;

    /* 
     * if there is an error, it is an error code, otherwise it
     * is how many bytes were copied from the mbuf.
     */
    int result;
};

/*
 * m_size represents maximum size of packet INCLUDING header
 */
static struct packet_mbuf_result
sdtp_create_packet_mbuf(struct sdtp_rpc *rpc, struct uio *uio, int m_size, int offset)
{
    VALID_RPC_ASSERT(rpc);

    CTASSERT(MLEN >= MHLEN);
    KASSERT(IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header) <= MHLEN,
        ("packet head buffer should contain ip header and sdtp data header"));

    KASSERT(m_size > 0, ("m_size must be positive: %d", m_size));

    KASSERT(uio != NULL, ("uio must be valid"));
    KASSERT(uio->uio_resid > 0, ("uio resid must be positive"));

    struct packet_mbuf_result res;
    struct mbuf *m, *tmp;
    int remaining, header_len = IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header);

    res.buf = NULL;
    res.result = -EINVAL;

    m = m_gethdr(M_NOWAIT, MT_DATA);
    if (!m) {
        res.result = -ENOMEM;
        goto sdtp_create_packet_mbuf_error;
    }
    memset(mtod(m, char *), 0, MHLEN);

    for (remaining = m_size - header_len, tmp = m; remaining > 0 && uio->uio_resid > 0; tmp = tmp->m_next) {
        //struct sdtp_data_segment *data_segment;
        char *datap = NULL;
        int len = min(min(uio->uio_resid, remaining), MLEN);

        KASSERT(len > 0, ("len must be positive"));
        KASSERT(len <= MLEN, ("len must be less than MLEN"));

        tmp->m_next = m_get(M_NOWAIT, MT_DATA);
        if (!tmp->m_next) {
            res.result = -ENOMEM;
            goto sdtp_create_packet_mbuf_error;
        }

        datap = mtod(tmp->m_next, char *);
        //data_segment = mtod(tmp->m_next, struct sdtp_data_segment *);
        //data_segment->offset_be = ntohl(m_size - remaining); // placeholder
        //data_segment->segment_length_be = ntohl(len); // placeholder
        //data_segment->ack
        uiomove(datap, len, uio);
        tmp->m_next->m_len = len;

        remaining -= len;
        KASSERT(remaining >= 0, ("remaining must be always positive or 0"));
        KASSERT(uio->uio_resid >= 0, ("uio_resid must be always positive or 0"));
    }

    m->m_pkthdr.len = m_size - remaining;
    m->m_len = header_len;

    struct sdtp_data_header *header =
        (struct sdtp_data_header *) (mtod(m, char *) + rpc->sdtpcb->ip_header_length);
    header->common.sport_be = htons(rpc->sdtpcb->port);
    header->common.dport_be = htons(rpc->dport);
    SDTP_SET_DOFF(header);
    header->common.type = SDTP_DATA;
    header->common.sender_id_be = htobe64(rpc->id);
    header->message_length_be = htonl(rpc->msgout.length);
    // I'm not sure if this is correct?
    header->incoming_be = htonl(rpc->msgout.length);
    header->cutoff_version_be = rpc->peer->cutoff_version_be;
	header->retransmit = 0;

    header->data_segment.offset_be = ntohl(offset);
    header->ack.client_id_be = htobe64(rpc->id ^ 1);
    header->ack.server_port_be = htons(rpc->dport);

    res.buf = m;
    res.result = m_size - header_len - remaining;

    KASSERT(m->m_pkthdr.len > 0, ("mbuf chain total length should be positive"));
    KASSERT(res.buf != NULL, ("res buf must be valid"));
    KASSERT(res.result > 0, ("res result must be positive"));

    return res;

sdtp_create_packet_mbuf_error:
    if (m) {
        m_freem(m);
    }
    KASSERT(res.buf == NULL, ("res buf must be NULL when there is an error"));
    KASSERT(res.result < 0, ("res result must be negative when there is an error"));
    return res;
}

static int
sdtp_fill_packets_slist(struct sdtp_rpc *rpc, struct uio *uio, int max_packet_size)
{
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);

    KASSERT(uio != NULL, ("uio must be valid"));
    KASSERT(uio->uio_resid > 0, ("uio resid must be positive"));

    int bytes_left, offset = 0, error = 0;
    struct sdtp_packet_slist_entry *prev = NULL;

    for (bytes_left = rpc->msgout.length; bytes_left > 0;) {
        struct packet_mbuf_result res;
        struct sdtp_packet_slist_entry *entry;
        int packet_size, m_size;

        packet_size = (bytes_left > max_packet_size) ? max_packet_size : bytes_left;
        m_size = IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header) + packet_size;

        sdtp_rpc_unlock(rpc);

        res = sdtp_create_packet_mbuf(rpc, uio, m_size, offset);
        if (res.result < 0) {
            error = -res.result;
            goto sdtp_fill_packets_slist_error;
        }
        bytes_left -= res.result;
        offset += res.result;

        entry = SDTP_ZONE_GET(zones.sdtp_zone_packet_slist_entry,
                              struct sdtp_packet_slist_entry);
        entry->data = res.buf;
        KASSERT(!(entry->data->m_flags & M_EXT), ("buf must not have external storage"));
        KASSERT(entry->data->m_pkthdr.len <= max_packet_size + IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header),
                ("buf size (%d) must be less or equal to MTU %lu",
                 entry->data->m_pkthdr.len, max_packet_size + IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header)));
        sdtp_rpc_debug(rpc, "buffer slist length: %d", entry->data->m_pkthdr.len);

        sdtp_rpc_lock(rpc);
        if (prev == NULL) {
            SLIST_INSERT_HEAD(&rpc->msgout.packets, entry, link);
            rpc->msgout.next_xmit = &rpc->msgout.packets.slh_first;
        } else {
            SLIST_INSERT_AFTER(prev, entry, link);
        }
        prev = entry;
        ++rpc->msgout.num_bufs;
    }

    return 0;

sdtp_fill_packets_slist_error:
    sdtp_rpc_lock(rpc);
    return error;
}

static void
sdtp_send_data(struct sdtp_rpc *rpc, struct mbuf *buf, int priority)
{
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_NOTOWNED(rpc);

    KASSERT(buf != 0, ("buf must be valid"));
    KASSERT(buf->m_flags & M_PKTHDR, ("buf must have packet header"));
    // m_dup causes the M_EXT, it should be fine!
    // KASSERT(!(buf->m_flags & M_EXT), ("buf must not have external storage"));
    KASSERT(buf->m_pkthdr.len >= IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header),
            ("buf must at least contain sdtp_data_header and ip header"));

    VALID_PEER_ASSERT(rpc->peer);

    struct epoch_tracker et;
    struct sdtp_data_header *header;
    //struct nhop_object *nh;
    struct inpcb *inp = &rpc->sdtpcb->inp;
    int family = rpc->sdtpcb->socket->so_proto->pr_domain->dom_family;

    //nh = rpc->peer->nh;
    header = (struct sdtp_data_header *) (mtod(buf, char *) + rpc->sdtpcb->ip_header_length);
    header->cutoff_version_be = rpc->peer->cutoff_version_be;

    // TODO: we need to have custom checksum for SDTP
    buf->m_pkthdr.csum_flags = CSUM_IP;
    buf->m_pkthdr.csum_data = 0;

    switch (family) {
    case AF_INET: {
        struct ip *ip_header = mtod(buf, struct ip *);

        NET_EPOCH_ENTER(et);

        memset(ip_header, 0, sizeof(struct ip));

        ip_header->ip_v = IPVERSION;
        ip_header->ip_hl = sizeof(struct ip) >> 2;
        ip_header->ip_off = htons(IP_DF);
        ip_header->ip_tos = inp->inp_ip_tos;
        ip_header->ip_len = htons(buf->m_pkthdr.len);
        //ip_header->ip_ttl = inp->inp_ip_ttl;
        ip_header->ip_ttl = 64;
        //KASSERT(inp->inp_ip_ttl > 0, ("need ttl > 0"));
        ip_header->ip_p = IPPROTO_SDTP;
        ipv6_to_ipv4(&rpc->peer->addr, &ip_header->ip_dst);
        ip_header->ip_src = inp->inp_laddr;
        ip_header->ip_sum = in_cksum_hdr(ip_header);

        int res = ip_output(buf, NULL, &inp->inp_route, 0, NULL, inp);
        NET_EPOCH_EXIT(et);
        sdtp_rpc_debug(rpc, "ip_output return error: %d", res);

        break;
    }
    case AF_INET6: {
        /*
        struct route_in6 ro6;
        memset(&ro6, 0, sizeof(ro6));
        ro6.ro_nh = nh;

        ip6_output(buf, NULL, &ro6, 0, NULL, &rpc->sdtpcb->inp);
        */
        KASSERT(0, ("not implemented yet"));
        break;
    }
    default: {
        KASSERT(0, ("unreachable"));
        break;
    }
    }
}

static void
sdtp_send_next_data(struct sdtp_rpc *rpc, bool force)
{
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);

    struct sdtp *sdtp = rpc->sdtpcb->sdtp;
    struct mbuf *txm;

	atomic_add_int(&rpc->msgout.active_xmits_atomic, 1);
    while (*rpc->msgout.next_xmit) {
        int priority;
        struct mbuf *buf = (*rpc->msgout.next_xmit)->data;

        KASSERT(buf->m_flags & M_PKTHDR, ("First packet buf need to contain a header"));
        KASSERT(!(buf->m_flags & M_EXT), ("buf must not have external storage"));
        sdtp_rpc_debug(rpc, "packet length: %d", buf->m_pkthdr.len);

        if (rpc->msgout.next_xmit_offset > rpc->msgout.granted) {
            sdtp_rpc_debug(rpc, "rpc trying to send %d bytes over granted bytes %d",
                           rpc->msgout.next_xmit_offset,
                           rpc->msgout.granted);
            break;
        }

        /*
         * TODO: remember to fix this
        if ((rpc->msgout.length - rpc->msgout.next_xmit_offset)
				>= homa->throttle_min_bytes) {

                }
        */

        if (rpc->msgout.next_xmit_offset < rpc->msgout.unscheduled) {
            priority = sdtp_unsched_priority(sdtp, rpc->peer, rpc->msgout.length);
        } else {
			priority = rpc->msgout.sched_priority;
        }

        rpc->msgout.next_xmit = &((*rpc->msgout.next_xmit)->link.sle_next);
        rpc->msgout.next_xmit_offset += rpc->msgout.pkt_data;
        if (rpc->msgout.next_xmit_offset > rpc->msgout.length) {
            rpc->msgout.next_xmit_offset = rpc->msgout.length;
        }

        sdtp_rpc_unlock(rpc);

        txm = m_dup(buf, M_NOWAIT);
        KASSERT(txm != NULL, ("txm must be valid"));
        sdtp_send_data(rpc, txm, priority);
        force = false;

        sdtp_rpc_lock(rpc);
    }
	atomic_add_int(&rpc->msgout.active_xmits_atomic, -1);
}

int
sdtp_message_out(struct sdtp_rpc *rpc, struct uio *uio, bool immediate_send)
{
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);

    KASSERT(uio != NULL, ("uio must be valid"));
    KASSERT(uio->uio_resid > 0, ("uio resid must be positive"));

    int max_packet_size, error = 0;
    //, overlap_xmit;
    uint16_t mtu;

    sdtp_msgout_init(rpc, uio);

    if (rpc->msgout.length > SDTP_MAX_MESSAGE_LENGTH || rpc->msgout.length == 0) {
        error = EINVAL;
        goto sdtp_message_out_error;
    }

    KASSERT(NH_IS_VALID(rpc->peer->nh), ("nh must be valid"));
    mtu = rpc->peer->nh->nh_mtu;
    sdtp_debug("ifp=%s mtu=%d\n",
       rpc->peer->nh->nh_ifp->if_xname,
       rpc->peer->nh->nh_ifp->if_mtu);
    max_packet_size = mtu - IP_SDTP_HEADER_SIZE(rpc, struct sdtp_data_header);
    KASSERT(max_packet_size > 0, ("max_packet_size must be positive"));
    sdtp_rpc_debug(rpc, "mtu: %d, max_packet_size: %d", mtu, max_packet_size);

    if (max_packet_size < 0) {
        error = EINVAL;
        goto sdtp_message_out_error;
    }

    rpc->msgout.pkt_data = rpc->msgout.length;
    rpc->msgout.unscheduled = calc_unscheduled(rpc);
	rpc->msgout.granted = rpc->msgout.unscheduled;

    // overlap_xmit = rpc->msgout.length > 2 * max_packet_size;
	atomic_set_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);

    error = sdtp_fill_packets_slist(rpc, uio, max_packet_size);
    if (error) {
        goto sdtp_message_out_error;
    }

    atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);
    if (immediate_send) {
        sdtp_send_next_data(rpc, false);
    }
    return 0;

sdtp_message_out_error:
    atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_FROM_USER);
    return error;
}
