/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/types.h>
#include <sys/stdint.h>
#include <sys/eventhandler.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include "sdtp.h"
#include "sdtp_os.h"
#include "sdtp_structs.h"
#include "sdtp_pool.h"
#include "sdtp_debug.h"
#include "sdtp_output.h"

extern struct sdtp *sdtp;
extern struct sdtp_zones zones;

#ifdef INET

static int
sdtp_attach(struct socket *so, int proto, struct thread *p)
{
    int error;
	struct sdtp_inpcb *inp;

    inp = (struct sdtp_inpcb *)so->so_pcb;
    if (inp != NULL) {
        return EINVAL;
    }

    error = sdtp_inpcb_alloc(so, sdtp);

    return error;
}

static int
sdtp_register_interest(struct sdtp_interest *interest, struct sdtp_inpcb *pcb, int flags, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;

    sdtp_interest_init(interest);
    atomic_store_int(&interest->locked_atomic, 1);
    if (id != 0) {
        if (!sdtp_is_client(id)) {
            return EINVAL;
        }

        rpc = sdtp_find_client_rpc(pcb, id);
        if (rpc == NULL) {
            return EINVAL;
        }

        if ((rpc->interest != NULL) && (rpc->interest != interest)) {
            sdtp_rpc_unlock(rpc);
            return EINVAL;
        }
    }

    mtx_lock_spin(&pcb->spinlock);
    if (pcb->shutdown) {
        mtx_unlock_spin(&pcb->spinlock);
        if (rpc) {
            sdtp_rpc_unlock(rpc);
        }
        return ESHUTDOWN;
    }

    if (id != 0) {
        if ((atomic_load_32(&rpc->flags_atomic) & RPC_PKTS_READY) || rpc->error) {
            goto sdtp_register_interest_claim_rpc;
        }
        rpc->interest = interest;
        interest->reg_rpc = rpc;
        sdtp_rpc_unlock(rpc);
    }

    atomic_store_int(&interest->locked_atomic, 0);
    if (flags & SDTP_RECVMSG_RESPONSE) {
        sdtp_pcb_debug(pcb, "Check if there are response RPCs");
        if (!SDTP_LIST_EMPTY(&pcb->ready_responses)) {
            sdtp_pcb_debug(pcb, "There are response RPCs in PCB list");
            rpc = SDTP_LIST_FIRST(&pcb->ready_responses, sdtp_rpc);
            goto sdtp_register_interest_claim_rpc;
        }

        insert_response_interest(pcb, interest);
    }
    if (flags & SDTP_RECVMSG_REQUEST) {
        sdtp_pcb_debug(pcb, "Check if there are request RPCs");
        if (!SDTP_LIST_EMPTY(&pcb->ready_requests)) {
            sdtp_pcb_debug(pcb, "There are request RPCs in PCB list");
            rpc = SDTP_LIST_FIRST(&pcb->ready_requests, sdtp_rpc);

            if (atomic_load_int(&interest->is_response_atomic)) {
                remove_response_interest(pcb, interest);
            }

            goto sdtp_register_interest_claim_rpc;
        }

        insert_request_interest(pcb, interest);
    }
    mtx_unlock_spin(&pcb->spinlock);
    return 0;

sdtp_register_interest_claim_rpc:

    remove_ready_rpc(pcb, rpc);
    if (!SDTP_LIST_EMPTY(&pcb->ready_requests) || !SDTP_LIST_EMPTY(&pcb->ready_responses)) {
        sdtp_sorwakeup(pcb);
    }

    atomic_set_32(&rpc->flags_atomic, RPC_HANDING_OFF);
    mtx_unlock_spin(&pcb->spinlock);
    if (!atomic_load_int(&interest->locked_atomic)) {
        sdtp_rpc_lock(rpc);
        atomic_store_int(&interest->locked_atomic, 1);
    }
    atomic_clear_32(&rpc->flags_atomic, RPC_HANDING_OFF);
    atomic_store_ptr(&interest->ready_rpc_atomic, (uintptr_t) rpc);
    return 0;
}

static int
sdtp_copy_to_user(struct uio *uio, struct sdtp_rpc *rpc)
{
#define MAX_BUFS 20
    struct mbuf *bufs[MAX_BUFS];

    int error = 0, n = 0;

    KASSERT(rpc->msgin.num_bufs > 0, ("the num of bufs should be positive: %d", rpc->msgin.num_bufs));

    while (true) {
        struct sdtp_packet_tailq_entry *buf_entry = TAILQ_FIRST(&rpc->msgin.packets);
        struct sdtp_data_header *header;
        int i, segment_offset;

        if (buf_entry == NULL || (rpc->msgin.copied_out >= rpc->msgin.total_length)) {
            goto sdtp_copy_to_user_copy;
        }

        struct mbuf *buf = buf_entry->data;

        sdtp_debug("sdtp_copy_to_user called with rpc: %#lx, buf: %#lx, buf data: %#lx\n",
                   (uintptr_t) rpc, (uintptr_t) buf, (uintptr_t) buf->m_data);
        KASSERT(buf->m_flags & M_PKTHDR, ("buf must have packet header"));
        KASSERT(buf->m_pkthdr.len >= sizeof(struct sdtp_data_header),
                ("buf %d (size: %d) must contain within its mbuf chain the size of sdtp_data_header\n",
                n, buf->m_pkthdr.len));
        KASSERT(buf->m_len >= sizeof(struct sdtp_data_header),
                ("buf %d (size: %d) must be the size of sdtp_data_header\n",
                n, buf->m_len));

        header = mtod(buf, struct sdtp_data_header *);
        segment_offset = ntohl(header->data_segment.offset_be);

        if (rpc->msgin.copied_out < segment_offset) {
            goto sdtp_copy_to_user_copy;
        }

        bufs[n] = buf;
        ++n;
        TAILQ_REMOVE(&rpc->msgin.packets, buf_entry, link);
        sdtp_free_packet_tailq_entry(buf_entry);

        --rpc->msgin.num_bufs;
        rpc->msgin.copied_out = segment_offset + buf->m_pkthdr.len - sizeof(struct sdtp_data_header);

        if (n < MAX_BUFS) {
            continue;
        }

sdtp_copy_to_user_copy:
        if (n == 0) {
            sdtp_rpc_debug(rpc, "failed to copy any buffers");
            break;
        }
        atomic_set_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);
        sdtp_rpc_unlock(rpc);

        for (i = 0; i < n && !error; ++i) {
            buf = bufs[i];

            KASSERT(buf->m_len >= sizeof(struct sdtp_data_header),
                    ("buf %d (%d) must contain the size of sdtp_data_header\n",
                    n, buf->m_len));

            header = mtod(buf, struct sdtp_data_header *); 
            int rem = buf->m_pkthdr.len - sizeof(struct sdtp_data_header);

            if (rem < 0) {
                error = EINVAL;
                continue;
            }

            KASSERT(buf->m_len - sizeof(*header) > 0, ("buf size without header must be positive\n"));
            error = uiomove(mtod(buf, char *) + sizeof(*header), buf->m_len - sizeof(*header), uio);
            if (error) {
                continue;
            }

            sdtp_rpc_debug(rpc, "copying %d length to userspace", buf->m_len - sizeof(*header));

            struct mbuf *m = buf->m_next;
            for (; m != NULL && uio->uio_resid > 0 && rem > 0; m = m->m_next) {
                int len = min(m->m_len, uio->uio_resid);
                len = min(m->m_len, rem);

                sdtp_rpc_debug(rpc, "copying %d length to userspace", len);
                error = uiomove(mtod(m, char *), len, uio);
                if (error) {
                    break;
                }
                rem -= len;
            }

            if (error) {
                continue;
            }
            SDTP_METRIC(rpc->sdtpcb, recv_pkts_atomic, 1);
        }

        for (i = 0; i < n; ++i) {
            // TODO: buffer should be free'd here?
            //TODO: sdtp_handle_acks(rpc, bufs[i]);
            sdtp_free_mbuf(bufs[i]);
            SDTP_METRIC(rpc->sdtpcb, freed_recv_pkts_atomic, 1);
        }
        n = 0;
        sdtp_rpc_lock(rpc);
        atomic_clear_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);
        if (error) {
            break;
        }
    }

    return error;
}

static struct sdtp_rpc *
sdtp_wait_for_message(struct sdtp_inpcb *pcb, int flags, uint64_t id, struct uio *uio, int *error)
{
    struct sdtp_rpc *rpc = NULL;
	struct sdtp_interest interest;
    uint64_t poll_start, now;
    int blocked, more_rpcs_to_reap = true;

    while (1) {
        sdtp_pcb_debug(pcb, "check if there is waiting interest");
        *error = sdtp_register_interest(&interest, pcb, flags, id);
        rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
        if (rpc != NULL || *error != 0) {
            goto sdtp_wait_for_message_found_rpc;
        }

        while (more_rpcs_to_reap) {
            rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
            if (rpc != NULL) {
                goto sdtp_wait_for_message_found_rpc;
            }

            more_rpcs_to_reap = sdtp_rpc_reap(pcb, /* reap_all */ false);
        }

        if (flags & SDTP_RECVMSG_NONBLOCKING) {
            *error = EAGAIN;
            goto sdtp_wait_for_message_found_rpc;
        }

        poll_start = now = get_cyclecount();
        sdtp_pcb_debug(pcb, "spin and check");
        while (1) {
            rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
            if (rpc) {
                goto sdtp_wait_for_message_found_rpc;
            }

            if (now >= (poll_start + pcb->sdtp->poll_cycles)) {
                break;
            }

            blocked = get_cyclecount();
            pause("sdtp_poll", 1);
            now = get_cyclecount();
            blocked = now - blocked;
            poll_start += blocked;
        }

        sdtp_pcb_debug(pcb, "going to sleep with thread: %#x", interest.thread);
        sdtp_pcb_debug(pcb, "sleep channel: %#x", &interest.spinlock);
        mtx_assert(&interest.spinlock, MA_NOTOWNED);

        mtx_lock_spin(&interest.spinlock);
        rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
        if (rpc == NULL && !pcb->shutdown) {
            int res = msleep_spin(&interest.spinlock, &interest.spinlock, "sdtp_pool", 0);
            sdtp_pcb_debug(pcb, "sleep result: %d", res);
            INTEREST_NOT_LINKED(&interest);
        }
        mtx_unlock_spin(&interest.spinlock);
        sdtp_pcb_debug(pcb, "waking up");

sdtp_wait_for_message_found_rpc:
        if (interest.reg_rpc != NULL
            || atomic_load_int(&interest.is_response_atomic)
            || atomic_load_int(&interest.is_request_atomic)) {

            mtx_lock_spin(&pcb->spinlock);
            if (interest.reg_rpc) {
                interest.reg_rpc->interest = NULL;
            }
            if (atomic_load_int(&interest.is_response_atomic)) {
                remove_response_interest(pcb, &interest);
            }
            if (atomic_load_int(&interest.is_request_atomic)) {
                remove_request_interest(pcb, &interest);
            }
            mtx_unlock_spin(&pcb->spinlock);
        }

        rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
        sdtp_pcb_debug(pcb, "new rpc after waking: %llu", (uintptr_t)rpc);
        if (rpc) {
            if (!atomic_load_int(&interest.locked_atomic)) {
                sdtp_rpc_lock(rpc);
            }
            // TODO: I don't this is needed because we already holding
            // the reference from interest.ready_rpc_atomic?
            sdtp_rpc_hold(rpc);
            atomic_clear_32(&rpc->flags_atomic, RPC_HANDING_OFF);
            if (rpc->state == SDTP_RPC_DEAD) {
                sdtp_rpc_unlock(rpc);
                sdtp_rpc_put(rpc);
                sdtp_pcb_debug(pcb, "dead RPC");
                continue;
            }

            if (rpc->error == 0) {
                if (rpc->ctx) {
                    (void) rpc->ctx;
                    // TODO: homals_copy_to_user
                } else {
                    sdtp_pcb_debug(pcb, "copy to user");
                    rpc->error = sdtp_copy_to_user(uio, rpc);
                }
            }
            if (rpc->error != 0) {
                goto sdtp_wait_for_message_done;
            }

            atomic_clear_32(&rpc->flags_atomic, RPC_PKTS_READY);

            sdtp_rpc_debug(rpc, "rpc->msgin.copied_out: %d, rpc->msgin.total_length: %d", rpc->msgin.copied_out, rpc->msgin.total_length);
            if (rpc->msgin.copied_out == rpc->msgin.total_length) {
                SDTP_METRIC(rpc->sdtpcb, recv_rpcs_atomic, 1);
                goto sdtp_wait_for_message_done;
            }
            sdtp_rpc_put(rpc);
            sdtp_rpc_unlock(rpc);
        }
    }

sdtp_wait_for_message_done:
    return rpc;
}

static struct mbuf *
sdtp_fill_rcv_control(struct sdtp_rpc *rpc, struct mbuf *buf)
{
    struct cmsghdr *header;

    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);
    MBUF_LEN_AT_LEAST(buf, CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)));

    header = mtod(buf, struct cmsghdr *);
	memset(header, 0, CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)));
    
    header->cmsg_len = CMSG_LEN(sizeof(struct sdtp_recvmsg_args));
    header->cmsg_level = IPPROTO_SDTP;
    header->cmsg_type = 1; // placeholder

    struct sdtp_recvmsg_args *args = (struct sdtp_recvmsg_args *) CMSG_DATA(header);
    args->id = rpc->id;
    args->completion_cookie = rpc->completion_cookie;
    if (rpc->msgin.total_length >= 0) {
	    args->num_bpages = rpc->msgin.num_bpages;
        memcpy(args->bpage_offsets, rpc->msgin.bpage_offsets,
               sizeof(args->bpage_offsets));
    }

    return buf;
}

static void
sdtp_fill_sockaddr(struct sdtp_rpc *rpc, struct sockaddr_in *sin)
{
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof(struct sockaddr_in);
    sin->sin_port = htons(rpc->dport);
    ipv6_to_ipv4(&rpc->peer->addr, &sin->sin_addr);
}

static void
sdtp_fill_sockaddr6(struct sdtp_rpc *rpc, struct sockaddr_in6 *sin)
{
    sin->sin6_family = AF_INET6;
    sin->sin6_len = sizeof(struct sockaddr_in6);
    sin->sin6_port = htons(rpc->dport);
    sin->sin6_addr = rpc->peer->addr;
}

// TODO: read options through controlp, but controlp is NULL? Maybe setsockopt() is better 
static int
sdtp_soreceive(struct socket *so,
    struct sockaddr **psa,
    struct uio *uio,
    struct mbuf **mp0,
    struct mbuf **controlp,
    int *flagsp)
{
    int res = 0, family = so->so_proto->pr_domain->dom_family;
    struct sdtp_inpcb *inp;
    struct sdtp_rpc *rpc = NULL;
    struct mbuf *control_buf = NULL;
	uint8_t sockbuf[256];

    inp = (struct sdtp_inpcb *) so->so_pcb;
    if (inp == NULL) {
        return EINVAL;
    }

    if (controlp != NULL) {
        KASSERT(CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)) <= MLEN,
                ("control msg header + sdtp_recvmsg_args size (%lu) should be less than MHLEN %d",
                CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)), MLEN));

        control_buf = m_get2(CMSG_SPACE(sizeof(struct sdtp_recvmsg_args)),
                             M_NOWAIT, MT_DATA, 0);
        if (!control_buf) {
            res = ENOBUFS;
            goto sdtp_soreceive_done;
        }

        control_buf->m_len = CMSG_SPACE(sizeof(struct sdtp_recvmsg_args));
    }

    // TODO: we don't use sdtp_pool_release_bpages?

    rpc = sdtp_wait_for_message(inp, (flagsp != NULL) ? *flagsp : 0 , 0, uio, &res);
    if (res) {
        goto sdtp_soreceive_done;
    }

    // TODO: freeze_type = SLOW_RPC

    if (controlp != NULL) {
        *controlp = sdtp_fill_rcv_control(rpc, control_buf);
    }
    if (psa != NULL) {
        switch (family) {
        case AF_INET: {
            sdtp_fill_sockaddr(rpc, (struct sockaddr_in *) sockbuf); 
            break;
        }
        case AF_INET6: {
            sdtp_fill_sockaddr6(rpc, (struct sockaddr_in6 *) sockbuf);
            break;
        }
        default: {
            res = EAFNOSUPPORT;
            goto sdtp_soreceive_done;
        }
        }
    }

sdtp_soreceive_done:
    if (rpc) {
        rpc->msgin.num_bufs = 0;

        if (sdtp_is_client(rpc->id)) {
            sdtp_peer_ack(rpc);
            SDTP_QUEUE_LOCK(&rpc->sdtpcb->active_rpcs);
            sdtp_rpc_free(rpc);
            SDTP_QUEUE_UNLOCK(&rpc->sdtpcb->active_rpcs);
        } else {
            if (res >= 0) {
                rpc->state = SDTP_RPC_IN_SERVICE;
            } else {
                SDTP_QUEUE_LOCK(&rpc->sdtpcb->active_rpcs);
                sdtp_rpc_free(rpc);
                SDTP_QUEUE_UNLOCK(&rpc->sdtpcb->active_rpcs);
            }
        }
        sdtp_rpc_put(rpc);
        sdtp_rpc_unlock(rpc);
    }
    if (control_buf != NULL && res != 0) {
        m_freem(control_buf);
        *controlp = NULL; 
    }
    if (psa != NULL) {
        *psa = (res == 0) ? sodupsockaddr((struct sockaddr *) sockbuf, M_NOWAIT) : NULL;
    }
    return res;
}

static void
sdtp_close(struct socket *so)
{
    struct epoch_tracker et;
    struct sdtp_inpcb *pcb;

    pcb = (struct sdtp_inpcb *) so->so_pcb;
    if (pcb == NULL) {
        return;
    }

    sdtp_inpcb_free(pcb);

    NET_EPOCH_ENTER(et);

    SOCK_LOCK(so);
    so->so_pcb = NULL;
    SOCK_UNLOCK(so);

    NET_EPOCH_EXIT(et);
}

static int
sdtp_bind(struct socket *so, struct sockaddr *addr, struct thread *p)
{
    struct sdtp_inpcb *inp;
    uint16_t port;

    inp = (struct sdtp_inpcb *) so->so_pcb;
    if (inp == NULL) {
        return EINVAL;
    }

    if (addr == NULL) {
        return EINVAL;
    }

    if (addr->sa_family != so->so_proto->pr_domain->dom_family) {
        return EAFNOSUPPORT;
    }

    switch (addr->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        port = ntohs(sin->sin_port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        port = ntohs(sin6->sin6_port);
        break;
    }
    default:
		return EAFNOSUPPORT;
    }

    return sdtp_inpcb_bind(&inp->sdtp->port_map, port, inp);
}

static struct sdtp_sendmsg_args *
sdtp_read_control_buf(struct mbuf *buf)
{
    struct cmsghdr *cmsg;

    if (buf == NULL || buf->m_len < sizeof(struct cmsghdr)) {
        return NULL;
    }

    cmsg = mtod(buf, struct cmsghdr *);

    if (cmsg->cmsg_level != IPPROTO_SDTP) {
        return NULL;
    }
    if (cmsg->cmsg_len > buf->m_len || cmsg->cmsg_len < CMSG_LEN(sizeof(struct sdtp_sendmsg_args))) {
        return NULL;
    }

    return (struct sdtp_sendmsg_args *) CMSG_DATA(cmsg);
}

static int
sdtp_send_request(struct sdtp_inpcb *pcb,
                  struct uio *uio,
                  struct sockaddr *sockaddr,
                  struct sdtp_sendmsg_args *args)
{
    int error = 0;
    struct sdtp_rpc *rpc = NULL;
    struct in6_addr addr;
    uint16_t port;

    switch (sockaddr->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
        addr = ipv4_to_ipv6(&sin->sin_addr);
        port = ntohs(sin->sin_port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
        addr = sin6->sin6_addr;
        port = ntohs(sin6->sin6_port);
        break;
    }
    default: {
		error = EAFNOSUPPORT;
        goto sdtp_send_request_error;
    }
    }

    rpc = sdtp_new_client_rpc(pcb, &addr, port, &error);
    if (rpc == NULL || error != 0) {
        goto sdtp_send_request_error;
    }
    sdtp_rpc_hold(rpc);

    // TODO: args flags & HOMA_SENDMSG_PRIVATE

    rpc->completion_cookie = args->completion_cookie;
    error = sdtp_message_out(rpc, uio, true);
    if (error != 0) {
        goto sdtp_send_request_error;
    }
    args->id = rpc->id;
    sdtp_rpc_put(rpc);
    sdtp_rpc_unlock(rpc);

    // copy msg control to user

    return 0;

sdtp_send_request_error:
    if (rpc) {
        SDTP_QUEUE_LOCK(&pcb->active_rpcs);
        sdtp_rpc_free(rpc);
        SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);

        sdtp_rpc_put(rpc);
        sdtp_rpc_unlock(rpc);
    }
    return error;
}

static int
sdtp_send_response(struct sdtp_inpcb *pcb,
                   struct uio *uio,
                   struct sockaddr *sockaddr,
                   struct sdtp_sendmsg_args *args)
{
    int error = 0;
    struct sdtp_rpc *rpc = NULL;
    struct in6_addr addr;
    uint16_t port;

    if (args->completion_cookie != 0) {
        error = EINVAL;
        goto sdtp_send_response_error;
    }

    switch (sockaddr->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
        addr = ipv4_to_ipv6(&sin->sin_addr);
        port = ntohs(sin->sin_port);
        break;
    }
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
        addr = sin6->sin6_addr;
        port = ntohs(sin6->sin6_port); 
        break;
    }
    default: {
		error = EAFNOSUPPORT;
        goto sdtp_send_response_error;
    }
    }

    rpc = sdtp_find_server_rpc(pcb, &addr, port, args->id);
    if (!rpc) {
        /* valid output */
        return 0;
    }
    sdtp_rpc_hold(rpc);

    if (rpc->error) {
        error = rpc->error;
        goto sdtp_send_response_error;
    }

    if (rpc->state != SDTP_RPC_IN_SERVICE) {
        error = EINVAL;
        goto sdtp_send_response_error_no_free_rpc;
    }

    sdtp_rpc_debug(rpc, "sending response");

    rpc->state = SDTP_RPC_OUTGOING;
    // TODO: implement homals part
    error = sdtp_message_out(rpc, uio, true);
    if (error) {
        goto sdtp_send_response_error;
    }

    sdtp_rpc_put(rpc);
    sdtp_rpc_unlock(rpc);
    return 0;

sdtp_send_response_error:
    if (rpc != NULL) {
        SDTP_QUEUE_LOCK(&pcb->active_rpcs);
        sdtp_rpc_free(rpc);
        SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
    }

sdtp_send_response_error_no_free_rpc:
    if (rpc != NULL) {
        sdtp_rpc_put(rpc);
        sdtp_rpc_unlock(rpc);
    }
    return error;
}

static int
sdtp_sosend(struct socket *so, struct sockaddr *addr, struct uio *uio, struct mbuf *top,
    struct mbuf *control, int flags, struct thread *p)
{
    KASSERT(uio != NULL, ("uio must be valid"));
    KASSERT(top == NULL, ("top must be null"));

    int error = 0;
    struct sdtp_inpcb *pcb;
    struct sdtp_sendmsg_args *args;

    sdtp_debug("sosend\n");

    pcb = (struct sdtp_inpcb *) so->so_pcb;
    if (pcb == NULL) {
        sdtp_debug("invalid pcb\n");
        error = EINVAL;
        goto sdtp_sosend_error;
    }

    args = sdtp_read_control_buf(control);
    if (args == NULL) {
        sdtp_debug("invalid control\n");
        error = EINVAL;
        goto sdtp_sosend_error;  
    }

    if (addr->sa_family != so->so_proto->pr_domain->dom_family) {
        sdtp_debug("not supported addr family, addr->sa_family: %d, so->dom_family: %d\n",
                   addr->sa_family, so->so_proto->pr_domain->dom_family);
        error = EAFNOSUPPORT;
        goto sdtp_sosend_error;
    }

    if ((addr->sa_len < sizeof(struct sockaddr_in))
        || ((addr->sa_len < sizeof(struct sockaddr_in6)) && (addr->sa_family == AF_INET6))) {
        sdtp_debug("invalid addr\n");
        error = EINVAL;
        goto sdtp_sosend_error;
    }

    if (args->id == 0) {
        error = sdtp_send_request(pcb, uio, addr, args);
    } else {
        error = sdtp_send_response(pcb, uio, addr, args);
    }

    if (error != 0) {
        goto sdtp_sosend_error;
    }

sdtp_sosend_error:
    if (control != NULL) {
        sdtp_free_mbuf(control);
    }

    return error;
}

struct protosw sdtp_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_attach =	sdtp_attach,
	.pr_soreceive =	sdtp_soreceive,
	.pr_bind =	    sdtp_bind,
	.pr_close =	sdtp_close,
	.pr_sosend =	sdtp_sosend,
	//.pr_ctloutput =	sdtp_ctloutput,
	/*
	.pr_connect =	sdtp_connect,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	sdtp_control,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	*/
};

#endif
#ifdef INET6

struct protosw sdtp6_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_attach =	sdtp_attach,
	.pr_soreceive =	sdtp_soreceive,
	.pr_bind =	    sdtp_bind,
	.pr_close =	sdtp_close,
	.pr_sosend =	sdtp_sosend,
	//.pr_ctloutput =	sdtp_ctloutput,
	/*
	.pr_connect =	sdtp_connect,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	sdtp_control,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	*/
};

#endif
