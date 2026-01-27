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

extern struct sdtp *sdtp;
extern struct sdtp_zones zones;

/*
 * 
 * TODO: 20251124
 * 1. syscall to send as client (request) -> copy from userspace buffer, printf 
 * 2. kernel creates a mbuf, copy userspace buffer into mbuf
 * 3. find the ip peer, then send to ip layer
 * 4. you should see a proper packet on tcpdump 
 *
 */

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
        if (!TAILQ_EMPTY(&pcb->ready_responses)) {
            rpc = TAILQ_FIRST(&pcb->ready_responses);
            goto sdtp_register_interest_claim_rpc;
        }

        insert_response_interest(pcb, interest);
    }
    if (flags & SDTP_RECVMSG_REQUEST) {
        if (!TAILQ_EMPTY(&pcb->ready_requests)) {
            rpc = TAILQ_FIRST(&pcb->ready_requests);

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
    if (!TAILQ_EMPTY(&pcb->ready_requests) || !TAILQ_EMPTY(&pcb->ready_responses)) {
        sorwakeup(pcb->socket);
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

        sdtp_debug("sdtp_copy_to_user called with rpc: %#lx, buf: %#lx, buf data: %#lx\n", (uintptr_t) rpc, (uintptr_t) buf, (uintptr_t) buf->m_data);
        KASSERT(buf->m_len >= 0, ("buf %d (%#lx) should not have negative size: %d\n", n, (uintptr_t) buf_entry, buf->m_len));

        if (buf->m_len < sizeof(struct sdtp_data_header)) {
            goto sdtp_copy_to_user_copy;
        }

        buf = m_pullup(buf, sizeof(struct sdtp_data_header));
        if (!buf) {
            goto sdtp_copy_to_user_copy;
        }
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
        rpc->msgin.copied_out = segment_offset + ntohl(header->data_segment.segment_length_be);

        if (n < MAX_BUFS) {
            continue;
        }

sdtp_copy_to_user_copy:
        if (n == 0) {
            break;
        }
        atomic_set_32(&rpc->flags_atomic, RPC_COPYING_TO_USER);
        sdtp_rpc_unlock(rpc);

        for (i = 0; i < n && !error; ++i) {
            buf = bufs[i];

            buf = m_pullup(buf, sizeof(struct sdtp_data_header));
            if (!buf) {
                continue;
            }

            header = mtod(buf, struct sdtp_data_header *); 
            int rem = ntohl(header->data_segment.segment_length_be);

            if (rem <= sizeof(*header) || rem > buf->m_pkthdr.len) {
                error = EINVAL;
                continue;
            }

            struct mbuf *m = buf->m_next;
            for (; m != NULL && uio->uio_resid > 0 && rem > 0; m = m->m_next) {
                int len = min(m->m_len, uio->uio_resid);
                len = min(m->m_len, rem);

                error = uiomove(mtod(m, char *), len, uio);
                if (error) {
                    break;
                }
                rem -= len;
            }

            if (error) {
                continue;
            }
        }

        for (i = 0; i < n; ++i) {
            //TODO: sdtp_handle_acks(rpc, bufs[i]);
            sdtp_free_mbuf(bufs[i]);
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
    int blocked;

    flags |= SDTP_RECVMSG_REQUEST;

    while (1) {
        *error = sdtp_register_interest(&interest, pcb, flags, id);
        rpc = (struct sdtp_rpc *) atomic_load_ptr(&interest.ready_rpc_atomic);
        if (rpc != NULL || *error != 0) {
            goto sdtp_wait_for_message_found_rpc;
        }

        /* TODO: clean up dead rpcs
        while (1) {
        }
        */

        if (flags & SDTP_RECVMSG_NONBLOCKING) {
            *error = EAGAIN;
            goto sdtp_wait_for_message_found_rpc;
        }

        poll_start = now = get_cyclecount();
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

        rpc = (struct sdtp_rpc *) atomic_load_acq_ptr(&interest.ready_rpc_atomic);
        if (rpc == NULL && !pcb->shutdown) {
            mtx_lock_spin(&interest.spinlock);
            msleep_spin(&interest.spinlock, &interest.spinlock, "sdtp_pool", 0);
            mtx_unlock_spin(&interest.spinlock);
        }
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
        if (rpc) {
            if (!atomic_load_int(&interest.locked_atomic)) {
                sdtp_rpc_lock(rpc);
            }
            atomic_clear_32(&rpc->flags_atomic, RPC_HANDING_OFF);
            if (rpc->state == SDTP_RPC_DEAD) {
                sdtp_rpc_unlock(rpc);
                continue;
            }

            if (rpc->error == 0) {
                if (rpc->ctx) {
                    (void) rpc->ctx;
                    // TODO: homals_copy_to_user
                } else {
                    rpc->error = sdtp_copy_to_user(uio, rpc);
                }
            }
            if (rpc->error != 0) {
                goto sdtp_wait_for_message_done;
            }

            atomic_clear_32(&rpc->flags_atomic, RPC_PKTS_READY);

            if (rpc->msgin.copied_out == rpc->msgin.total_length) {
                goto sdtp_wait_for_message_done;
            }
            sdtp_rpc_unlock(rpc);
        }
    }

sdtp_wait_for_message_done:
    return rpc;
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
    int res = 0;
    struct sdtp_inpcb *inp;
    struct sdtp_rpc *rpc = NULL;

    inp = (struct sdtp_inpcb *) so->so_pcb;
    if (inp == NULL) {
        return EINVAL;
    }

    // TODO: we don't use sdtp_pool_release_bpages?

    rpc = sdtp_wait_for_message(inp, 0, 0, uio, &res);
    if (res) {
        goto sdtp_soreceive_done;
    }

    // TODO: freeze_type = SLOW_RPC

    rpc->msgin.num_bufs = 0;
    sdtp_rpc_unlock(rpc);

sdtp_soreceive_done:
    return res;
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

static void
sdtp_close(struct socket *so)
{
    so->so_pcb = NULL;
}


//static int
//sdtp_sendm(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
//    struct mbuf *control, struct thread *p)
//{
//    //struct sdtp_inpcb *pcb = (struct sdtp_inpcb *) so->so_pcb;
//    struct sdtp_msg_args args;
//    //uint64_t start = get_cyclecount();
//    //uint64_t finish;
//    int error = 0;
//    struct sdtp_rpc *rpc = NULL;
//
//    /* todo: does control contain sdtp_msg_args? */
//    if (control == NULL || control->m_len < sizeof(args)) {
//        error = EINVAL;
//        goto sendm_error;
//    }
//    m_copydata(control, 0, sizeof(args), (char *)&args);
//
//    if (addr->sa_family != so->so_proto->pr_domain->dom_family) {
//        error = EAFNOSUPPORT;
//        goto sendm_error;
//    }
//
//    if ((addr->sa_len < sizeof(struct sockaddr_in)) || ((addr->sa_len < sizeof(struct sockaddr_in6)) && (addr->sa_family == AF_INET6))) {
//        error = EINVAL;
//        goto sendm_error;
//    }
//
//    if (args.id == 0) {
//
//        /* request message */
//        uprintf("hello");
//
//    } else {
//
//        uprintf("bye");
//    }
//
//sendm_error:
//    if (rpc != NULL) {
//        // todo: free rpc
//    }
//    if (control != NULL) {
//        m_freem(control);
//    }
//    if (m != NULL) {
//        m_freem(m);
//    }
//
//    return error;
//}

struct protosw sdtp_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_attach =	sdtp_attach,
	.pr_soreceive =	sdtp_soreceive,
	.pr_bind =	    sdtp_bind,
	.pr_close =	sdtp_close,
	//.pr_ctloutput =	sdtp_ctloutput,
	//.pr_send =	sdtp_sendm,
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
	//.pr_ctloutput =	sdtp_ctloutput,
	//.pr_send =	sdtp_sendm,
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
