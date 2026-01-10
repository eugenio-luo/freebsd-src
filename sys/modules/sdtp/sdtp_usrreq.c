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

#include <netinet/in.h>

#include "sdtp.h"
#include "sdtp_structs.h"

extern struct sdtp *sdtp;

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
	.pr_bind =	    sdtp_bind,
	//.pr_send =	sdtp_sendm,
	/*
	.pr_connect =	sdtp_connect,
	.pr_ctloutput =	sdp_ctloutput,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	in_control,
	.pr_close =	sctp_close,
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
	.pr_bind =	    sdtp_bind,
	//.pr_send =	sdtp_sendm,
	/*
	.pr_connect =	sdtp_connect,
	.pr_ctloutput =	sdp_ctloutput,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_control =	in_control,
	.pr_close =	sctp_close,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	.pr_soreceive =	sctp_soreceive
	*/
};

#endif
