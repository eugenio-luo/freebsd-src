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

#include <netinet/in.h>

static int sdtp_connect(struct socket *so, struct sockaddr *addr,
		struct thread *p)
{
	return ENOTSUP;
}

static int
sdtp_attach(struct socket *so, int proto, struct thread *p)
{
	return (0);
}

#ifdef INET

struct protosw sdtp_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_connect =	sdtp_connect,
	.pr_attach =	sdtp_attach,
	/*
	.pr_ctloutput =	sdp_ctloutput,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_bind =	sdp_bind,
	.pr_control =	in_control,
	.pr_close =	sctp_close,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_send =	sctp_sendm,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	.pr_soreceive =	sctp_soreceive
	*/
};

#endif
#ifdef INET6

struct protosw sdtp6_protosw = {
	.pr_type = SOCK_DGRAM,
	.pr_flags = 0,
	.pr_protocol = IPPROTO_SDTP,
	.pr_connect =	sdtp_connect,
	.pr_attach =	sdtp_attach,
	/*
	.pr_ctloutput =	sdp_ctloutput,
	.pr_abort =	sdp_abort,
	.pr_accept =	sdp_accept,
	.pr_bind =	sdp_bind,
	.pr_control =	in_control,
	.pr_close =	sctp_close,
	.pr_detach =	sctp_close,
	.pr_disconnect = sctp_disconnect,
	.pr_listen =	sctp_listen,
	.pr_peeraddr =	sctp_peeraddr,
	.pr_send =	sctp_sendm,
	.pr_shutdown =	sctp_shutdown,
	.pr_sockaddr =	sctp_ingetaddr,
	.pr_sosend =	sctp_sosend,
	.pr_soreceive =	sctp_soreceive
	*/
};

#endif
