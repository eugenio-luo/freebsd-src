/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include <sys/cdefs.h>
#include "opt_inet.h"
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/kthread.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>

#include "sdtp_structs.h"

struct sdtp sdtp_data;
struct sdtp *sdtp = &sdtp_data;

static struct thread *timer_kthread;

extern struct protosw sdtp_protosw;
extern struct protosw sdtp6_protosw;

static void sdtp_timer_main(void * __unused arg);
static volatile bool existing = false;

int running = 0;

static int
sdtp_module_load(void)
{
	int error = 0;

#ifdef INET
    uprintf("IP4 active!\n");
	error = protosw_register(&inetdomain, &sdtp_protosw);
	if (error != 0)
		return (error);
	// error = ipproto_register(IPPROTO_SDTP, sdtp_input, sdtp_ctlinput);
	error = ipproto_register(IPPROTO_SDTP, NULL, NULL);
	if (error != 0)
		return (error);
#endif
#ifdef INET6
    uprintf("IP6 active!\n");
    error = protosw_register(&inet6domain, &sdtp6_protosw);
    if (error != 0)
		return (error);
	error = ip6proto_register(IPPROTO_SDTP, NULL, NULL);
    if (error != 0)
		return (error);
#endif
	
    error = kthread_add(&sdtp_timer_main, NULL, NULL, &timer_kthread, 0, 0, "sdtp_timer");
    if (error != 0) {
        timer_kthread = NULL;
        return (error);
    }
    // sched_add(timer_kthread, SRQ_BORING);

    error = sdtp_init(sdtp);
	// error = sdtp_syscalls_init();
	return error;
}

static void sdtp_timer_main(void * __unused arg)
{
    running = 1;
    // while (!existing);

    kthread_exit();
}

static int
sdtp_module_unload(void)
{
    int error = 0;
    existing = true;

    error = sdtp_uninit(sdtp);
#ifdef INET
	(void)ipproto_unregister(IPPROTO_SDTP);
	(void)protosw_unregister(&sdtp_protosw);
#endif
#ifdef INET6
	(void)ip6proto_unregister(IPPROTO_SDTP);
	(void)protosw_unregister(&sdtp6_protosw);
#endif

    return error;
}

static int
sdtp_modload(struct module *module, int cmd, void *arg)
{
	int error;

	switch (cmd) {
	case MOD_LOAD:
		error = sdtp_module_load();
		break;
	case MOD_UNLOAD:
		error = sdtp_module_unload();
		break;
	default:
		error = 0;
		break;
	}
	return (error);
}

static moduledata_t sdtp_mod = {
	"sdtp",
	&sdtp_modload,
	NULL,
};

SYSCTL_INT(_debug, OID_AUTO, sdtp_module, CTLFLAG_RW, &running, 0, "sdtp_module");

DECLARE_MODULE(sdtp, sdtp_mod, SI_SUB_PROTO_IFATTACHDOMAIN, SI_ORDER_ANY);
MODULE_VERSION(sdtp, 1);
