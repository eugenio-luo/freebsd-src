/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp_structs.h" 

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <machine/cpu.h>
#include <machine/atomic.h>

/*
 * sdtp_init() - Constructor for sdtp objects.
 *
 * Return: 0 on success, or a negative errno if there was an error.
 *         Even if an error occurs, it is safe and necessary to call
 *         sdtp_uninit.
 */
int sdtp_init(struct sdtp *sdtp)
{
	/* TODO: init core memory */

	atomic_store_64(&sdtp->next_out_id, 2);
	atomic_store_64(&sdtp->link_idle_time, get_cyclecount());
	mtx_init(&sdtp->grantable_spinlock, "sdtp grantable spinlock", NULL, MTX_SPIN);
	LIST_INIT(&sdtp->grantable_rpcs);
	sdtp->num_grantable_rpcs = 0;
	sdtp->last_grantable_change = get_cyclecount();
	sdtp->max_grantable_rpcs = 0;
	sdtp->grant_nonfifo = 0;
	sdtp->grant_nonfifo_left = 0;
	mtx_init(&sdtp->pacer_spinlock, "sdtp pacer spinlock", NULL, MTX_SPIN);
	sdtp->pacer_fifo_fraction = 50;
	sdtp->pacer_fifo_count = 1;
	sdtp->pacer_wake_time = 0;
	mtx_init(&sdtp->throttle_spinlock, "sdtp throttle spinlock", NULL, MTX_SPIN);
	LIST_INIT(&sdtp->throttled_rpcs);
	sdtp->throttle_add = 0;
	sdtp->throttle_min_bytes = 1000;

	uprintf("sdtp_init(): %lu\n", sizeof(struct sdtp));
	uprintf("lock: %lu\n", sizeof(sdtp->pacer_spinlock));
	uprintf("num_grantable_rpc: %lu\n", sizeof(sdtp->num_grantable_rpcs));
	uprintf("grantable_rpcs: %lu\n", sizeof(sdtp->grantable_rpcs));
	return 0;
}

int sdtp_uninit(struct sdtp *sdtp)
{
    // TODO: Work on it
    return 0;
}
