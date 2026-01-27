/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp_structs.h"
#include "sdtp_os.h"
#include "sdtp.h"
#include "sdtp_debug.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/pcpu.h>
#include <sys/smp.h>

#include <machine/cpu.h>
#include <machine/atomic.h>
#include <sys/socketvar.h>

MALLOC_DEFINE(M_SDTP_PEERMAP, "sdtp peermap", "SDTP peermap buckets");
DPCPU_DEFINE(struct sdtp_core, sdtp_cores);
struct sdtp_zones zones;

static int 
sdtp_zone_init(void)
{
    struct sdtp_packet_tailq_entry *entry;
    int i;

    SDTP_ZONE_INIT(zones.sdtp_zone_sock, "sdtp_sock",
	    sizeof(struct sdtp_inpcb), maxsockets);
    SDTP_ZONE_INIT(zones.sdtp_zone_rpc, "sdtp_rpc",
        sizeof(struct sdtp_rpc), MAX_SDTP_RPC);
    SDTP_ZONE_INIT(zones.sdtp_zone_peer, "sdtp_peer",
        sizeof(struct sdtp_peer), MAX_SDTP_PEER);
    SDTP_ZONE_INIT(zones.packet_tailq.sdtp_zone_entry, "sdtp_packet_tailq_entry",
        sizeof(struct sdtp_packet_tailq_entry), MAX_SDTP_PACKET_TAILQ_ENTRY);

    TAILQ_INIT(&zones.packet_tailq.entries);
	mtx_init(&zones.packet_tailq.spinlock, "sdtp packet tailq spinlock", NULL, MTX_SPIN);
    for (i = 0; i < MAX_SDTP_PACKET_TAILQ_ENTRY; ++i) {
        entry = SDTP_ZONE_GET(zones.packet_tailq.sdtp_zone_entry, struct sdtp_packet_tailq_entry);
        TAILQ_INSERT_HEAD(&zones.packet_tailq.entries, entry, link);
    }

    return 0;
}

struct sdtp_packet_tailq_entry *
sdtp_alloc_packet_tailq_entry(void)
{
    struct sdtp_packet_tailq_entry *entry;

    mtx_lock_spin(&zones.packet_tailq.spinlock);
    entry = TAILQ_FIRST(&zones.packet_tailq.entries);
    TAILQ_REMOVE(&zones.packet_tailq.entries, entry, link);
    mtx_unlock_spin(&zones.packet_tailq.spinlock);

    return entry;
}

void
sdtp_free_packet_tailq_entry(struct sdtp_packet_tailq_entry *entry)
{
    mtx_lock_spin(&zones.packet_tailq.spinlock);
    memset(entry, 0, sizeof(struct sdtp_packet_tailq_entry));
    TAILQ_INSERT_HEAD(&zones.packet_tailq.entries, entry, link);
    mtx_unlock_spin(&zones.packet_tailq.spinlock);
}

static int
sdtp_core_init(void)
{
    int cpu;
    struct sdtp_core *core;

    CPU_FOREACH(cpu) {
        core = DPCPU_ID_PTR(cpu, sdtp_cores);

        core->last_active = 0;
        core->last_gro = 0;
        core->held_packet = NULL;
        core->held_bucket = 0;
    }

    return 0;
}

static void
sdtp_pcbmap_init(struct sdtp_pcbmap *pcbmap)
{
	int i;
	mtx_init(&pcbmap->write_spinlock, "sdtp pcbmap write spinlock", NULL, MTX_SPIN);
	for (i = 0; i < SDTP_PCBMAP_BUCKETS; i++) {
	    LIST_INIT(&pcbmap->buckets[i]);
	}
}

static int
sdtp_peermap_init(struct sdtp_peermap *peermap)
{
	int i;
	
    mtx_init(&peermap->write_spinlock, "sdtp peermap write spinlock", NULL, MTX_SPIN);
	TAILQ_INIT(&peermap->dead_dsts);

    peermap->buckets = (struct sdtp_peer_list *) malloc(SDTP_PEERTAB_BUCKETS * sizeof(*peermap->buckets),
                                                        M_SDTP_PEERMAP, M_WAITOK);
    if (!peermap->buckets)
		return ENOMEM;
	
    for (i = 0; i < SDTP_PEERTAB_BUCKETS; i++) {
		LIST_INIT(&peermap->buckets[i]);
	}
	return 0;
}

static int
sdtp_struct_init(struct sdtp *sdtp)
{
    int err, i;

    /* fix pacer thread */
    sdtp->pacer_kthread = NULL;

    atomic_store_64(&sdtp->next_out_id_atomic, 2);
	atomic_store_64(&sdtp->link_idle_time_atomic, get_cyclecount());
	mtx_init(&sdtp->grantable_spinlock, "sdtp grantable spinlock", NULL, MTX_SPIN);
	TAILQ_INIT(&sdtp->grantable_rpcs);
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
	TAILQ_INIT(&sdtp->throttled_rpcs);
	sdtp->throttle_add = 0;
	sdtp->throttle_min_bytes = 1000;
	atomic_store_64(&sdtp->total_incoming_atomic, 0);
	sdtp->next_client_port = SDTP_MIN_DEFAULT_PORT;
    sdtp_pcbmap_init(&sdtp->port_map);
    err = sdtp_peermap_init(&sdtp->peers);
    if (err) {
		return err;
	}

    sdtp->unsched_bytes = 10000;
	sdtp->link_mbps = 10000;
	sdtp->poll_usecs = 50;
	sdtp->num_priorities = SDTP_MAX_PRIORITIES;
	for (i = 0; i < SDTP_MAX_PRIORITIES; i++)
		sdtp->priority_map[i] = i;
	sdtp->max_sched_prio = SDTP_MAX_PRIORITIES - 5;
	sdtp->unsched_cutoffs[SDTP_MAX_PRIORITIES-1] = 200;
	sdtp->unsched_cutoffs[SDTP_MAX_PRIORITIES-2] = 2800;
	sdtp->unsched_cutoffs[SDTP_MAX_PRIORITIES-3] = 15000;
	sdtp->unsched_cutoffs[SDTP_MAX_PRIORITIES-4] = SDTP_MAX_MESSAGE_LENGTH;
	
    sdtp->cutoff_version = 1;
	sdtp->fifo_grant_increment = 10000;
	sdtp->grant_fifo_fraction = 50;
	sdtp->max_overcommit = 8;
	sdtp->max_incoming = 400000;
	sdtp->max_rpcs_per_peer = 1;
	sdtp->dynamic_windows = 0;
	sdtp->resend_ticks = 15;
	sdtp->resend_interval = 10;
	sdtp->timeout_resends = 5;
	sdtp->request_ack_ticks = 2;
	sdtp->reap_limit = 10;
	sdtp->dead_buffs_limit = 5000;
	sdtp->max_dead_buffs = 0;

    // TODO: pacer thread initialization 

    sdtp->pacer_exit = false;
	sdtp->max_nic_queue_ns = 2000;
	sdtp->cycles_per_kbyte = 0;
	sdtp->verbose = 0;
	sdtp->max_gso_size = 10000;
	sdtp->max_gro_skbs = 20;
	sdtp->gso_force_software = 0;
	sdtp->gro_policy = SDTP_GRO_NORMAL;
	sdtp->gro_busy_usecs = 10;
	sdtp->timer_ticks = 0;
	mtx_init(&sdtp->metrics_spinlock, "sdtp metrics spinlock", NULL, MTX_SPIN);
	sdtp->metrics = NULL;
	sdtp->metrics_capacity = 0;
	sdtp->metrics_length = 0;
	sdtp->metrics_active_opens = 0;
	sdtp->flags = 0;
	sdtp->freeze_type = 0;
	sdtp->sync_freeze = 0;
	sdtp->bpage_lease_usecs = 10000;
	sdtp->hardware_state_threshold = 1;
	strncpy(sdtp->hardware_interface, "enp1s0f0np0", sizeof(sdtp->hardware_interface) - 1);

    return err;
}

int sdtp_init(struct sdtp *sdtp)
{
    CTASSERT(SDTP_MAX_PRIORITIES >= 8);

    int err;

    err = sdtp_zone_init();
    err = sdtp_core_init();
    err = sdtp_struct_init(sdtp);

    return err;
}

void
sdtp_interest_init(struct sdtp_interest *interest)
{
    memset(interest, 0, sizeof(struct sdtp_interest));

    interest->thread = curthread;
    atomic_store_ptr(&interest->ready_rpc_atomic, 0);

    mtx_init(&interest->spinlock, "interest sleep lock", NULL, MTX_SPIN);
    atomic_store_int(&interest->locked_atomic, 0);

    interest->reg_rpc = NULL;
    atomic_store_int(&interest->is_response_atomic, false);
    atomic_store_int(&interest->is_request_atomic, false);
}

// TODO: fix uninit
int sdtp_uninit(struct sdtp *sdtp)
{
    SDTP_ZONE_DESTROY(zones.sdtp_zone_sock);
    SDTP_ZONE_DESTROY(zones.sdtp_zone_rpc);
    SDTP_ZONE_DESTROY(zones.sdtp_zone_peer);
    SDTP_ZONE_DESTROY(zones.packet_tailq.sdtp_zone_entry);
    return 0;
}
