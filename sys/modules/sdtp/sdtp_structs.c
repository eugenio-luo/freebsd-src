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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <machine/cpu.h>
#include <machine/atomic.h>
#include <sys/socketvar.h>

// TODO: sxlock 

char *core_memory;

struct sdtp_base_info base_info;

static void
sdtp_pcb_init(void)
{
	rw_init(&(base_info.sdtp_zone_sock_lock), "sdtp_sock_lock");
	rw_init(&(base_info.sdtp_zone_rpc_lock), "sdtp_rpc_lock");
    
    SDTP_ZONE_INIT(base_info.sdtp_zone_sock, "sdtp_sock",
	    sizeof(struct sdtp_inpcb), maxsockets);
    SDTP_ZONE_INIT(base_info.sdtp_zone_rpc, "sdtp_rpc",
        sizeof(struct sdtp_rpc), MAX_SDTP_RPC);
}

// socktab
static void
sdtp_pcbmap_init(struct sdtp_pcbmap *pcbmap)
{
	int i;
	mtx_init(&pcbmap->write_mtx, "sdtp pcbmap write spinlock", NULL, MTX_SPIN);
	for (i = 0; i < SDTP_PCBMAP_BUCKETS; i++) {
	    LIST_INIT(&pcbmap->buckets[i]);
	}
}

MALLOC_DEFINE(M_SDTP_PEERMAP, "sdtp peermap", "SDTP peermap buckets");

static int
sdtp_peermap_init(struct sdtp_peermap *peermap)
{
	int i;
	
    mtx_init(&peermap->write_mtx, "sdtp peermap write spinlock", NULL, MTX_SPIN);
	LIST_INIT(&peermap->dead_dsts);

    peermap->buckets = (struct sdtp_peer_head *) malloc(SDTP_PEERTAB_BUCKETS * sizeof(*peermap->buckets),
                                                        M_SDTP_PEERMAP, M_WAITOK);
    if (!peermap->buckets)
		return ENOMEM;
	
    for (i = 0; i < SDTP_PEERTAB_BUCKETS; i++) {
		LIST_INIT(&peermap->buckets[i]);
	}
	return 0;
}

/*
 * sdtp_init() - Constructor for sdtp objects.
 *
 * Return: 0 on success, or a negative errno if there was an error.
 *         Even if an error occurs, it is safe and necessary to call
 *         sdtp_uninit.
 */
int sdtp_init(struct sdtp *sdtp)
{
    int i;

    sdtp_pcb_init();

    if (!core_memory) {
        // initialize core memory
    }

	sdtp->pacer_kthread = NULL;
	// todo: what is the equivalent of: init_completion(&homa_pacer_kthread_done);
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
	atomic_store_64(&sdtp->total_incoming, 0);
	sdtp->next_client_port = SDTP_MIN_DEFAULT_PORT;
    sdtp_pcbmap_init(&sdtp->port_map);
    int err = sdtp_peermap_init(&sdtp->peers);
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

    // todo: pacer thread initialization 

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
	mtx_init(&sdtp->metrics_lock, "sdtp metrics spinlock", NULL, MTX_SPIN);
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

    uprintf("sdtp_init(): %lu\n", sizeof(struct sdtp));
	return 0;
}

int sdtp_uninit(struct sdtp *sdtp)
{
	rw_destroy(&(base_info.sdtp_zone_sock_lock));
    SDTP_ZONE_DESTROY(base_info.sdtp_zone_sock);
    SDTP_ZONE_DESTROY(base_info.sdtp_zone_rpc);
    return 0;
}

static struct sdtp_inpcb *sdtp_find_pcb(struct sdtp_pcbmap *pcbmap, uint16_t port)
{
    struct sdtp_pcbmap_link *link;
    struct sdtp_inpcb *result = NULL;

    /* todo: do we need `hlist_for_each_entry_rcu` here? */
	LIST_FOREACH(link, &pcbmap->buckets[sdtp_port_hash(port)], hash_links) {
        struct sdtp_inpcb *pcb = link->sock;
        if (pcb->port == port) {
            result = pcb;
            break;
        }
    }
    
	return result;
}

int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp)
{
    int error, i;
	struct sdtp_inpcb *inp;
    struct sdtp_pcbmap *pcbmap = &sdtp->port_map;

    error = 0;

    rw_wlock(&(base_info.sdtp_zone_sock_lock));
    inp = SDTP_ZONE_GET(base_info.sdtp_zone_sock, struct sdtp_inpcb);
    if (inp == NULL) {
        rw_wunlock(&(base_info.sdtp_zone_sock_lock));
        return ENOBUFS;
    }
	memset(inp, 0, sizeof(*inp));

    inp->socket = so;
	inp->inp.inp_socket = so;
	inp->inp.inp_cred = crhold(so->so_cred);
#ifdef INET6
	if (INP_SOCKAF(so) == AF_INET6) {
		if (MODULE_GLOBAL(ip6_auto_flowlabel)) {
			inp->inp.inp_flags |= IN6P_AUTOFLOWLABEL;
		}
		if (MODULE_GLOBAL(ip6_v6only)) {
			inp->inp.inp_flags |= IN6P_IPV6_V6ONLY;
		}
	}
#endif

    mtx_lock_spin(&pcbmap->write_mtx);
    atomic_store_32(&inp->protect_count, 0);
	mtx_init(&inp->lock, "socket spinlock", NULL, MTX_SPIN);
	inp->last_locker = "none";
    inp->sdtp = sdtp;
	inp->ip_header_length = (inp->inp.inp_flags & INP_IPV4)
			? SDTP_IPV4_HEADER_LENGTH : SDTP_IPV6_HEADER_LENGTH;
	inp->shutdown = false;

    while (1) {
        if (sdtp->next_client_port < SDTP_MIN_DEFAULT_PORT) {
			sdtp->next_client_port = SDTP_MIN_DEFAULT_PORT;
		}
		if (!sdtp_find_pcb(pcbmap, sdtp->next_client_port)) {
			break;
		}
		sdtp->next_client_port++;
    }
    inp->port = sdtp->next_client_port;
	// todo: hsk->inet.inet_num = hsk->port?
    inp->inp.inp_lport = htons(inp->port);
	sdtp->next_client_port++;
	inp->pcbmap_links.sock = inp;
    
    // todo: what is the equivalent of hlist_add_head_rcu?
    LIST_INSERT_HEAD(&pcbmap->buckets[sdtp_port_hash(inp->port)], &inp->pcbmap_links, hash_links);
    LIST_INIT(&inp->active_rpcs);
    LIST_INIT(&inp->dead_rpcs);
    inp->dead_skbs = 0;
    LIST_INIT(&inp->ready_requests);
    LIST_INIT(&inp->ready_responses);
    LIST_INIT(&inp->request_interests);
    LIST_INIT(&inp->response_interests);
    
    for (i = 0; i < SDTP_CLIENT_RPC_BUCKETS; i++) {
		struct sdtp_rpc_bucket *bucket = &inp->client_rpc_buckets[i];
	    mtx_init(&bucket->lock, "SDTP client rpc bucket spinlock", NULL, MTX_SPIN);
        LIST_INIT(&bucket->rpcs);
	}
    for (i = 0; i < SDTP_SERVER_RPC_BUCKETS; i++) {
        struct sdtp_rpc_bucket *bucket = &inp->server_rpc_buckets[i];
	    mtx_init(&bucket->lock, "SDTP server rpc bucket spinlock", NULL, MTX_SPIN);
        LIST_INIT(&bucket->rpcs);
        LIST_INIT(&inp->ctx_buckets[i]);
    }
	inp->reuse_ctx = NULL;
	memset(&inp->buffer_pool, 0, sizeof(inp->buffer_pool));
    
    uprintf("socket created!\n");

	mtx_unlock_spin(&pcbmap->write_mtx);
    rw_wunlock(&(base_info.sdtp_zone_sock_lock));

    return error;
}

struct sdtp_rpc *
sdtp_rpc_new_client(struct sdtp_inpcb *pcb, const struct sockaddr_in_union *dest, int *error)
{
    struct sdtp_rpc *rpc;
    struct sdtp_rpc_bucket *bucket;
    struct in6_addr dest_addr;

    *error = 0;
    dest_addr = canonical_ipv6_addr(dest);
    
    rw_wlock(&(base_info.sdtp_zone_rpc_lock));
    rpc = SDTP_ZONE_GET(base_info.sdtp_zone_rpc, struct sdtp_rpc);
    rw_wunlock(&(base_info.sdtp_zone_rpc_lock));
    if (inp == NULL) {
        *error = ENOBUFS;
        return NULL;
    }

    rpc->sdtpcb = pcb;
    rpc->id = atomic_fetch_add(&pcb->sdtp->next_out_id, 2); 

    return rpc;
}
