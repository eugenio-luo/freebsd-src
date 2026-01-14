/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_STRUCTS_H_
#define _SDTP_STRUCTS_H_

#include <sys/mutex.h>
#include <sys/queue.h>
#include <vm/uma.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/cdefs.h>

#include <netinet/in.h>

#include "sdtp_common.h"
#include "sdtp.h"
#include "sdtp_pcb.h"
#include "sdtp_peer.h"
#include "sdtp_rpc.h"

/*
struct sockaddr_in_union {
    struct sockaddr_in  in4;
    struct sockaddr_in6 in6;
};

inline struct in6_addr
canonical_ipv6_addr(const struct sockaddr_in_union *addr)
{
    struct in6_addr res;

    if (addr->in6.sin6_family == AF_INET) {
        bzero(&res, sizeof(res));
        res.s6_addr[10] = 0xff;
        res.s6_addr[11] = 0xff;
        memcpy(&res.s6_addr[12], &addr->in4.sin_addr, 4);
    } else {
        res = addr->in6.sin6_addr;
    }

    return res;
}
*/

struct sdtp_core {
    uint64_t last_active;
    uint64_t last_gro;
    /*
     * atomic_t softirq_backlog;
     * int softirq_offset;
     */

    struct sdtp_packet *held_packet;
    int held_bucket;
    struct thread *thread;
    uint64_t syscall_end_time;

    // struct homa_metrics metrics;
};

struct sdtp_dead_dst {
    struct nhop_object *nh;
    uint64_t gc_time;
    struct sdtp_dead_dst_tailq dst_links;
};

enum sdtp_freeze_type {
	RESTART_RPC        = 1,
	PEER_TIMEOUT       = 2,
	SLOW_RPC           = 3,
	SOCKET_CLOSE       = 4,
	PACKET_LOST        = 5,
};

struct sdtp {
	uint64_t next_out_id_atomic; 
	uint64_t link_idle_time_atomic __aligned(SDTP_CACHE_LINE_SIZE);
	
    struct mtx grantable_spinlock __aligned(SDTP_CACHE_LINE_SIZE); 
    struct sdtp_rpc_tailq grantable_rpcs;
	int num_grantable_rpcs;
	uint64_t last_grantable_change;
	int max_grantable_rpcs;
	int grant_nonfifo;
	int grant_nonfifo_left;
	
    /* only try */
	struct mtx pacer_spinlock __aligned(SDTP_CACHE_LINE_SIZE);
    int pacer_fifo_fraction;
	int pacer_fifo_count;
	uint64_t pacer_wake_time;
	
    struct mtx throttle_spinlock;
    struct sdtp_rpc_tailq throttled_rpcs;
	uint64_t throttle_add; 
	int throttle_min_bytes;
	uint64_t total_incoming_atomic __aligned(CACHE_LINE_SIZE);
	uint16_t next_client_port __aligned(CACHE_LINE_SIZE);

    struct sdtp_pcbmap port_map __aligned(CACHE_LINE_SIZE);
    struct sdtp_peermap peers;
    
    int unsched_bytes;
    int link_mbps;
    int poll_usecs;
    int poll_cycles;
    int num_priorities;
    int priority_map[SDTP_MAX_PRIORITIES];
    int max_sched_prio;
    int unsched_cutoffs[SDTP_MAX_PRIORITIES];
    int cutoff_version;
	int fifo_grant_increment;
    int grant_fifo_fraction;
    int max_overcommit;
    int max_incoming;
    int max_rpcs_per_peer;
    int dynamic_windows;
    int resend_ticks;
    int resend_interval;
    int timeout_resends;
    int request_ack_ticks;
    int reap_limit;
    int dead_buffs_limit;
    int max_dead_buffs;

    struct thread *pacer_kthread;

    bool pacer_exit;
    int max_nic_queue_ns;
    int max_nic_queue_cycles;
    uint32_t cycles_per_kbyte;
    int verbose;
    int max_gso_size;
    int max_gro_skbs;
    int gso_force_software;
    int gro_policy;

    #define SDTP_GRO_BYPASS          0x1
	#define SDTP_GRO_SAME_CORE       0x2
	#define SDTP_GRO_IDLE            0x4
	#define SDTP_GRO_NEXT            0x8
	#define SDTP_GRO_IDLE_NEW        0x10
	#define SDTP_GRO_FAST_GRANTS     0x20
	#define SDTP_GRO_SHORT_BYPASS    0x40
	#define SDTP_GRO_NORMAL      (SDTP_GRO_SAME_CORE|SDTP_GRO_IDLE_NEW \
			|SDTP_GRO_SHORT_BYPASS)

    int gro_busy_usecs;
    int gro_busy_cycles;
    uint32_t timer_ticks;

    struct mtx metrics_spinlock;
    char *metrics;
    size_t metrics_capacity;
    size_t metrics_length;
    
    int metrics_active_opens;
	int flags;
    enum sdtp_freeze_type freeze_type;
    int sync_freeze;
    int bpage_lease_usecs;
	int hardware_state_threshold;
	char hardware_interface[32];
    int bpage_lease_cycles;
    int temp[4];
};

struct sdtp_crypto_info {
    
};

typedef struct uma_zone *sdtp_zone_t;

struct sdtp_zones {
    sdtp_zone_t sdtp_zone_sock;
    sdtp_zone_t sdtp_zone_rpc;
    sdtp_zone_t sdtp_zone_peer;
};

static inline struct sdtp_rpc_bucket *sdtp_client_rpc_bucket(struct sdtp_inpcb *pcb, uint64_t id)
{
    return &pcb->client_rpc_buckets[(id >> 1) & (SDTP_CLIENT_RPC_BUCKETS - 1)];
}

static inline int sdtp_port_hash(uint16_t port)
{
	return port & (SDTP_PCBMAP_BUCKETS - 1);
}

int sdtp_init(struct sdtp *sdtp);
int sdtp_uninit(struct sdtp *sdtp);
void sdtp_interest_init(struct sdtp_interest *interest);

int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp);
//struct sdtp_rpc *sdtp_rpc_new_client(struct sdtp_inpcb *pcb, const struct sockaddr_in_union *dest, int *error);

#endif 
