/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_PEER_H_
#define _SDTP_PEER_H_

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/cdefs.h>
#include <sys/domain.h>
#include <sys/mutex.h>

#include <netinet/in.h>

#include "sdtp.h"

struct sdtp_rpc;

struct sdtp_peer {
    struct in6_addr addr;
    struct nhop_object *nh;

    int unsched_cutoffs[SDTP_MAX_PRIORITIES];
    
    uint16_t cutoff_version_be;

    unsigned long last_update_jiffies;

	struct sdtp_rpc_tailq grantable_rpcs;
	struct sdtp_rpc_tailq grantable_links;

    LIST_ENTRY(sdtp_peer) peermap_links;

    int outstanding_resends;
    int most_recent_resend;
    
    struct sdtp_rpc *least_recent_rpc;

    uint32_t least_recent_ticks;
    uint32_t current_ticks;

    struct sdtp_rpc *resend_rpc;

    int num_acks;

    struct sdtp_ack acks[NUM_PEER_UNACKED_IDS];

    struct mtx ack_spinlock;
};

struct sdtp_peermap {
    struct mtx write_spinlock;
    struct sdtp_dead_dst_tailq dead_dsts;
    struct sdtp_peer_list *buckets;
};

struct sdtp_peer *sdtp_find_peer(struct sdtp_peermap *peermap, struct in6_addr *addr, struct inpcb *pcb, int *error);
void sdtp_peer_ack(struct sdtp_rpc *rpc);
void sdtp_peer_lock(struct sdtp_peer *peer);
void sdtp_peer_unlock(struct sdtp_peer *peer);
int sdtp_unsched_priority(struct sdtp *sdtp, struct sdtp_peer *peer, int length);

#endif
