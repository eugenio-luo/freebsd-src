/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp_common.h"
#include "sdtp_os.h"
#include "sdtp_peer.h"
#include "sdtp_structs.h"

#include <sys/types.h>
#include <sys/hash.h>

extern struct sdtp_zones zones;

struct sdtp_peer *
sdtp_find_peer(struct sdtp_peermap *peermap, struct in6_addr *addr, struct inpcb *pcb, int *error)
{
	struct sdtp_peer *peer;

    uint32_t bucket_idx = hash32_buf(addr, sizeof(struct in6_addr), HASHINIT);
    bucket_idx &= SDTP_PEERTAB_BUCKETS - 1;

    // TODO: Read not atomically safe!!
    LIST_FOREACH(peer, &peermap->buckets[bucket_idx], peermap_links) {
        if (is_ipv6_same(&peer->addr, addr)) {
            return peer;
        }
    }

    mtx_lock_spin(&peermap->write_spinlock);
    LIST_FOREACH(peer, &peermap->buckets[bucket_idx], peermap_links) {
        if (is_ipv6_same(&peer->addr, addr)) {
            goto sdtp_find_peer_done;
        }
    }

    peer = SDTP_ZONE_GET(zones.sdtp_zone_peer, struct sdtp_peer);
    if (!peer) {
        *error = ENOMEM;
        goto sdtp_find_peer_done;
    }

    peer->addr = *addr;
    // TODO: for now no nh !!!!
	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES-1] = 0;
	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES-2] = INT_MAX;
	peer->cutoff_version_be = 0;
	peer->last_update_jiffies = 0;
	TAILQ_INIT(&peer->grantable_rpcs);
	TAILQ_INIT(&peer->grantable_links);
    LIST_INSERT_HEAD(&peermap->buckets[bucket_idx], peer, peermap_links);
	peer->outstanding_resends = 0;
	peer->most_recent_resend = 0;
	peer->least_recent_rpc = NULL;
	peer->least_recent_ticks = 0;
	peer->current_ticks = -1;
	peer->resend_rpc = NULL;
	peer->num_acks = 0;
	mtx_init(&peer->ack_spinlock, "peer ack spinlock", NULL, MTX_SPIN);

sdtp_find_peer_done:
    mtx_unlock_spin(&peermap->write_spinlock);
    return peer;
}
