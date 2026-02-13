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
#include "sdtp_output.h"
#include "sdtp_debug.h"

#include <sys/types.h>
#include <sys/hash.h>
#include <sys/endian.h>

#include <netinet/in.h>
#include <netinet6/in6_fib.h>
#include <netinet/in_fib.h>

extern struct sdtp_zones zones;

void
sdtp_peer_lock(struct sdtp_peer *peer)
{
    sdtp_peer_debug(peer, "locked by %#lx", (uintptr_t)curthread);
    mtx_lock_spin(&peer->ack_spinlock);
}

void
sdtp_peer_unlock(struct sdtp_peer *peer)
{
    mtx_unlock_spin(&peer->ack_spinlock);
    sdtp_peer_debug(peer, "unlocked by %#lx", (uintptr_t)curthread);
}

static struct nhop_object *
sdtp_resolve_nh(struct in6_addr *addr, int *error)
{
    struct nhop_object *nh;
    struct in_addr tmp;

    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        ipv6_to_ipv4(addr, &tmp);
        nh = fib4_lookup(RT_DEFAULT_FIB, tmp, 0, NHR_NONE, 0);
    } else {
        nh = fib6_lookup(RT_DEFAULT_FIB, addr, 0, NHR_NONE, 0);
    }

    if (nh == NULL) {
        *error = EHOSTUNREACH;
    }
    return nh;
}

struct sdtp_peer *
sdtp_find_peer(struct sdtp_peermap *peermap, struct in6_addr *addr, struct inpcb *pcb, int *error)
{
	struct sdtp_peer *peer;

    uint32_t bucket_idx = hash32_buf(addr, sizeof(struct in6_addr), HASHINIT);
    bucket_idx &= SDTP_PEERTAB_BUCKETS - 1;

    mtx_lock_spin(&peermap->write_spinlock);
    LIST_FOREACH(peer, &peermap->buckets[bucket_idx], peermap_links) {
        if (is_ipv6_same(&peer->addr, addr)) {
            mtx_unlock_spin(&peermap->write_spinlock);
            return peer;
        }
    }
    mtx_unlock_spin(&peermap->write_spinlock);

    peer = SDTP_ZONE_GET(zones.sdtp_zone_peer, struct sdtp_peer);
    if (!peer) {
        *error = ENOMEM;
        goto sdtp_find_peer_done;
    }

    peer->addr = *addr;

    peer->nh = sdtp_resolve_nh(addr, error);
    if (*error) {
        goto sdtp_find_peer_done;
    }

	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES-1] = 0;
	peer->unsched_cutoffs[SDTP_MAX_PRIORITIES-2] = INT_MAX;
	peer->cutoff_version_be = 0;
	peer->last_update_jiffies = 0;
	TAILQ_INIT(&peer->grantable_rpcs);
	TAILQ_INIT(&peer->grantable_links);
	peer->outstanding_resends = 0;
	peer->most_recent_resend = 0;
	peer->least_recent_rpc = NULL;
	peer->least_recent_ticks = 0;
	peer->current_ticks = -1;
	peer->resend_rpc = NULL;
	peer->num_acks = 0;
	mtx_init(&peer->ack_spinlock, "peer ack spinlock", NULL, MTX_SPIN);

    mtx_lock_spin(&peermap->write_spinlock);
    LIST_INSERT_HEAD(&peermap->buckets[bucket_idx], peer, peermap_links);
    mtx_unlock_spin(&peermap->write_spinlock);

sdtp_find_peer_done:
    return peer;
}

int
sdtp_unsched_priority(struct sdtp *sdtp, struct sdtp_peer *peer, int length)
{
    int i;
	for (i = sdtp->num_priorities-1; ; i--) {
		if (peer->unsched_cutoffs[i] >= length) {
			return i;
        }
	}

    KASSERT(0, ("unreachable"));
    __unreachable();
}
