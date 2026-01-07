/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp_os.h"
#include "sdtp_pcb.h"
#include "sdtp_structs.h"

#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

extern struct sdtp_zones zones;

// TODO: Currently unsafe for readers!!!! There is no atomic guarantee
static struct sdtp_inpcb *sdtp_find_pcb(struct sdtp_pcbmap *pcbmap, uint16_t port)
{
    struct sdtp_pcbmap_link *link;
    struct sdtp_inpcb *result = NULL;

    // TODO: do we need `hlist_for_each_entry_rcu` here? 
	LIST_FOREACH(link, &pcbmap->buckets[sdtp_port_hash(port)], hash_links) {
        struct sdtp_inpcb *pcb = link->sock;
        if (pcb->port == port) {
            result = pcb;
            break;
        }
    }
    
	return result;
}

int
sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp)
{
    int i;
	struct sdtp_inpcb *inp;
    struct sdtp_pcbmap *pcbmap = &sdtp->port_map;

    inp = SDTP_ZONE_GET(zones.sdtp_zone_sock, struct sdtp_inpcb);
    if (inp == NULL) {
        return ENOBUFS;
    }

    inp->socket = so;
    so->so_pcb = inp;

    atomic_store_32(&inp->protect_count_atomic, 0);
	mtx_init(&inp->spinlock, "socket spinlock", NULL, MTX_SPIN);
	inp->last_locker = "none";
    inp->sdtp = sdtp;
	inp->shutdown = false;
	inp->ip_header_length = (INP_SOCKAF(so) == AF_INET)
			? SDTP_IPV4_HEADER_LENGTH : SDTP_IPV6_HEADER_LENGTH;

    for (i = 0; i < SDTP_CLIENT_RPC_BUCKETS; i++) {
		struct sdtp_rpc_bucket *bucket = &inp->client_rpc_buckets[i];
	    mtx_init(&bucket->spinlock, "SDTP client rpc bucket spinlock", NULL, MTX_SPIN);
        LIST_INIT(&bucket->rpcs);
	}
    for (i = 0; i < SDTP_SERVER_RPC_BUCKETS; i++) {
        struct sdtp_rpc_bucket *bucket = &inp->server_rpc_buckets[i];
	    mtx_init(&bucket->spinlock, "SDTP server rpc bucket spinlock", NULL, MTX_SPIN);
        LIST_INIT(&bucket->rpcs);
        LIST_INIT(&inp->ctx_buckets[i]);
    }

    // TODO: what is the equivalent of hlist_add_head_rcu?
    TAILQ_INIT(&inp->active_rpcs);
    TAILQ_INIT(&inp->dead_rpcs);
    inp->dead_skbs = 0;
    TAILQ_INIT(&inp->ready_requests);
    TAILQ_INIT(&inp->ready_responses);
    TAILQ_INIT(&inp->request_interests);
    TAILQ_INIT(&inp->response_interests);

	inp->reuse_ctx = NULL;
	memset(&inp->buffer_pool, 0, sizeof(inp->buffer_pool));
    
    mtx_lock_spin(&pcbmap->write_spinlock);
    
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
	sdtp->next_client_port++;
	inp->pcbmap_links.sock = inp;
    
    uprintf("socket created!\n");

    LIST_INSERT_HEAD(&pcbmap->buckets[sdtp_port_hash(inp->port)], &inp->pcbmap_links, hash_links);
	
    mtx_unlock_spin(&pcbmap->write_spinlock);

    return 0;
}
