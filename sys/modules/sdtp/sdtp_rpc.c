/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp.h"
#include "sdtp_os.h"
#include "sdtp_rpc.h"
#include "sdtp_structs.h"
#include "sdtp_peer.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>

#include <machine/atomic.h>

// TODO: fix whatever mess with sdtp_new_server_rpc() and sdtp_handoff_rpc()

extern struct sdtp_zones zones;

static uint64_t
sdtp_local_id(uint64_t sender_id_be)
{
    return be64toh(sender_id_be) ^ 1;
}

static bool
sdtp_is_client(uint64_t id)
{
    return (id & 1) == 0;
}

static void
sdtp_handoff_rpc(struct sdtp_rpc *rpc)
{
	struct sdtp_interest *interest;
    struct sdtp_inpcb *pcb = rpc->sdtpcb;

    if ((atomic_load_32(&rpc->flags_atomic) & RPC_HANDING_OFF)
        || rpc->is_ready)
    {
        return;
    }

    if (rpc->interest) {
        interest = rpc->interest;
        goto sdtp_handoff_rpc_waiting;
    }

    if (sdtp_is_client(rpc->id)) {
        interest = TAILQ_FIRST(&pcb->response_interests);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, rpc);
    } else {
        interest = TAILQ_FIRST(&pcb->request_interests);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, rpc);
    }

    sorwakeup(pcb->socket);
    return;

sdtp_handoff_rpc_waiting:
    atomic_set_32(&rpc->flags_atomic, RPC_HANDING_OFF);
    atomic_store_32(&interest->locked_atomic, 0);
    atomic_store_rel_long(&interest->ready_rpc, (long) rpc);

    if (interest->reg_rpc) {
        interest->reg_rpc->interest = NULL;
        interest->reg_rpc = NULL;
    }
    if (interest->request_links.tqe_prev != NULL) {
        TAILQ_REMOVE(&pcb->request_interests, interest, request_links);
    }
    if (interest->response_links.tqe_prev != NULL) {
        TAILQ_REMOVE(&pcb->response_interests, interest, response_links);
    }
    // TODO: I'm not sure if this is the correct function?
    wakeup(&interest->thread);
}

static struct sdtp_rpc *
sdtp_find_client_rpc(struct sdtp_inpcb *pcb, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_rpc_bucket *bucket = sdtp_client_rpc_bucket(pcb, id);

    mtx_lock_spin(&bucket->spinlock);
    LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
       if (rpc->id == id) {
            return rpc;
        }
    }
    mtx_unlock_spin(&bucket->spinlock);
    return NULL;
}

static struct sdtp_rpc *
sdtp_find_server_rpc(struct sdtp_inpcb *pcb, struct in6_addr *source, uint16_t port, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_rpc_bucket *bucket = sdtp_server_rpc_bucket(pcb, id);

    mtx_lock_spin(&bucket->spinlock);
    LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
       if (rpc->id == id
            && rpc->dport == port
            && is_ipv6_same(&rpc->peer->addr, source)) {

            return rpc;
        }
    }
    mtx_unlock_spin(&bucket->spinlock);
    return NULL;
}

static struct sdtp_rpc *
sdtp_new_server_rpc(struct sdtp_inpcb *pcb, struct in6_addr *source, struct sdtp_data_header *header, int *error)
{
    *error = 0;
    uint64_t id = sdtp_local_id(header->common.sender_id_be);
    struct sdtp_rpc_bucket *bucket = sdtp_server_rpc_bucket(pcb, id);
    struct sdtp_rpc *rpc = NULL;

    mtx_lock_spin(&bucket->spinlock);
    LIST_FOREACH(rpc, &bucket->rpcs, hash_links) {
       if (rpc->id == id
            && rpc->dport == ntohs(header->common.sport_be)
            && is_ipv6_same(&rpc->peer->addr, source)) {

            return rpc;
        }
    }

    rpc = SDTP_ZONE_GET(zones.sdtp_zone_rpc, struct sdtp_rpc);
    if (!rpc) {
        *error = ENOMEM;
        goto sdtp_new_server_rpc_error;
    }

    rpc->sdtpcb = pcb;
    rpc->spinlock = &bucket->spinlock;
    rpc->state = SDTP_RPC_INCOMING;
    atomic_store_32(&rpc->flags_atomic, 0);
    atomic_store_32(&rpc->grants_in_progress_atomic, 0);
    rpc->peer = sdtp_find_peer(&pcb->sdtp->peers, source, &pcb->inp, error);
    if (*error != 0) {
        goto sdtp_new_server_rpc_error;
    }
    rpc->dport = ntohs(header->common.sport_be);
    rpc->id = id;
    rpc->completion_cookie = 0;
	rpc->error = 0;
    rpc->is_ready = false;
	rpc->msgin.total_length = -1;
	rpc->msgin.num_bufs = 0;
	rpc->msgin.num_bpages = 0;
	memset(&rpc->msgout, 0, sizeof(rpc->msgout));
	rpc->msgout.length = -1;
    rpc->interest = NULL;
    TAILQ_INIT(&rpc->grantable_links);
    TAILQ_INIT(&rpc->throttled_links);
    rpc->silent_ticks = 0;
	rpc->resend_timer_ticks = pcb->sdtp->timer_ticks;
	rpc->done_timer_ticks = 0;
	rpc->magic = SDTP_RPC_MAGIC;
	rpc->start_cycles = get_cyclecount();

    mtx_lock_spin(&pcb->spinlock);
    if (pcb->shutdown) {
        mtx_unlock_spin(&pcb->spinlock);
        *error = ESHUTDOWN;
        goto sdtp_new_server_rpc_error;
    }

    // TODO: HomaLS context initialization

    LIST_INSERT_HEAD(&bucket->rpcs, rpc, hash_links);
    TAILQ_INSERT_TAIL(&pcb->active_rpcs, rpc, active_links);
    if (!rpc->ctx) {
        if (ntohl(header->data_segment.offset_be) == 0) {
            atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
            sdtp_handoff_rpc(rpc);
        }
    }

    mtx_unlock_spin(&pcb->spinlock);
    return rpc;

sdtp_new_server_rpc_error:
    mtx_unlock_spin(&bucket->spinlock);
    if (rpc) {
        SDTP_ZONE_FREE(zones.sdtp_zone_rpc, rpc);
    }
    return NULL;
}

static void
sdtp_data_packet(struct mbuf *m, struct sdtp_rpc *rpc, struct sdtp_data_header *header, struct sdtp_inpcb *pcb)
{
    /*
    struct sdtp *sdtp = pcb->sdtp;
    bool rpc_handoff = false;

    if (rpc->state != SDTP_RPC_INCOMING) {
        if (sdtp_is_client(rpc->id)) {
            if (rpc->state != SDTP_RPC_OUTGOING) {
                goto sdtp_data_packet_error;
            }
            rpc->state = SDTP_RPC_INCOMING;
        } else {
            if (rpc->msgin.total_length >= 0) {
                goto sdtp_data_packet_error;
            }
        }
    }

    if (rpc->msgin.total_length < 0) {
    }

    if (rpc_handoff) {
        sdtp_handoff_rpc(rpc);
    }

    return;

sdtp_data_packet_error:
    m_freem(m);
    */
    sdtp_handoff_rpc(rpc);
    return;
}

void
sdtp_handle_packet(struct mbuf *m, struct sdtp_common_header *header, struct in6_addr *source, struct sdtp_inpcb *pcb)
{
    // TODO: implement sdtp_lock_cache?
    // I don't think we need it for now if we are only processing one at a time anyway
    // but if I don't implement it, then I need to start locking the RPC itself?

    int error = 0;
    uint64_t id = sdtp_local_id(header->sender_id_be);
    struct sdtp_rpc *rpc;

    if (!sdtp_is_client(id)) {
        if (header->type == SDTP_DATA) {
            rpc = sdtp_new_server_rpc(pcb, source, (struct sdtp_data_header *) header, &error);
            if (error) {
                rpc = NULL;
                goto sdtp_handle_packet_error;
            }
        } else {
            rpc = sdtp_find_server_rpc(pcb, source, ntohs(header->sport_be), id);
        }
    } else {
        rpc = sdtp_find_client_rpc(pcb, id);
    }

    if (!rpc) {
        if (header->type != SDTP_CUTOFFS && header->type != SDTP_NEED_ACK
            && header->type != SDTP_ACK && header->type != SDTP_RESEND) {
            goto sdtp_handle_packet_error;
        }
    } else {
        if (header->type == SDTP_DATA || header->type == SDTP_GRANT || header->type == SDTP_BUSY) {
            rpc->silent_ticks = 0; 
        }
        rpc->peer->outstanding_resends = 0; 
        
        // TODO: implement frozen
    }

    printf("sdtp_header type: %x, sport: %d\n", header->type, ntohs(header->sport_be));
    switch (header->type) {
    case SDTP_DATA: {
        sdtp_data_packet(m, rpc, (struct sdtp_data_header *) header, pcb);
        break;
    }

    default:
        break;
    }

    return;

sdtp_handle_packet_error:
    m_freem(m);
}
