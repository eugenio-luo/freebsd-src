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
#include "sdtp_debug.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>

#include <machine/atomic.h>

extern struct sdtp_zones zones;

void
sdtp_rpc_lock(struct sdtp_rpc *rpc)
{
    sdtp_rpc_debug(rpc, "locked by %#lx", (uintptr_t)curthread);
    mtx_lock_spin(rpc->spinlock_p);
}

void
sdtp_rpc_unlock(struct sdtp_rpc *rpc)
{
    mtx_unlock_spin(rpc->spinlock_p);
    sdtp_rpc_debug(rpc, "unlocked by %#lx", (uintptr_t)curthread);
}

void sdtp_free_mbuf(struct mbuf *buf)
{
    KASSERT(buf != NULL, ("mbuf should be valid"));
    KASSERT(buf->m_len > 0, ("mbuf size should be at least 0"));

    sdtp_debug("buf %#lx free'd", (uintptr_t) buf);
    m_freem(buf);
}

static uint64_t
sdtp_local_id(uint64_t sender_id_be)
{
    return be64toh(sender_id_be) ^ 1;
}

bool
sdtp_is_client(uint64_t id)
{
    return (id & 1) == 0;
}

/*
 * sdtp_handoff_rpc()
 *
 * pcb should be locked
 */
static void
sdtp_handoff_rpc(struct sdtp_rpc *rpc)
{
    VALID_RPC_ASSERT(rpc);

	struct sdtp_interest *interest;
    struct sdtp_inpcb *pcb = rpc->sdtpcb;

    mtx_assert(&pcb->spinlock, MA_OWNED);
    mtx_assert(rpc->spinlock_p, MA_OWNED);

    sdtp_rpc_debug(rpc, "handing off");

    if ((atomic_load_32(&rpc->flags_atomic) & RPC_HANDING_OFF)
        || atomic_load_int(&rpc->is_ready_atomic))
    {
        return;
    }

    if (rpc->interest) {
        interest = rpc->interest;
        goto sdtp_handoff_rpc_waiting;
    }

    if (sdtp_is_client(rpc->id)) {
        interest = SDTP_QUEUE_FIRST(&pcb->response_interests, sdtp_interest);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, rpc);
    } else {
        interest = SDTP_QUEUE_FIRST(&pcb->request_interests, sdtp_interest);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, rpc);
    }

    mtx_unlock_spin(&pcb->spinlock);
    if (rpc->spinlock_p != NULL) {
        sdtp_rpc_unlock(rpc);
    }

    sdtp_sorwakeup(pcb);

    mtx_lock_spin(&pcb->spinlock);
    if (rpc->spinlock_p != NULL) {
        sdtp_rpc_lock(rpc);
    }
    return;

sdtp_handoff_rpc_waiting:
    atomic_set_32(&rpc->flags_atomic, RPC_HANDING_OFF);
    atomic_store_32(&interest->locked_atomic, 0);

    atomic_store_rel_ptr(&interest->ready_rpc_atomic, (uintptr_t) rpc);

    if (interest->reg_rpc) {
        interest->reg_rpc->interest = NULL;
        interest->reg_rpc = NULL;
    }

    if (atomic_load_int(&interest->is_request_atomic)) {
        remove_request_interest(pcb, interest);
    }
    if (atomic_load_int(&interest->is_response_atomic)) {
        remove_response_interest(pcb, interest);
    }

    sdtp_rpc_debug(rpc, "waking up thread: %#x", interest->thread);
    KASSERT(TD_IS_SLEEPING(interest->thread), ("interest's thread should be sleeping"));
    INTEREST_NOT_LINKED(interest);

    wakeup(&interest->spinlock);
}

struct sdtp_rpc *
sdtp_find_client_rpc(struct sdtp_inpcb *pcb, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_rpc_bucket *bucket = sdtp_client_rpc_bucket(pcb, id);

    SDTP_LIST_LOCK(&bucket->rpcs);
    SDTP_LIST_FOREACH_LOCKED(rpc, &bucket->rpcs, hash_links) {
       if (rpc->id == id) {
            return rpc;
        }
    }
    SDTP_LIST_UNLOCK(&bucket->rpcs);
    return NULL;
}

struct sdtp_rpc *
sdtp_find_server_rpc(struct sdtp_inpcb *pcb, struct in6_addr *source, uint16_t port, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_rpc_bucket *bucket = sdtp_server_rpc_bucket(pcb, id);

    SDTP_LIST_LOCK(&bucket->rpcs);
    SDTP_LIST_FOREACH_LOCKED(rpc, &bucket->rpcs, hash_links) {
       if (rpc->id == id
            && rpc->dport == port
            && is_ipv6_same(&rpc->peer->addr, source)) {

            return rpc;
        }
    }
    SDTP_LIST_UNLOCK(&bucket->rpcs);
    return NULL;
}

static struct sdtp_rpc *
sdtp_new_server_rpc(struct sdtp_inpcb *pcb, struct in6_addr *source, struct sdtp_data_header *header, int *error)
{
    *error = 0;
    uint64_t id = sdtp_local_id(header->common.sender_id_be);
    struct sdtp_rpc_bucket *bucket = sdtp_server_rpc_bucket(pcb, id);
    struct sdtp_rpc *rpc = sdtp_find_server_rpc(pcb, source, ntohs(header->common.sport_be), id);

    if (rpc) {
        return rpc;
    }

    rpc = SDTP_ZONE_GET(zones.sdtp_zone_rpc, struct sdtp_rpc);
    if (!rpc) {
        *error = ENOMEM;
        goto sdtp_new_server_rpc_error;
    }

    rpc->sdtpcb = pcb;
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
    SDTP_LIST_ENTRY_INIT(&rpc->hash_links);
    atomic_store_int(&rpc->is_ready_atomic, false);
    SDTP_LIST_ENTRY_INIT(&rpc->ready_links);
    SDTP_QUEUE_ENTRY_INIT(&rpc->active_links);
    SDTP_QUEUE_ENTRY_INIT(&rpc->dead_links);
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
    // rpc->ctx = set_rpc_context();

    SDTP_QUEUE_LOCK(&pcb->active_rpcs);
    SDTP_LIST_LOCK(&bucket->rpcs);
    rpc->spinlock_p = &bucket->rpcs.spinlock;
    SDTP_LIST_INSERT_HEAD_LOCKED(&bucket->rpcs, rpc, hash_links);
    SDTP_QUEUE_INSERT_TAIL_LOCKED(&pcb->active_rpcs, rpc, active_links);
    SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
    if (!rpc->ctx) {
        if (ntohl(header->data_segment.offset_be) == 0) {
            atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
            sdtp_handoff_rpc(rpc);
        }
    }

    mtx_unlock_spin(&pcb->spinlock);
    return rpc;

sdtp_new_server_rpc_error:
    if (rpc) {
        SDTP_ZONE_FREE(zones.sdtp_zone_rpc, rpc);
    }
    return NULL;
}

static void
sdtp_message_in_init(struct sdtp_message_in *msgin, int length, int incoming)
{
    msgin->total_length = length;
    TAILQ_INIT(&msgin->packets);
    msgin->num_bufs = 0;
    msgin->bytes_remaining = length;
	msgin->gsoseg_offset = 0;
	msgin->decrypt_offset = 0;
	msgin->gsoseg_bufs = &msgin->packets;
	msgin->decrypt_bufs = &msgin->packets;
	msgin->max_pkt_data = 0;
	msgin->nextgsoseg_length = 0;
	msgin->nextgsoseg_received = 0;
	msgin->incoming = (incoming > length) ? length : incoming;
	msgin->priority = 0;
	msgin->scheduled = length > incoming;
	msgin->copied_out = 0;
	msgin->num_bpages = 0;
}

/*
 * sdtp_add_packet()
 *
 * rpc need to be locked
 */
static void
sdtp_add_packet(struct mbuf *m, struct sdtp_rpc *rpc, struct sdtp_data_header *header)
{
    RPC_LOCK_OWNED(rpc);
    MBUF_LEN_ASSERT(m, struct sdtp_data_header);

    struct sdtp_packet_tailq_entry *packet, *new;
    int offset = ntohl(header->data_segment.offset_be);
    int data_bytes = ntohl(header->data_segment.segment_length_be);

    int floor = rpc->msgin.copied_out;
    int ceiling = rpc->msgin.total_length;

    TAILQ_FOREACH_REVERSE(packet, &rpc->msgin.packets, sdtp_packet_tailq, link) {
        struct sdtp_data_header *h = mtod(packet->data, struct sdtp_data_header *);
        int tmp_off = ntohl(h->data_segment.offset_be);
        int tmp_dbytes = ntohl(h->data_segment.segment_length_be);
        if (tmp_off < offset) {
            floor = tmp_off + tmp_dbytes;
            break;
        }
        ceiling = tmp_off;
    }

    if ((offset < floor) || (offset + data_bytes > ceiling)) {
        sdtp_free_mbuf(m);
        return;
    }

    if (header->retransmit) {
        (void) header;
        //TODO: homa_freeze()
    }

    new = sdtp_alloc_packet_tailq_entry();
    new->data = m;

    if (packet) {
        TAILQ_INSERT_AFTER(&rpc->msgin.packets, packet, new, link);
    } else {
        TAILQ_INSERT_HEAD(&rpc->msgin.packets, new, link);
    }

    rpc->msgin.bytes_remaining -= data_bytes;
    rpc->msgin.num_bufs++;

}

/*
 * sdtp_data_packet()
 *
 * rpc need to be locked
 */
static int 
sdtp_data_packet(struct mbuf *m, struct sdtp_rpc *rpc, struct sdtp_inpcb *pcb)
{
    RPC_LOCK_OWNED(rpc);

    MBUF_LEN_ASSERT(m, struct sdtp_data_header);
    VALID_PCB_ASSERT(pcb);
    VALID_RPC_ASSERT(rpc);

    struct sdtp_data_header *header = mtod(m, struct sdtp_data_header *);
    struct sdtp *sdtp = pcb->sdtp;
    bool rpc_handoff = false;
    int old_remaining, incoming_delta = 0;

    sdtp_data_header_debug(header, NULL);

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
        sdtp_message_in_init(&rpc->msgin, ntohl(header->message_length_be), ntohl(header->incoming_be));
        incoming_delta += rpc->msgin.incoming;

        if (rpc->ctx) {
		    /* TODO: Set sdtp_max_pkt_data for first data packet */
            (void) rpc->ctx;
        }
    }

    old_remaining = rpc->msgin.bytes_remaining;
    if (rpc->ctx) {
        // TODO: sdtp_add_packet()
        (void) rpc->ctx;
    } else {
        (void) rpc->ctx;
        sdtp_add_packet(m, rpc, header);
    }
    incoming_delta -= old_remaining - rpc->msgin.bytes_remaining;

    if (rpc->ctx) {
        (void) rpc->ctx;
        // TODO: rpc_handoff = 
    } else {
        rpc_handoff = !(atomic_load_32(&rpc->flags_atomic) & RPC_PKTS_READY);
    }

    if (rpc_handoff) {
        atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
        mtx_lock_spin(&pcb->spinlock);
        sdtp_handoff_rpc(rpc);
        mtx_unlock_spin(&pcb->spinlock);
    }

    if (rpc->msgin.scheduled) {
		(void) rpc;
        // TODO: homa_check_grantable(homa, rpc);
    }

    if (ntohs(header->cutoff_version_be) !=sdtp->cutoff_version) {
        (void) rpc;
        //TODO: The sender has out-of-date cutoffs
    }

    return incoming_delta;

sdtp_data_packet_error:
    sdtp_free_mbuf(m);
    return incoming_delta;
}

static void
sdtp_reap_rpc(struct sdtp_inpcb *pcb, int count)
{
}

void
sdtp_handle_packet(struct mbuf *m, struct in6_addr *source, struct sdtp_inpcb *pcb)
{
    // TODO: For now without sdtp_lock_cache, I lock the rpc lock

    MBUF_LEN_ASSERT(m, struct sdtp_common_header);
    VALID_PCB_ASSERT(pcb);

    struct sdtp_common_header *header = mtod(m, struct sdtp_common_header *);
    int error = 0;
    uint64_t id = sdtp_local_id(header->sender_id_be);
    struct sdtp *sdtp = pcb->sdtp;
    struct sdtp_rpc *rpc;

    sdtp_header_debug(header, "is_client: %d", sdtp_is_client(id));

    if (!sdtp_is_client(id)) {
        if (header->type == SDTP_DATA) {
            m = m_pullup(m, sizeof(struct sdtp_data_header));
            if (!m) {
                goto sdtp_handle_packet_error;
            }
            struct sdtp_data_header *data_header = mtod(m, struct sdtp_data_header *);

            rpc = sdtp_new_server_rpc(pcb, source, data_header, &error);
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

    switch (header->type) {
    case SDTP_DATA: {
        m = m_pullup(m, sizeof(struct sdtp_data_header));
        if (!m) {
            break;
        }
        int incoming_delta = sdtp_data_packet(m, rpc, pcb);

        atomic_add_64(&sdtp->total_incoming_atomic, incoming_delta);

        // TODO: sdtp_rpc_reap
        break;
    }

    default:
        break;
    }

    sdtp_rpc_unlock(rpc);

    RPC_LOCK_NOTOWNED(rpc);
    return;

sdtp_handle_packet_error:
    return;
}

void
sdtp_rpc_free(struct sdtp_rpc *rpc)
{
    int delta;

    mtx_assert(rpc->spinlock_p, MA_OWNED);

    if (rpc == NULL || rpc->state == SDTP_RPC_DEAD) {
        return;
    }

    rpc->state = SDTP_RPC_DEAD;
    // TODO: sdtp_remove_from_grantable

    if (SDTP_LIST_LINKED(rpc, hash_links)) {
        SDTP_LIST_REMOVE_LOCKED(rpc, hash_links);
    }
    if (SDTP_QUEUE_LINKED(rpc, active_links)) {
        SDTP_QUEUE_REMOVE_LOCKED(&(rpc->sdtpcb->active_rpcs), rpc, active_links);
    }
    SDTP_QUEUE_INSERT_TAIL(&(rpc->sdtpcb->dead_rpcs), rpc, dead_links);
	rpc->sdtpcb->dead_bufs += rpc->msgin.num_bufs + rpc->msgout.num_bufs;
    if (SDTP_LIST_LOCK_IF_LINKED(rpc, ready_links)) {
        SDTP_LIST_REMOVE(rpc, ready_links);
    }
    if (rpc->interest != NULL) {
        rpc->interest->reg_rpc = NULL;
        wakeup(&rpc->interest->spinlock);
        rpc->interest = NULL;
    }

    delta = (rpc->msgin.total_length < 0) ? 0
	    : (rpc->msgin.incoming - (rpc->msgin.total_length
	    - rpc->msgin.bytes_remaining));
    if (delta != 0) {
        atomic_add_64(&rpc->sdtpcb->sdtp->total_incoming_atomic, delta);
    }
    // TODO: sdtp_remove_from_throttled
}
