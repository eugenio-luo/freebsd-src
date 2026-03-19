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
#include "sdtp_test.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>

#include <machine/atomic.h>

extern struct sdtp_zones zones;

// TODO: there is a possible lock reversal between rpc lock and pcb lock

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

    sdtp_debug("buf %#lx free'd\n", (uintptr_t) buf);
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

static inline struct sdtp_rpc *
sdtp_rpc_zone_get(struct sdtp_inpcb *pcb)
{
    struct sdtp_rpc *rpc = SDTP_ZONE_GET(zones.sdtp_zone_rpc, struct sdtp_rpc);
    if (rpc) {
        SDTP_METRIC(pcb, allocated_rpcs_atomic, 1);
    }
    return rpc;
}

static inline void
sdtp_rpc_zone_free(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
    SDTP_ZONE_FREE(zones.sdtp_zone_rpc, rpc);
    SDTP_METRIC(pcb, freed_rpcs_atomic, 1);
}

/*
 * sdtp_handoff_rpc()
 *
 * pcb should be locked
 */
static void
sdtp_handoff_rpc(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);
    VALID_PCB_ASSERT(pcb);
    mtx_assert(&pcb->spinlock, MA_OWNED);

	struct sdtp_interest *interest;

    sdtp_rpc_debug(rpc, "handing off");

    if ((atomic_load_32(&rpc->flags_atomic) & RPC_HANDING_OFF)
        || atomic_load_int(&rpc->is_ready_atomic))
    {
        sdtp_rpc_debug(rpc, "already handing off");
        return;
    }

    if (rpc->interest) {
        sdtp_rpc_debug(rpc, "already has interest");
        interest = rpc->interest;
        goto sdtp_handoff_rpc_waiting;
    }

    if (sdtp_is_client(rpc->id)) {
        sdtp_rpc_debug(rpc, "check if thread is waiting for response");
        interest = SDTP_QUEUE_FIRST(&pcb->response_interests, sdtp_interest);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, &pcb->ready_responses, rpc);
    } else {
        sdtp_rpc_debug(rpc, "check if thread is waiting for request");
        interest = SDTP_QUEUE_FIRST(&pcb->request_interests, sdtp_interest);
        if (interest) {
            goto sdtp_handoff_rpc_waiting;
        }
        insert_ready_rpc(pcb, &pcb->ready_requests, rpc);
    }

    mtx_unlock_spin(&pcb->spinlock);
    if (rpc->spinlock_p != NULL) {
        sdtp_rpc_unlock(rpc);
    }

    sdtp_rpc_debug(rpc, "wake up pcb");
    sdtp_sorwakeup(pcb);

    mtx_lock_spin(&pcb->spinlock);
    if (rpc->spinlock_p != NULL) {
        sdtp_rpc_lock(rpc);
    }
    return;

sdtp_handoff_rpc_waiting:
    mtx_lock_spin(&interest->spinlock);
    sdtp_rpc_debug(rpc, "there is a thread waiting");
    atomic_set_32(&rpc->flags_atomic, RPC_HANDING_OFF);
    atomic_store_32(&interest->locked_atomic, 0);

    atomic_store_rel_ptr(&interest->ready_rpc_atomic, (uintptr_t) rpc);
    sdtp_rpc_hold(rpc);

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
    INTEREST_NOT_LINKED(interest);

    wakeup(&interest->spinlock);
    mtx_unlock_spin(&interest->spinlock);
}

struct sdtp_rpc *
sdtp_find_client_rpc(struct sdtp_inpcb *pcb, uint64_t id)
{
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_rpc_bucket *bucket = sdtp_client_rpc_bucket(pcb, id);

    sdtp_pcb_debug(pcb, "finding client rpc");

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

    sdtp_pcb_debug(pcb, "finding server rpc");

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

struct sdtp_rpc *
sdtp_new_client_rpc(struct sdtp_inpcb *pcb, struct in6_addr *dest, uint16_t port, int *error)
{
    struct sdtp_rpc_bucket *bucket;
    struct sdtp_rpc *rpc;
    *error = 0;

    sdtp_pcb_debug(pcb, "creating new client rpc");
    rpc = sdtp_rpc_zone_get(pcb);
    if (!rpc) {
        *error = ENOMEM;
        sdtp_pcb_debug(pcb, "not enough memory for new client rpc");
        goto sdtp_new_client_rpc_error;
    }

    rpc->sdtpcb = pcb;
    rpc->id = atomic_fetchadd_64(&pcb->sdtp->next_out_id_atomic, 2);
    rpc->state = SDTP_RPC_OUTGOING;

    bucket = sdtp_client_rpc_bucket(pcb, rpc->id);
    rpc->peer = sdtp_find_peer(&pcb->sdtp->peers, dest, &pcb->inp, error);
    if (*error != 0) {
        sdtp_pcb_debug(pcb, "new client rpc can't find peer");
        goto sdtp_new_client_rpc_error;
    }
    rpc->dport = port;
    rpc->msgin.total_length = -1;
    rpc->msgout.length = -1;
    SDTP_LIST_ENTRY_INIT(&rpc->hash_links);
    atomic_store_int(&rpc->is_ready_atomic, false);
    SDTP_LIST_ENTRY_INIT(&rpc->ready_links);
    SDTP_QUEUE_ENTRY_INIT(&rpc->active_links);
    SDTP_QUEUE_ENTRY_INIT(&rpc->dead_links);
    TAILQ_INIT(&rpc->grantable_links);
    TAILQ_INIT(&rpc->throttled_links);
	rpc->resend_timer_ticks = pcb->sdtp->timer_ticks;
	rpc->magic = SDTP_RPC_MAGIC;
	rpc->start_cycles = get_cyclecount();
    refcount_init(&rpc->refs, 0);

    mtx_lock_spin(&pcb->spinlock);
    if (pcb->shutdown) {
        mtx_unlock_spin(&pcb->spinlock);
        *error = ESHUTDOWN;
        goto sdtp_new_client_rpc_error;
    }

    SDTP_QUEUE_LOCK(&pcb->active_rpcs);
    SDTP_LIST_LOCK(&bucket->rpcs);
    rpc->spinlock_p = &bucket->rpcs.spinlock;
    SDTP_LIST_INSERT_HEAD_LOCKED(&bucket->rpcs, rpc, hash_links);
    SDTP_QUEUE_INSERT_TAIL_LOCKED(&pcb->active_rpcs, rpc, active_links);
    SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
    mtx_unlock_spin(&pcb->spinlock);

    return rpc;

sdtp_new_client_rpc_error:
    // TODO: free peer
    if (rpc) {
        sdtp_rpc_zone_free(pcb, rpc);
    }
    return NULL;
}

SDTP_STATIC inline void
sdtp_set_header_offset(struct sdtp_data_header *header)
{
    if (ntohl(header->data_segment.offset_be) == -1) {
        header->data_segment.offset_be = header->common.sequence_be;
    }
}

static void
sdtp_init_server_rpc_fields(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc, struct sdtp_data_header *header, uint64_t id)
{
    rpc->sdtpcb = pcb;
    rpc->state = SDTP_RPC_INCOMING;
    atomic_store_32(&rpc->flags_atomic, 0);
    atomic_store_32(&rpc->grants_in_progress_atomic, 0);
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
    refcount_init(&rpc->refs, 0);
}

static void
sdtp_lock_rpc_and_insert_pcb_list(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc, uint64_t id)
{
    struct sdtp_rpc_bucket *bucket = sdtp_server_rpc_bucket(pcb, id);

    SDTP_QUEUE_LOCK(&pcb->active_rpcs);
    SDTP_LIST_LOCK(&bucket->rpcs);
    rpc->spinlock_p = &bucket->rpcs.spinlock;
    SDTP_LIST_INSERT_HEAD_LOCKED(&bucket->rpcs, rpc, hash_links);
    SDTP_QUEUE_INSERT_TAIL_LOCKED(&pcb->active_rpcs, rpc, active_links);
    SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
}

SDTP_STATIC struct sdtp_expected_rpc_ptr
sdtp_new_server_rpc(struct sdtp_inpcb *pcb, struct in6_addr *source, struct sdtp_data_header *header)
{
    int error = 0;
    uint64_t id = sdtp_local_id(header->common.sender_id_be);
    struct sdtp_rpc *rpc = sdtp_find_server_rpc(pcb, source, ntohs(header->common.sport_be), id);

    if (rpc) {
        sdtp_pcb_debug(pcb, "no need for new rpc, found old one");
        return SDTP_MAKE_EXPECTED(struct sdtp_expected_rpc_ptr, rpc);
    }

    sdtp_pcb_debug(pcb, "creating new server rpc");

    rpc = sdtp_rpc_zone_get(pcb);
    if (!rpc) {
        error = ENOMEM;
        sdtp_pcb_debug(pcb, "not enough memory for new server rpc");
        goto sdtp_new_server_rpc_error;
    }

    sdtp_set_header_offset(header);
    sdtp_init_server_rpc_fields(pcb, rpc, header, id);
    rpc->peer = sdtp_find_peer(&pcb->sdtp->peers, source, &pcb->inp, &error);
    if (error != 0) {
        sdtp_pcb_debug(pcb, "new server rpc can't find peer");
        goto sdtp_new_server_rpc_error;
    }

    mtx_lock_spin(&pcb->spinlock);
    if (pcb->shutdown) {
        mtx_unlock_spin(&pcb->spinlock);
        error = ESHUTDOWN;
        goto sdtp_new_server_rpc_error;
    }

    // TODO: HomaLS context initialization
    // rpc->ctx = set_rpc_context();

    sdtp_lock_rpc_and_insert_pcb_list(pcb, rpc, id);

    if (!rpc->ctx) {
        if (ntohl(header->data_segment.offset_be) == 0) {
            atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
            sdtp_handoff_rpc(pcb, rpc);
        }
    }

    mtx_unlock_spin(&pcb->spinlock);
    return SDTP_MAKE_EXPECTED(struct sdtp_expected_rpc_ptr, rpc);

sdtp_new_server_rpc_error:
    // TODO: free peer
    if (rpc) {
        sdtp_rpc_zone_free(pcb, rpc);
    }
    return SDTP_MAKE_UNEXPECTED(struct sdtp_expected_rpc_ptr, error);
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

static bool
sdtp_add_packet(struct mbuf *m, struct sdtp_rpc *rpc, struct sdtp_data_header *header)
{
    KASSERT(m != NULL, ("m must be valid"));
    MBUF_LEN_ASSERT(m, struct sdtp_data_header);
    KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);
    KASSERT(header != NULL, ("header must be valid"));

    struct sdtp_packet_tailq_entry *packet, *new;
    int offset = ntohl(header->data_segment.offset_be);
    int data_bytes = m->m_pkthdr.len - sizeof(struct sdtp_data_header);
    int floor = rpc->msgin.copied_out;
    int ceiling = rpc->msgin.total_length;

    sdtp_data_header_debug(header, "size: %d", data_bytes);
    KASSERT(data_bytes > 0, ("data_bytes must be positive"));

    TAILQ_FOREACH_REVERSE(packet, &rpc->msgin.packets, sdtp_packet_tailq, link) {

        KASSERT(packet->data->m_flags & M_PKTHDR, ("packet must be a header mbuf"));

        struct sdtp_data_header *h = mtod(packet->data, struct sdtp_data_header *);
        int tmp_off = ntohl(h->data_segment.offset_be);
        int tmp_dbytes = packet->data->m_pkthdr.len - sizeof(struct sdtp_data_header);

        KASSERT(tmp_dbytes > 0, ("tmp_dbytes must be positive"));

        if (tmp_off < offset) {
            floor = tmp_off + tmp_dbytes;
            break;
        }
        ceiling = tmp_off;
    }

    if ((offset < floor) || (offset + data_bytes > ceiling)) {
        sdtp_rpc_debug(rpc, "drop packet");
        return false;
    }

    if (header->retransmit) {
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
    sdtp_rpc_debug(rpc, "new packet added");
    return true;
}

static void
sdtp_rpc_acked(struct sdtp_inpcb *pcb, struct in6_addr *source_addr, uint16_t source_port, struct sdtp_ack *ack)
{
    uint16_t server_port = ntohs(ack->server_port_be);
    uint64_t id = sdtp_local_id(ack->client_id_be);
    struct sdtp_inpcb *tmp = pcb;
    struct sdtp_rpc *rpc;

    if (tmp->port != server_port) {
        tmp = sdtp_find_inpcb(&pcb->sdtp->port_map, server_port);
        if (!tmp) {
            return;
        }
    }

    rpc = sdtp_find_server_rpc(tmp, source_addr, source_port, id);
    if (rpc) {
        SDTP_QUEUE_LOCK(&pcb->active_rpcs);
        sdtp_rpc_free(rpc);
        SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
        sdtp_rpc_unlock(rpc);
    }
}

/* return true if RPC is alive, otherwise false. We need to check because we drop the RPC lock */
static bool
sdtp_ack_client(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc, struct sdtp_data_header *header, struct in6_addr *source)
{
    if (header->ack.client_id_be == 0) {
        return true;
    }

    sdtp_rpc_unlock(rpc);
    sdtp_rpc_acked(pcb, source, ntohs(header->common.sport_be), &header->ack);
    sdtp_rpc_lock(rpc);

    return rpc->state != SDTP_RPC_DEAD;
}

/* return false if the RPC isn't in the correct state */
static bool
sdtp_prepare_rpc_for_data(struct sdtp_rpc *rpc)
{
    bool is_client = sdtp_is_client(rpc->id);

    if (rpc->state == SDTP_RPC_INCOMING) {
        return true;
    }

    if (!is_client && rpc->msgin.total_length >= 0) {
        return false;
    }

    if (is_client) {
        if (rpc->state != SDTP_RPC_OUTGOING) {
            return false;
        }

        rpc->state = SDTP_RPC_INCOMING;
    }

    return true;
}

static bool
sdtp_data_packet(struct sdtp *sdtp, struct mbuf *m, struct sdtp_rpc *rpc, struct sdtp_inpcb *pcb, struct in6_addr *source)
{
    KASSERT(sdtp != NULL, ("sdtp must be valid"));
    KASSERT(m != NULL, ("m must be valid"));
    VALID_RPC_ASSERT(rpc);
    RPC_LOCK_OWNED(rpc);
    VALID_PCB_ASSERT(pcb);
    KASSERT(source != NULL, ("source must be valid"));

    struct sdtp_data_header *header = mtod(m, struct sdtp_data_header *);
    sdtp_set_header_offset(header);
    sdtp_data_header_debug(header, NULL);

    if (!sdtp_ack_client(pcb, rpc, header, source)) {
        goto sdtp_data_packet_error;
    }

    if (!sdtp_prepare_rpc_for_data(rpc)) {
        goto sdtp_data_packet_error;
    }

    if (rpc->msgin.total_length < 0) {
        sdtp_message_in_init(&rpc->msgin, ntohl(header->message_length_be), ntohl(header->incoming_be));
        if (rpc->ctx) {
		    /* TODO: Set sdtp_max_pkt_data for first data packet */
        }
    }

    if (rpc->ctx) {
        // TODO: sdtp_add_packet() and handoff() 
        goto sdtp_data_packet_error;
    } else {
        if (!sdtp_add_packet(m, rpc, header)) {
            goto sdtp_data_packet_error;
        }

        if (!(atomic_load_32(&rpc->flags_atomic) & RPC_PKTS_READY)) {
            atomic_set_32(&rpc->flags_atomic, RPC_PKTS_READY);
            mtx_lock_spin(&pcb->spinlock);
            sdtp_handoff_rpc(pcb, rpc);
            mtx_unlock_spin(&pcb->spinlock);
        }
    }

    if (rpc->msgin.scheduled) {
        // TODO: homa_check_grantable(homa, rpc);
    }

    if (ntohs(header->cutoff_version_be) != sdtp->cutoff_version) {
        //TODO: The sender has out-of-date cutoffs
    }

    return true;

sdtp_data_packet_error:
    return false;
}

int
sdtp_rpc_reap(struct sdtp_inpcb *pcb, bool reap_all)
{
#define BATCH_MAX 10
    struct sdtp_rpc *rpcs[BATCH_MAX];
    struct sdtp_packet_slist_entry *out_pkts[BATCH_MAX];
    struct sdtp_packet_tailq_entry *in_pkts[BATCH_MAX];
    bool checked_all_rpcs;
    int bufs_to_reap, batch_size, num_out_pkts, num_in_pkts, num_rpcs;
    struct sdtp_rpc *rpc, *tmp;

    sdtp_pcb_debug(pcb, "reap dead rpcs");

    bufs_to_reap = pcb->sdtp->reap_limit;
    checked_all_rpcs = SDTP_QUEUE_EMPTY(&pcb->dead_rpcs);
    sdtp_pcb_debug(pcb, "empty dead rpcs? %d", checked_all_rpcs);
    while (!checked_all_rpcs) {
        batch_size = BATCH_MAX;
        if (!reap_all) {
            if (bufs_to_reap <= 0) {
                sdtp_pcb_debug(pcb, "bufs_to_reap: %d", bufs_to_reap);
                break;
            }
            if (batch_size > bufs_to_reap) {
                batch_size = bufs_to_reap;
            }
            bufs_to_reap -= batch_size;
        }
        num_out_pkts = 0;
        num_in_pkts = 0;
        num_rpcs = 0;

        sdtp_pcb_debug(pcb, "reap batch size: %d", batch_size);

        mtx_lock_spin(&pcb->spinlock);
        if (atomic_load_32(&pcb->protect_count_atomic)) {
            mtx_unlock_spin(&pcb->spinlock);
            return 0;
        }

        SDTP_QUEUE_LOCK(&pcb->dead_rpcs);
        SDTP_QUEUE_FOREACH_SAFE_LOCKED(rpc, &pcb->dead_rpcs, dead_links, tmp) {
            u_int refs;

            if ((atomic_load_32(&rpc->flags_atomic) & RPC_CANT_REAP)
                || (atomic_load_32(&rpc->grants_in_progress_atomic) != 0)
                || (atomic_load_int(&rpc->msgout.active_xmits_atomic) != 0) ) {

                continue;
            }

            sdtp_rpc_lock(rpc);
            refs = refcount_load(&rpc->refs);
            sdtp_rpc_unlock(rpc);

            if (refs > 1) {
                continue;
            }

            rpc->magic = 0;
            rpc->state = 0;
            if (rpc->msgout.length >= 0) {
                while (!SLIST_EMPTY(&rpc->msgout.packets)) {
                    out_pkts[num_out_pkts] = SLIST_FIRST(&rpc->msgout.packets);
                    SLIST_REMOVE_HEAD(&rpc->msgout.packets, link);
                    ++num_out_pkts;
                    --rpc->msgout.num_bufs;
                    if (num_out_pkts >= batch_size) {
                        goto sdtp_reap_rpc_release;
                    }
                }
            }

            if (rpc->msgin.total_length >= 0) {
                while (!TAILQ_EMPTY(&rpc->msgin.packets)) {
                    in_pkts[num_in_pkts] = TAILQ_FIRST(&rpc->msgin.packets);
                    TAILQ_REMOVE_HEAD(&rpc->msgin.packets, link);
                    ++num_in_pkts;
                    --rpc->msgin.num_bufs;
                    if (num_in_pkts >= batch_size) {
                        goto sdtp_reap_rpc_release;
                    }
                }
            }

            rpcs[num_rpcs] = rpc;
            ++num_rpcs;
            SDTP_QUEUE_REMOVE_LOCKED(&pcb->dead_rpcs, rpc, dead_links);
            if (num_rpcs >= batch_size) {
                goto sdtp_reap_rpc_release;
            }
        }
        checked_all_rpcs = true;

sdtp_reap_rpc_release:
        SDTP_QUEUE_UNLOCK(&pcb->dead_rpcs);
        pcb->dead_bufs -= num_out_pkts + num_in_pkts;
        mtx_unlock_spin(&pcb->spinlock);

        sdtp_pcb_debug(pcb, "reap %d out packets", num_out_pkts);
        for (int i = 0; i < num_out_pkts; ++i) {
            m_freem(out_pkts[i]->data);
            SDTP_ZONE_FREE(zones.sdtp_zone_packet_slist_entry, out_pkts[i]);
            SDTP_METRIC(pcb, freed_send_pkts_atomic, 1);
        }

        sdtp_pcb_debug(pcb, "reap %d in packets", num_in_pkts);
        for (int i = 0; i < num_in_pkts; ++i) {
            m_freem(in_pkts[i]->data);
            sdtp_free_packet_tailq_entry(in_pkts[i]);
            SDTP_METRIC(pcb, freed_recv_pkts_atomic, 1);
        }

        sdtp_pcb_debug(pcb, "reap %d rpcs", num_rpcs);
        for (int i = 0; i < num_rpcs; ++i) {
            sdtp_rpc_lock(rpcs[i]);
            sdtp_rpc_unlock(rpcs[i]);
            sdtp_rpc_zone_free(pcb, rpcs[i]);
        }
    }

    return !checked_all_rpcs;
}

SDTP_STATIC struct sdtp_expected_rpc_ptr
sdtp_get_rpc(struct mbuf *m, struct sdtp_inpcb *pcb, struct sdtp_common_header *header, struct in6_addr *source)
{
    KASSERT(m != NULL, ("m must be valid"));
    MBUF_LEN_ASSERT(m, struct sdtp_common_header);
    VALID_PCB_ASSERT(pcb);
    KASSERT(header != NULL, ("header must be valid"));
    KASSERT(source != NULL, ("source must be valid"));

    uint64_t id = sdtp_local_id(header->sender_id_be);
    bool is_client = sdtp_is_client(id);
    struct sdtp_rpc *rpc;
    struct sdtp_expected_rpc_ptr expected_rpc;

    sdtp_header_debug(header, "id: %x, is_client: %d", id, sdtp_is_client(id));

    if (!is_client && header->type == SDTP_DATA) {
        /* We are the RPC server and it's a DATA packet */
        expected_rpc = sdtp_new_server_rpc(pcb, source, mtod(m, struct sdtp_data_header *));
        if (!SDTP_IS_ERROR(expected_rpc) && SDTP_GET_VAL(expected_rpc) != NULL) {
            VALID_RPC_ASSERT(SDTP_GET_VAL(expected_rpc));
            RPC_LOCK_OWNED(SDTP_GET_VAL(expected_rpc));
        }
        return expected_rpc;
    }

    rpc = is_client ? sdtp_find_client_rpc(pcb, id)
                    : sdtp_find_server_rpc(pcb, source, ntohs(header->sport_be), id);
    if (rpc) {
        VALID_RPC_ASSERT(rpc);
        RPC_LOCK_OWNED(rpc);
    }
    return SDTP_MAKE_EXPECTED(struct sdtp_expected_rpc_ptr, rpc);
}

SDTP_STATIC bool
sdtp_preprocess_rpc(struct sdtp_rpc *rpc, struct sdtp_common_header *header)
{
    KASSERT(header != NULL, ("header must be valid"));

    if (rpc) {
        VALID_RPC_ASSERT(rpc);
        RPC_LOCK_OWNED(rpc);

        if (header->type == SDTP_DATA || header->type == SDTP_GRANT || header->type == SDTP_BUSY) {
            rpc->silent_ticks = 0;
        }
        rpc->peer->outstanding_resends = 0; 
        return true;

    } else if (header->type != SDTP_CUTOFFS && header->type != SDTP_NEED_ACK
        && header->type != SDTP_ACK && header->type != SDTP_RESEND) {

        return false;
    }

    return true;
}

static void
sdtp_ack_packet(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc, struct mbuf *m, struct in6_addr *source)
{
    struct sdtp_ack_header *header = mtod(m, struct sdtp_ack_header *);
    int n = ntohs(header->num_acks_be);

    if (rpc) {
        SDTP_QUEUE_LOCK(&pcb->active_rpcs);
        sdtp_rpc_free(rpc);
        SDTP_QUEUE_UNLOCK(&pcb->active_rpcs);
    }

    if (n > 0) {
        if (rpc) {
            sdtp_rpc_unlock(rpc);
        }

        for (int i = 0; i < n; ++i) {
            sdtp_rpc_acked(pcb, source, ntohs(header->common.sport_be), &header->acks[i]);
        }

        if (rpc) {
            sdtp_rpc_lock(rpc);
        }
    }
}

/* TODO: temporary solution */
static void
sdtp_cutoffs_packet(struct mbuf *m, struct sdtp_rpc *rpc)
{
    struct sdtp_cutoffs_header *cutoffs_header = mtod(m, struct sdtp_cutoffs_header *);
    if (rpc) {
        rpc->peer->cutoff_version_be = cutoffs_header->cutoff_version_be;
    }
}

void
sdtp_handle_packet(struct mbuf *m, struct in6_addr *source, struct sdtp_inpcb *pcb)
{
    KASSERT(m != NULL, ("m must be valid"));
    MBUF_LEN_ASSERT(m, struct sdtp_common_header);
    KASSERT(m->m_flags & M_PKTHDR, ("mbuf must be a header mbuf"));
    VALID_PCB_ASSERT(pcb);
    KASSERT(source != NULL, ("source must be valid"));

    struct sdtp_common_header *header = mtod(m, struct sdtp_common_header *);

    KASSERT(header->type >= SDTP_DATA && header->type <= SDTP_ACK, ("header type must be valid (%#x)", header->type));
    KASSERT(m->m_pkthdr.len >= sdtp_header_lengths[header->type - SDTP_DATA], ("mbuf must be at least the size of its type header"));
    KASSERT(m->m_len >= sdtp_header_lengths[header->type - SDTP_DATA], ("mbuf must contain its type header"));

    bool consumed = false;
    struct sdtp_rpc *rpc = NULL;
    struct sdtp_expected_rpc_ptr expected_rpc;

    expected_rpc = sdtp_get_rpc(m, pcb, header, source);
    if (SDTP_IS_ERROR(expected_rpc)) {
        goto sdtp_handle_packet_error;
    }
    rpc = SDTP_GET_VAL(expected_rpc);

    if (rpc) {
        sdtp_rpc_hold(rpc);
    }

    if (!sdtp_preprocess_rpc(rpc, header)) {
        goto sdtp_handle_packet_error;
    }

    switch (header->type) {
    case SDTP_DATA: {
        consumed = sdtp_data_packet(pcb->sdtp, m, rpc, pcb, source);
        break;
    }

    case SDTP_CUTOFFS:
        sdtp_cutoffs_packet(m, rpc);
        break;

    case SDTP_ACK:
        sdtp_ack_packet(pcb, rpc, m, source);
        break;

    case SDTP_GRANT:
    case SDTP_RESEND:
    case SDTP_UNKNOWN:
    case SDTP_BUSY:
    case SDTP_FREEZE:
    case SDTP_NEED_ACK:
        break;

    default:
        KASSERT(0, ("switch statement: header type must be valid (%#x)", header->type));
        __unreachable();
    }

    if (rpc) {
        sdtp_rpc_put(rpc);
        sdtp_rpc_unlock(rpc);
    }
    if (!consumed) {
        sdtp_free_mbuf(m);
    }
    if (pcb->dead_bufs >= 2 * pcb->sdtp->dead_buffs_limit) {
        sdtp_rpc_reap(pcb, /* reap_all */ false);
    }

    return;

sdtp_handle_packet_error:
    if (rpc) {
        sdtp_rpc_put(rpc);
        sdtp_rpc_unlock(rpc);
    }
    sdtp_free_mbuf(m);
}

void
sdtp_rpc_free(struct sdtp_rpc *rpc)
{
    VALID_RPC_ASSERT(rpc);

    int delta;

    mtx_assert(rpc->spinlock_p, MA_OWNED);

    if (rpc == NULL || rpc->state == SDTP_RPC_DEAD) {
        return;
    }

    rpc->state = SDTP_RPC_DEAD;
    // TODO: sdtp_remove_from_grantable

    /* TODO: somehow sdtp_pcb_free hold the lock for this? */
    if (SDTP_LIST_LINKED(rpc, hash_links)) {
        SDTP_LIST_REMOVE_LOCKED(rpc, hash_links);
    }
    /* we don't need to lock here sdtp_pcb_free own the lock */
    if (SDTP_QUEUE_LINKED(rpc, active_links)) {
        SDTP_QUEUE_REMOVE_LOCKED(&(rpc->sdtpcb->active_rpcs), rpc, active_links);
    }
    SDTP_QUEUE_INSERT_TAIL(&(rpc->sdtpcb->dead_rpcs), rpc, dead_links);
	rpc->sdtpcb->dead_bufs += rpc->msgin.num_bufs + rpc->msgout.num_bufs;
    if (SDTP_LIST_LOCK_IF_LINKED(rpc, ready_links)) {
        SDTP_LIST_REMOVE_LOCKED_THEN_UNLOCK(rpc, ready_links);
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
