/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_RPC_H_
#define _SDTP_RPC_H_

#include <sys/mutex.h>

#include "sdtp.h"
#include "sdtp_common.h"
#include "sdtp_pcb.h"

struct sdtp_peer;

struct sdtp_packet_slist_entry {
    /*
     * it is guaranteed that all these mbufs 
     * have sdtp_data_header as first bytes
    */ 
    struct mbuf *data;

    SLIST_ENTRY(sdtp_packet_slist_entry) link;
};

struct sdtp_packet_tailq_entry {
    /*
     * it is guaranteed that all these mbufs 
     * have sdtp_data_header as first bytes
    */ 
    struct mbuf *data;

    TAILQ_ENTRY(sdtp_packet_tailq_entry) link;
};

struct sdtp_message_out {
    int length;
    int num_buffers;

    struct sdtp_packet_slist packets;
    struct sdtp_packet_slist_entry **nextxmit;
    int next_xmit_offset;

    unsigned int active_xmits_atomic;

    int gso_pkt_data;
    int unscheduled;
    int granted;

    uint8_t sched_priority;
    uint64_t init_cycles;
};

struct sdtp_message_in {
    int total_length;
    
    struct sdtp_packet_tailq packets;

    int num_bufs;

    int bytes_remaining;
    int decrypt_offset;
    struct sdtp_packet_tailq *decrypt_bufs;
	
    int gsoseg_offset;
	int nextgsoseg_length;
	int nextgsoseg_received; 

    struct sdtp_packet_tailq *gsoseg_bufs;

    unsigned int max_pkt_data;
    int incoming;
    int priority;
    bool scheduled;
    uint64_t birth;
    int copied_out;
    uint32_t num_bpages;
    uint32_t bpage_offsets[SDTP_MAX_BPAGES];
};

struct sdtp_rpc {
    struct sdtp_inpcb *sdtpcb;

	struct mtx *spinlock_p;

    enum {
        SDTP_RPC_OUTGOING            = 5,
		SDTP_RPC_INCOMING            = 6,
		SDTP_RPC_IN_SERVICE          = 8,
		SDTP_RPC_DEAD                = 9
    } state;

    uint32_t flags_atomic;

#define RPC_PKTS_READY        1
#define RPC_COPYING_FROM_USER 2
#define RPC_COPYING_TO_USER   4
#define RPC_HANDING_OFF       8
#define RPC_DECRYPTING	      16
#define RPC_ACKING_HOMALS     32

#define RPC_CANT_REAP (RPC_COPYING_FROM_USER | RPC_COPYING_TO_USER \
		| RPC_HANDING_OFF | RPC_DECRYPTING | RPC_ACKING_HOMALS)

    uint32_t grants_in_progress_atomic;

	struct sdtp_peer *peer;

    uint16_t dport;
    uint64_t id;
    uint64_t completion_cookie;
    int error;

    struct sdtp_message_in msgin;
    struct sdtp_message_out msgout;

    LIST_ENTRY(sdtp_rpc) hash_links;

    int is_ready_atomic;

    TAILQ_ENTRY(sdtp_rpc) ready_links;
    TAILQ_ENTRY(sdtp_rpc) active_links;
    TAILQ_ENTRY(sdtp_rpc) dead_links;

    struct sdtp_interest *interest;

	struct sdtp_rpc_tailq grantable_links;
	struct sdtp_rpc_tailq throttled_links;

    int silent_ticks;
    uint32_t resend_timer_ticks;
    uint32_t done_timer_ticks;

#define SDTP_RPC_MAGIC 0xdeadbeef
	int magic;

	uint64_t start_cycles;

	void *ctx;
	void *rpc_offload_ctx_tx;
	void *rpc_offload_ctx_rx;
};

static inline void
insert_ready_rpc(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&rpc->is_ready_atomic) == false);

    atomic_store_int(&rpc->is_ready_atomic, true);
    TAILQ_INSERT_TAIL(&pcb->ready_responses, rpc, ready_links);
}

static inline void
remove_ready_rpc(struct sdtp_inpcb *pcb, struct sdtp_rpc *rpc)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&rpc->is_ready_atomic) == true);

    TAILQ_REMOVE(&pcb->ready_responses, rpc, ready_links);
    atomic_store_int(&rpc->is_ready_atomic, false);
}

struct sdtp_rpc *sdtp_find_client_rpc(struct sdtp_inpcb *pcb, uint64_t id);
bool sdtp_is_client(uint64_t id);
void sdtp_handle_packet(struct mbuf *m, struct in6_addr *addr, struct sdtp_inpcb *pcb);
void sdtp_rpc_lock(struct sdtp_rpc *rpc);
void sdtp_rpc_unlock(struct sdtp_rpc *rpc);
void sdtp_free_mbuf(struct mbuf *buf);

#endif
