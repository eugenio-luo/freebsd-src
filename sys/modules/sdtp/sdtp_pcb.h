/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_PCB_H_
#define _SDTP_PCB_H_

#include <sys/cdefs.h>
#include <sys/mutex.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include "sdtp_common.h"
#include "sdtp_pool.h"
#include "sdtp_queue.h"

struct sdtp;
struct sdtp_inpcb; 
struct sdtp_rpc;

struct sdtp_interest {
    struct thread *thread;
 
    uintptr_t ready_rpc_atomic;

    int locked_atomic;
    struct mtx spinlock;

    struct sdtp_rpc *reg_rpc;

    int is_response_atomic;
    int is_request_atomic;
    SDTP_QUEUE_ENTRY(struct sdtp_interest_mqueue, sdtp_interest) request_links;
    SDTP_QUEUE_ENTRY(struct sdtp_interest_mqueue, sdtp_interest) response_links;
};

struct sdtp_rpc_bucket {
    struct sdtp_rpc_mlist rpcs;
};

struct sdtp_pcbmap_link {
    LIST_ENTRY(sdtp_pcbmap_link) hash_links;
    struct sdtp_inpcb *sock;
};

struct sdtp_pcbmap {
    struct mtx write_spinlock;
    struct sdtp_pcbmap_link_list buckets[SDTP_PCBMAP_BUCKETS];
};

struct sdtp_inpcb {
	struct inpcb inp;
    struct socket *socket;

	struct mtx spinlock;
    char *last_locker;

    uint32_t protect_count_atomic;
    struct sdtp *sdtp;
    bool shutdown;
    uint16_t port;
    int ip_header_length;

    struct sdtp_pcbmap_link pcbmap_links;

    struct sdtp_rpc_mqueue active_rpcs;
    struct sdtp_rpc_mqueue dead_rpcs;

    int dead_bufs;

    struct sdtp_rpc_mlist ready_requests;
    struct sdtp_rpc_mlist ready_responses;

    struct sdtp_interest_mqueue request_interests;
    struct sdtp_interest_mqueue response_interests;

    struct sdtp_rpc_bucket client_rpc_buckets[SDTP_CLIENT_RPC_BUCKETS];
    struct sdtp_rpc_bucket server_rpc_buckets[SDTP_SERVER_RPC_BUCKETS];

    struct sdtp_pool buffer_pool;

    struct sdtp_context_list ctx_buckets[SDTP_SERVER_RPC_BUCKETS];
    void *reuse_ctx;
};

static inline void
insert_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&interest->is_response_atomic) == false);

    atomic_store_int(&interest->is_response_atomic, true);
    SDTP_QUEUE_INSERT_TAIL(&pcb->response_interests, interest, response_links);
}

static inline void
remove_response_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&interest->is_response_atomic) == true);

    SDTP_QUEUE_REMOVE(&pcb->response_interests, interest, response_links);
    atomic_store_int(&interest->is_response_atomic, false);
}

static inline void
insert_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&interest->is_request_atomic) == false);

    atomic_store_int(&interest->is_request_atomic, true);
    SDTP_QUEUE_INSERT_TAIL(&pcb->request_interests, interest, request_links);
}

static inline void
remove_request_interest(struct sdtp_inpcb *pcb, struct sdtp_interest *interest)
{
    mtx_assert(&pcb->spinlock, MA_OWNED);
    MPASS(atomic_load_int(&interest->is_request_atomic) == true);

    SDTP_QUEUE_REMOVE(&pcb->request_interests, interest, request_links);
    atomic_store_int(&interest->is_request_atomic, false);
}

void sdtp_sorwakeup(struct sdtp_inpcb *pcb);
struct sdtp_inpcb *sdtp_find_inpcb(struct sdtp_pcbmap *pcbmap, uint16_t port);
int sdtp_inpcb_bind(struct sdtp_pcbmap *pcbmap, uint16_t port, struct sdtp_inpcb *pcb);
int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp);
void sdtp_inpcb_free(struct sdtp_inpcb *pcb);

#endif
