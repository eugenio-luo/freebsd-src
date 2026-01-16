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

struct sdtp;
struct sdtp_inpcb; 
struct sdtp_rpc;

struct sdtp_interest {
    struct thread *thread;
 
    unsigned long ready_rpc;

    int locked_atomic;
	
    struct sdtp_rpc *reg_rpc;

    TAILQ_ENTRY(sdtp_interest) request_links;
    TAILQ_ENTRY(sdtp_interest) response_links;
};

struct sdtp_rpc_bucket {
	struct mtx spinlock;
    struct sdtp_rpc_list rpcs;
};

struct sdtp_pcbmap_link {
    LIST_ENTRY(sdtp_pcbmap_link) hash_links;
    struct sdtp_inpcb *sock;
};

struct sdtp_pcbmap {
    struct mtx write_spinlock;
    struct sdtp_pcbmap_link_list buckets[SDTP_PCBMAP_BUCKETS];
};

struct sdtp_cache_line {
    char bytes[64];
};

struct sdtp_bpage {
    union {
        struct sdtp_cache_line cache_line;
        struct {
	        struct mtx spinlock;
            uint32_t refs_atomic;
            int owner;
            uint64_t expiration;
        };
    };
};
CTASSERT(sizeof(struct sdtp_bpage) == sizeof(struct sdtp_cache_line));

struct sdtp_pool_core {
    union {
        struct sdtp_cache_line cache_line;
        struct {
            int page_hint;
            int allocated;
            int next_candidate;
        };
    };
};
CTASSERT(sizeof(struct sdtp_pool_core) == sizeof(struct sdtp_cache_line));

struct sdtp_pool {
    struct sdtp *sdtp;

    char *region;
    int num_bpages;

    struct sdtp_bpage *descriptors;

    uint32_t free_bpages_atomic;

    struct sdtp_pool_core *cores;
    int num_cores;
}; 

struct sdtp_context {

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

    struct sdtp_rpc_tailq active_rpcs;
    struct sdtp_rpc_tailq dead_rpcs;
    
    int dead_bufs;

    struct sdtp_rpc_tailq ready_requests;
    struct sdtp_rpc_tailq ready_responses;

    struct sdtp_interest_tailq request_interests;
    struct sdtp_interest_tailq response_interests;

    struct sdtp_rpc_bucket client_rpc_buckets[SDTP_CLIENT_RPC_BUCKETS];
    struct sdtp_rpc_bucket server_rpc_buckets[SDTP_SERVER_RPC_BUCKETS];
    
    struct sdtp_pool buffer_pool;

    struct sdtp_context_list ctx_buckets[SDTP_SERVER_RPC_BUCKETS];
    void *reuse_ctx;
};

struct sdtp_inpcb *sdtp_find_inpcb(struct sdtp_pcbmap *pcbmap, uint16_t port);
int sdtp_inpcb_bind(struct sdtp_pcbmap *pcbmap, uint16_t port, struct sdtp_inpcb *pcb);
int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp);

#endif
