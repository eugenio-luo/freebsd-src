/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_STRUCTS_H_
#define _SDTP_STRUCTS_H_

#include <sys/mutex.h>
#include <sys/queue.h>
#include <vm/uma.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/mbufq.h>

#include <netinet/in.h>
#include <netinet6/in6.h>

#include <netinet/in_pcb.h>

// TODO: convert a lot of LIST_ENTRY and LIST_HEAD to TAILQ_ENTRY and TAILQ_HEAD

#define SDTP_MIN_DEFAULT_PORT 0x8000

#define MAX_SDTP_RPC 0x4000

#define SDTP_CLIENT_RPC_BUCKETS 1024
#define SDTP_SERVER_RPC_BUCKETS 1024
#define SDTP_PCBMAP_BUCKETS     1024

#define SDTP_IPV6_HEADER_LENGTH 40
#define SDTP_IPV4_HEADER_LENGTH 20


#define SDTP_MAX_MESSAGE_LENGTH 1000000
#define SDTP_BPAGE_SHIFT 16
#define SDTP_BPAGE_SIZE (1 << SDTP_BPAGE_SHIFT)
#define SDTP_MAX_BPAGES ((SDTP_MAX_MESSAGE_LENGTH + SDTP_BPAGE_SIZE - 1) \
		>> SDTP_BPAGE_SHIFT)

struct sockaddr_in_union {
    struct sockaddr_in  in4;
    struct sockaddr_in6 in6;
};

inline struct in6_addr
canonical_ipv6_addr(const sockaddr_in_union *addr)
{
    struct in6_addr res;

    if (addr->in6.sin6_family == AF_INET) {
        bzero(&res, sizeof(res));
        res.s6_addr[10] = 0xff;
        res.s6_addr[11] = 0xff;
        memcpy(&res.s6_addr[12], &addr->in4.sin_addr, 4);
    } else {
        res = addr->in6.sin6_addr;
        in6_clearscope(&res);
    }

    return res;
}

struct sdtp_inpcb;
struct sdtp;
struct sdtp_peer;

struct sdtp_message_out {
    int length;
    int num_buffers;

    struct mbuf *packets;
    struct mbuf **next_xmit;

    int next_xmit_offset;

    /* atomic */
    unsigned int active_xmits;

    int gso_pkt_data;
    int unscheduled;
    int granted;

    uint8_t sched_priority;
    uint64_t init_cycles;
};

struct sdtp_message_in {
    int total_length;
    struct mbufq packets;
    int num_bufs;

    int bytes_remaining;
    int decrypt_offset;

	int gsoseg_offset;
	int nextgsoseg_length;
	int nextgsoseg_received; 

    struct mbufq *decrypt_mbufq;
    struct mbufq *gsoseg_mbufq;

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

    /* spinlock */
	struct mtx lock;

    enum {
        RPC_OUTGOING            = 5,
		RPC_INCOMING            = 6,
		RPC_IN_SERVICE          = 8,
		RPC_DEAD                = 9
    } state;

    /* atomic */
    uint32_t flags;

#define RPC_PKTS_READY        1
#define RPC_COPYING_FROM_USER 2
#define RPC_COPYING_TO_USER   4
#define RPC_HANDING_OFF       8
#define RPC_DECRYPTING	      16
#define RPC_ACKING_HOMALS     32 // handling ackes after decryption

#define RPC_CANT_REAP (RPC_COPYING_FROM_USER | RPC_COPYING_TO_USER \
		| RPC_HANDING_OFF | RPC_DECRYPTING | RPC_ACKING_HOMALS)

    /* atomic */
    uint32_t grants_in_progress;

	struct sdtp_peer *peer;

    uint16_t dport;
    uint64_t id;
    uint64_t completion_cookie;
    int error;
    struct sdtp_message_in msgin;
    struct sdtp_message_out msgout;

    LIST_ENTRY(sdtp_rpc) hash_links;
    LIST_ENTRY(sdtp_rpc) ready_links;
    
    LIST_ENTRY(sdtp_rpc) active_links;
	LIST_ENTRY(sdtp_rpc) dead_links;

    struct sdtp_interest *interest;

	LIST_ENTRY(sdtp_rpc) grantable_links;
	LIST_ENTRY(sdtp_rpc) throttled_links;

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

struct sdtp_rpc_bucket {
    /* spinlock */
	struct mtx lock;

    LIST_HEAD(, sdtp_rpc) rpcs;
};

struct sdtp_interest {
    struct thread *thread;
 
    unsigned long ready_rpc;

	/* only atomic operations access, it can potentially be negative */
    int locked;

    LIST_ENTRY(sdtp_interest) request_links;
    LIST_ENTRY(sdtp_interest) response_links;
};

struct sdtp_cache_line {
    char bytes[64];
};

struct sdtp_bpage {
    union {
        struct sdtp_cache_line cache_line;
        struct {
            /* spinlock */
	        struct mtx lock;

	        /* only atomic operations access, it can potentially be negative */
            uint32_t refs;

            int owner;

            uint64_t expiration;
        };
    };
};

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

struct sdtp_pool {
    struct sdtp *sdtp;

    char *region;
    int num_bpages;

    struct sdtp_bpage *descriptors;

	/* only atomic operations access, it can potentially be negative */
    uint32_t free_bpages;

    struct sdtp_pool_core *cores;

    int num_cores;
}; 

struct sdtp_context {

};

struct sdtp_pcbmap_link {
    LIST_ENTRY(sdtp_pcbmap_link) hash_links;
    struct sdtp_inpcb *sock;
};

struct sdtp_inpcb {
	struct inpcb inp;

    struct socket *socket;

    /* spinlock */
	struct mtx lock;
    char *last_locker;
    
	/* only atomic operations access, it can potentially be negative */
    uint32_t protect_count;

    struct sdtp *sdtp;
    bool shutdown;
    uint16_t port;
    int ip_header_length;

    struct sdtp_pcbmap_link pcbmap_links;

	LIST_HEAD(, sdtp_rpc) active_rpcs;
	LIST_HEAD(, sdtp_rpc) dead_rpcs;

    int dead_skbs;

    LIST_HEAD(, sdtp_rpc) ready_requests;
    LIST_HEAD(, sdtp_rpc) ready_responses;

    LIST_HEAD(, sdtp_interest) request_interests;
    LIST_HEAD(, sdtp_interest) response_interests;

    struct sdtp_rpc_bucket client_rpc_buckets[SDTP_CLIENT_RPC_BUCKETS];
    struct sdtp_rpc_bucket server_rpc_buckets[SDTP_SERVER_RPC_BUCKETS];

    struct sdtp_pool buffer_pool;

    LIST_HEAD(, sdtp_context) ctx_buckets[SDTP_SERVER_RPC_BUCKETS];
    void *reuse_ctx;
};

struct sdtp_pcbmap {
	/* spinlock */
    struct mtx write_mtx;

    LIST_HEAD(, sdtp_pcbmap_link) buckets[SDTP_PCBMAP_BUCKETS];
};

struct sdtp_dead_dst {
    LIST_ENTRY(sdtp_dead_dst) dst_links;
    
    /* todo: dst_entry, I have no idea how to translate it */
    // struct dst_entry *dst;
    
    uint64_t gc_time;
};

struct sdtp_ack {
    /* big endian */
    uint64_t client_id;

    /* big endian */
    uint16_t client_port;

    /* big endian */
    uint16_t server_port;
} __attribute__((packed));

#define SDTP_MAX_PRIORITIES 8
#define NUM_PEER_UNACKED_IDS 5

struct sdtp_peer {
    struct in6_addr addr;

    // todo: struct flowi
    
    // todo: struct dst_entry *

    int unsched_cutoffs[SDTP_MAX_PRIORITIES];

    /* big endian */
    uint16_t cutoff_version;

    unsigned long last_update_jiffies;

	LIST_HEAD(, sdtp_rpc) grantable_rpcs;
	LIST_ENTRY(sdtp_rpc) grantable_links;

    LIST_ENTRY(sdtp_peer) peermap_links;   
    
    int outstanding_resends;
    int most_recent_resend;
    
    struct sdtp_rpc *least_recent_rpc;

    uint32_t least_recent_ticks;
    uint32_t current_ticks;

    struct sdtp_rpc *resend_rpc;

    int num_acks;

    struct sdtp_ack acks[NUM_PEER_UNACKED_IDS];

    /* spinlock */
    struct mtx ack_lock;
};

#define SDTP_PEERTAB_BUCKET_BITS 20
#define SDTP_PEERTAB_BUCKETS (1 << SDTP_PEERTAB_BUCKET_BITS)

LIST_HEAD(sdtp_peer_head, sdtp_peer);

struct sdtp_peermap {
	/* spinlock */
    struct mtx write_mtx;

    LIST_HEAD(, sdtp_dead_dst) dead_dsts;

    struct sdtp_peer_head *buckets;
};

enum sdtp_freeze_type {
	RESTART_RPC        = 1,
	PEER_TIMEOUT       = 2,
	SLOW_RPC           = 3,
	SOCKET_CLOSE       = 4,
	PACKET_LOST        = 5,
};

struct sdtp {
	/* only atomic operations access */
	uint64_t next_out_id; 
	/* only atomic operations access */
	uint64_t link_idle_time; 
	
	/* spinlock for @grantable_rpcs and @num_grantable_rpcs */
	struct mtx grantable_spinlock;  
	LIST_HEAD(, sdtp_rpc) grantable_rpcs;
	int num_grantable_rpcs;
	uint64_t last_grantable_change;
	int max_grantable_rpcs;
	int grant_nonfifo;
	int grant_nonfifo_left;
	
	/* Use only in 'try' mode. Ensures only one instance of sdtp_pacer_xmit runs at a time */
	struct mtx pacer_spinlock __aligned(CACHE_LINE_SIZE);
	/* set externally with sysctl */
	int pacer_fifo_fraction;
	int pacer_fifo_count;
	uint64_t pacer_wake_time;
	
	/* spinlock for @throttled_rpcs */
	struct mtx throttle_spinlock;  
	/* TODO: it should be accessed only by _rcu functions, but they don't exists in FreeBSD
	 * so I need to find something equivalent */
	LIST_HEAD(, sdtp_rpc) throttled_rpcs;
	uint64_t throttle_add; 
	/* set externally with sysctl */
	int throttle_min_bytes;
	/* only atomic operations access, it can potentially be negative */
	uint64_t total_incoming __aligned(CACHE_LINE_SIZE);
	uint16_t next_client_port __aligned(CACHE_LINE_SIZE);

    struct sdtp_pcbmap port_map __aligned(CACHE_LINE_SIZE);

    struct sdtp_peermap peers;

    int unsched_bytes;

    int link_mbps;

    int poll_usecs;

    int poll_cycles;
  
    int num_priorities;

    int priority_map[SDTP_MAX_PRIORITIES];

    int max_sched_prio;

    int unsched_cutoffs[SDTP_MAX_PRIORITIES];

    int cutoff_version;

	int fifo_grant_increment;
	
    int grant_fifo_fraction;

    int max_overcommit;

    int max_incoming;

    int max_rpcs_per_peer;

    int dynamic_windows;

    int resend_ticks;

    int resend_interval;

    int timeout_resends;

    int request_ack_ticks;

    int reap_limit;

    int dead_buffs_limit;

    int max_dead_buffs;

    struct thread *pacer_kthread;

    bool pacer_exit;

    int max_nic_queue_ns;

    int max_nic_queue_cycles;

    uint32_t cycles_per_kbyte;

    int verbose;

    int max_gso_size;

    int max_gro_skbs;

    int gso_force_software;

    int gro_policy;

    #define SDTP_GRO_BYPASS          0x1
	#define SDTP_GRO_SAME_CORE       0x2
	#define SDTP_GRO_IDLE            0x4
	#define SDTP_GRO_NEXT            0x8
	#define SDTP_GRO_IDLE_NEW        0x10
	#define SDTP_GRO_FAST_GRANTS     0x20
	#define SDTP_GRO_SHORT_BYPASS    0x40
	#define SDTP_GRO_NORMAL      (SDTP_GRO_SAME_CORE|SDTP_GRO_IDLE_NEW \
			|SDTP_GRO_SHORT_BYPASS)

    int gro_busy_usecs;

    int gro_busy_cycles;

    uint32_t timer_ticks;

    /* spinlock */
    struct mtx metrics_lock;

    char *metrics;

    size_t metrics_capacity;

    size_t metrics_length;

    int metrics_active_opens;

	int flags;

    enum sdtp_freeze_type freeze_type;

    int sync_freeze;

    int bpage_lease_usecs;

	int hardware_state_threshold;

	char hardware_interface[32];

    int bpage_lease_cycles;

    int temp[4];
};

struct sdtp_crypto_info {
    
};

typedef struct uma_zone *sdtp_zone_t;

struct sdtp_base_info {
    struct rwlock sdtp_zone_sock_lock;
    sdtp_zone_t sdtp_zone_sock;

    struct rwlock sdtp_zone_rpc_lock;
    sdtp_zone_t sdtp_zone_rpc;
};

static inline struct sdtp_rpc_bucket *sdtp_client_rpc_bucket(struct sdtp_inpcb *pcb, uint64_t id)
{
    return &pcb->client_rpc_buckets[(id >> 1) & (SDTP_CLIENT_RPC_BUCKETS - 1)];
}

static inline int sdtp_port_hash(uint16_t port)
{
	return port & (SDTP_PCBMAP_BUCKETS - 1);
}

int sdtp_init(struct sdtp *sdtp);
int sdtp_uninit(struct sdtp *sdtp);
void sdtp_interest_init(struct sdtp_interest *interest);

int sdtp_inpcb_alloc(struct socket *so, struct sdtp *sdtp);
struct sdtp_rpc *sdtp_rpc_new_client(struct sdtp_inpcb *pcb, const struct sockaddr_in_union *dest, int *error);

#endif 
