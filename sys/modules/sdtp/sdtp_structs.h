/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _NETINET_SDTP_STRUCTS_H_
#define _NETINET_SDTP_STRUCTS_H_

#include <sys/mutex.h>
#include <sys/queue.h>

struct sdtp_rpc {
	LIST_ENTRY(sdtp_rpc) grantable_links;
	LIST_ENTRY(sdtp_rpc) throttled_links;
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

};

int sdtp_init(struct sdtp *sdtp);
int sdtp_uninit(struct sdtp *sdtp);

#endif 
