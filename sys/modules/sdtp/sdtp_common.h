/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_COMMON_H_
#define _SDTP_COMMON_H_

#include <sys/queue.h>

#define SDTP_CACHE_LINE_SIZE 64
#define SDTP_CACHE_ROUNDUP(x) ((x) + SDTP_CACHE_LINE_SIZE - 1) & ~(SDTP_CACHE_LINE_SIZE - 1)  

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

#define SDTP_MAX_PRIORITIES 8
#define NUM_PEER_UNACKED_IDS 5

#define SDTP_PEERTAB_BUCKET_BITS 20
#define SDTP_PEERTAB_BUCKETS (1 << SDTP_PEERTAB_BUCKET_BITS)

struct sdtp_rpc;
struct sdtp_interest;
struct sdtp_context;
struct sdtp_packet_tailq_entry;
struct sdtp_packet_slist_entry;
struct sdtp_pcbmap_link;
struct sdtp_peer;
struct sdtp_dead_dst;

TAILQ_HEAD(sdtp_rpc_tailq, sdtp_rpc);
LIST_HEAD(sdtp_rpc_list, sdtp_rpc);

TAILQ_HEAD(sdtp_interest_tailq, sdtp_interest);

LIST_HEAD(sdtp_context_list, sdtp_context);

TAILQ_HEAD(sdtp_packet_tailq, sdtp_packet_tailq_entry);
SLIST_HEAD(sdtp_packet_slist, sdtp_packet_slist_entry);

LIST_HEAD(sdtp_pcbmap_link_list, sdtp_pcbmap_link);

LIST_HEAD(sdtp_peer_list, sdtp_peer);

TAILQ_HEAD(sdtp_dead_dst_tailq, sdtp_dead_dst);

#endif
