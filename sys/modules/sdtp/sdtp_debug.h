/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_DEBUG_H_
#define _SDTP_DEBUG_H_

#include <machine/stdarg.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/systm.h>

#include "sdtp_pcb.h"
#include "sdtp_rpc.h"
#include "sdtp.h"

#define SDTP_DEBUG_LOG_LEVEL LOG_INFO

static inline void
sdtp_vdebug(const char *fmt, va_list args)
{
#ifdef SDTP_DEBUG
    vlog(SDTP_DEBUG_LOG_LEVEL, fmt, args);
#endif
}

static inline void
sdtp_debug(const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    va_list args;
    va_start(args, fmt);
    sdtp_vdebug(fmt, args);
    va_end(args);
#endif
}

static inline const char *
rpc_flag_to_string(uint32_t flags)
{
    switch (flags) {
    case RPC_PKTS_READY:        return "PKTS_READY";
    case RPC_COPYING_FROM_USER: return "COPYING_FROM_USER";
    case RPC_COPYING_TO_USER:   return "COPYING_TO_USER";
    case RPC_HANDING_OFF:       return "HANDING_OFF";
    case RPC_DECRYPTING:        return "DECRYPTING";
    case RPC_ACKING_HOMALS:     return "ACKING_HOMALS";
    default:                    return "UNKNOWN";
    }
}

static inline const char *
header_type_to_string(uint8_t type)
{
    switch (type) {
    case SDTP_DATA:     return "DATA";
    case SDTP_GRANT:    return "GRANT";
    case SDTP_RESEND:   return "RESEND";
    case SDTP_UNKNOWN:  return "UNKNOWN";
    case SDTP_BUSY:     return "BUSY";
    case SDTP_CUTOFFS:  return "CUTOFFS";
    case SDTP_FREEZE:   return "FREEZE";
    case SDTP_NEED_ACK: return "NEED_ACK";
    case SDTP_ACK:      return "ACK";
    default:            return "UNKNOWN";
    }
}

#define BUF_SIZE 256

static inline void
sdtp_opt_fmt_print(char *buf, int len, const char *fmt, va_list args)
{
#ifdef SDTP_DEBUG
    if (len < BUF_SIZE) {
        if (fmt) {
            buf[len++] = ':';
            buf[len++] = ' ';

            vsnprintf(buf + len, BUF_SIZE - len, fmt, args);
        }
    }

    sdtp_debug("%s\n", buf);
#endif
}

static inline void
sdtp_rpc_debug(struct sdtp_rpc *rpc, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[BUF_SIZE];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "RPC %lu [ dport: %d, state: %s, error: %d ]",
           rpc->id, rpc->dport,
           rpc_flag_to_string(atomic_load_32(&rpc->flags_atomic)),
           rpc->error);

    va_start(args, fmt);
    sdtp_opt_fmt_print(&buf[0], len, fmt, args);
    va_end(args);
#endif
}

static inline void
sdtp_pcb_debug(struct sdtp_inpcb *pcb, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[BUF_SIZE];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "PCB %#lx [ port: %d ]",
                   (uintptr_t) pcb, pcb->port);

    va_start(args, fmt);
    sdtp_opt_fmt_print(&buf[0], len, fmt, args);
    va_end(args);
#endif
}

static inline void
sdtp_header_debug(struct sdtp_common_header *header, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[BUF_SIZE];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "PKT [sport: %d, dport: %d, type: %s]",
               ntohs(header->sport_be), ntohs(header->dport_be),
               header_type_to_string(header->type));

    va_start(args, fmt);
    sdtp_opt_fmt_print(&buf[0], len, fmt, args);
    va_end(args);
#endif
}

static inline void
sdtp_data_header_debug(struct sdtp_data_header *header, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[BUF_SIZE];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "DATA PKT [sport: %d, dport: %d, len: %d]",
               ntohs(header->common.sport_be), ntohs(header->common.dport_be),
               ntohl(header->message_length_be));

    va_start(args, fmt);
    sdtp_opt_fmt_print(&buf[0], len, fmt, args);
    va_end(args);
#endif
}

#define MBUF_LEN_ASSERT(M, HEADER_TYPE) \
    do { \
        KASSERT((M)->m_len >= (int32_t)sizeof(HEADER_TYPE), \
                ("mbuf " #M " (m_len %d) should be at least size of " #HEADER_TYPE " (size: %zu)", \
                (M)->m_len, sizeof(HEADER_TYPE))); \
    } while (0)

#define MBUF_LEN_AT_LEAST(M, SIZE) \
    do { \
        KASSERT((M)->m_len >= (int32_t)SIZE, \
                ("mbuf " #M " (m_len %d) should be at least size of " #SIZE " (size: %zu)", \
                (M)->m_len, SIZE)); \
    } while (0)

#define VALID_PCB_ASSERT(PCB) \
    do { \
        KASSERT(PCB != NULL, ("pcb " #PCB " should be valid")); \
        KASSERT((PCB)->sdtp != NULL, ("pcb " #PCB " should contain valid sdtp")); \
    } while (0)

#define VALID_RPC_ASSERT(RPC) \
    do { \
        KASSERT(RPC != NULL, ("rpc " #RPC " should be valid")); \
    } while (0)

#define RPC_LOCK_OWNED(RPC) \
    do { \
        mtx_assert((RPC)->spinlock_p, MA_OWNED); \
    } while (0)

#define RPC_LOCK_NOTOWNED(RPC) \
    do { \
        mtx_assert((RPC)->spinlock_p, MA_NOTOWNED); \
    } while (0)

#define INTEREST_NOT_LINKED(INTEREST) \
    do { \
        KASSERT(atomic_load_int(&(INTEREST)->is_response_atomic) == false \
                && atomic_load_int(&(INTEREST)->is_request_atomic) == false, \
            ("interest " #INTEREST " should not be on any list")); \
    } while (0)

#endif
