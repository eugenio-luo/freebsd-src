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

#include "sdtp_pcb.h"
#include "sdtp_rpc.h"
#include "sdtp.h"

static inline void
sdtp_vdebug(int pri, const char *fmt, va_list args)
{
#ifdef SDTP_DEBUG
    vlog(pri, fmt, args);
#endif
}

static inline void
sdtp_debug(int pri, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    va_list args;
    va_start(args, fmt);
    sdtp_vdebug(pri, fmt, args);
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

static inline void
sdtp_rpc_debug(struct sdtp_rpc *rpc, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[256];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "RPC %lu [ dport %d, state %s, error %d ]",
           rpc->id, rpc->dport,
           rpc_flag_to_string(atomic_load_32(&rpc->flags_atomic)),
           rpc->error);

    if (fmt && len < sizeof(buf)) {
        buf[len++] = ':';
        buf[len++] = ' ';

        va_start(args, fmt);
        vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
        va_end(args);
    }

    sdtp_debug(LOG_INFO, "%s", buf);
#endif
}

static inline void
sdtp_pcb_debug(struct sdtp_inpcb *pcb, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[256];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "PCB %#lx [ port %d ]",
                   (uintptr_t) pcb, pcb->port);

    if (fmt && len < sizeof(buf)) {
        buf[len++] = ':';
        buf[len++] = ' ';

        va_start(args, fmt);
        vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
        va_end(args);
    }

    sdtp_debug(LOG_INFO, "%s", buf);
#endif
}

static inline void
sdtp_header_debug(struct sdtp_common_header *header, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[256];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "PKT [sport: %d, dport: %d, type: %s]",
               ntohs(header->sport_be), ntohs(header->dport_be),
               header_type_to_string(header->type));

    if (fmt && len < sizeof(buf)) {
        buf[len++] = ':';
        buf[len++] = ' ';

        va_start(args, fmt);
        vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
        va_end(args);
    }

    sdtp_debug(LOG_INFO, "%s", buf);
#endif
}

static inline void
sdtp_data_header_debug(struct sdtp_data_header *header, const char *fmt, ...)
{
#ifdef SDTP_DEBUG
    char buf[256];
    va_list args;
    int len;

    len = snprintf(buf, sizeof(buf), "DATA PKT [sport: %d, dport: %d, len: %d]",
               ntohs(header->common.sport_be), ntohs(header->common.dport_be),
               ntohl(header->message_length_be));

    if (fmt && len < sizeof(buf)) {
        buf[len++] = ':';
        buf[len++] = ' ';

        va_start(args, fmt);
        vsnprintf(buf + len, sizeof(buf) - len, fmt, args);
        va_end(args);
    }

    sdtp_debug(LOG_INFO, "%s", buf);
#endif
}

#endif
