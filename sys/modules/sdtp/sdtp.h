/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_H_
#define _SDTP_H_

#include <sys/stdint.h>

#define IPPROTO_SDTP 146
#define SDTP_MAX_MESSAGE_LENGTH 1000000

struct sdtp_msg_args {
    uint64_t id;
    uint64_t completion_cookie;
};

#endif
