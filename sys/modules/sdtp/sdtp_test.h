/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_TEST_H_
#define _SDTP_TEST_H_

#ifdef SDTP_TEST

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>

#include "sdtp_structs.h"

struct sdtp_test_state {
    struct sysctl_oid *sysctl_tree;

    /*
     * drop_next_rpc_pkt_idx represents the index of the next RPC's
     * dropped packet. By default it has value -1, which means that no
     * packet will be dropped. After dropping once the variable will
     * be reset to -1.
     */
    int drop_next_rpc_pkt_idx_atomic;
};

extern struct sdtp_test_state test_state;

int sdtp_test_state_init(struct sdtp_test_state *state, struct sdtp *sdtp);

#endif

#endif
