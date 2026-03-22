/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#include "sdtp_test.h"

int
sdtp_test_state_init(struct sdtp_test_state *state, struct sdtp *sdtp)
{
    state->sysctl_tree = SYSCTL_ADD_NODE(
        &sdtp->metrics.sysctl_ctx,
        SYSCTL_CHILDREN(sdtp->metrics.sysctl_tree),
        OID_AUTO,
        "test",
        CTLFLAG_RW | CTLFLAG_MPSAFE,
        0,
        "SDTP test state");

    if (state->sysctl_tree == NULL) {
        return ENOMEM;
    }

    atomic_store_int(&state->drop_next_rpc_pkt_idx_atomic, -1);

    SYSCTL_ADD_INT(&sdtp->metrics.sysctl_ctx,
            SYSCTL_CHILDREN(state->sysctl_tree),
            OID_AUTO,
            "drop_next_rpc_pkt_idx",
            CTLFLAG_RW | CTLFLAG_MPSAFE,
            &state->drop_next_rpc_pkt_idx_atomic,
            0,
            "drop_next_rpc_pkt_idx");

    return 0;
}
