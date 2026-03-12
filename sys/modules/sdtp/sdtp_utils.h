/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_UTILS_H_
#define _SDTP_UTILS_H_

#define SDTP_DEFINE_EXPECTED_TYPE(NAME, T) \
    struct sdtp_expected_##NAME { \
        T value; \
        int error; \
    }; \

#define SDTP_UNEXPECTED(EXP_T, ERR) \
    ( EXP_T ) { \
        .error = (ERR), \
    } \

#define SDTP_EXPECTED(EXP_T, V) \
    ( EXP_T ) { \
        .value = (V), .error = 0, \
    } \

#define SDTP_IS_ERROR(EXP_VAL) ((EXP_VAL).error != 0)
#define SDTP_GET_VAL(EXP_VAL) ((EXP_VAL).value)
#define SDTP_GET_ERROR(EXP_VAL) ((EXP_VAL).error)

#endif
