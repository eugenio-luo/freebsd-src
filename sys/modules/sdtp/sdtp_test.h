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

#define SDTP_STATIC

#else

#define SDTP_STATIC static

#endif

#endif
