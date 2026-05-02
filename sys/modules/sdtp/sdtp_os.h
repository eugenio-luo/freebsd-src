/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_OS_H_
#define _SDTP_OS_H_

#include <vm/uma.h>

#include "sdtp_structs.h"

#define SDTP_ZONE_INIT(zone, name, size, number)                       \
	{                                                              \
		zone = uma_zcreate(name, size, NULL, NULL, NULL, NULL, \
		    UMA_ALIGN_PTR, 0);                                 \
		uma_zone_set_max(zone, number);                        \
	}

#define SDTP_ZONE_DESTROY(zone)	      uma_zdestroy(zone)

#define SDTP_ZONE_GET(zone, type)     (type *)uma_zalloc(zone, M_NOWAIT | M_ZERO);

#define SDTP_ZONE_FREE(zone, element) uma_zfree(zone, element);

#endif
