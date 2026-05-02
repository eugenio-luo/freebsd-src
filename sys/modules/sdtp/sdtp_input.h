/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_INPUT_H_
#define _SDTP_INPUT_H_

#include <sys/mbuf.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <netinet6/ip6_var.h>

int sdtp_input(struct mbuf **mp, int *offp, int proto);
void sdtp_ctlinput(struct icmp *icmp);

int sdtp6_input(struct mbuf **mp, int *offp, int proto);
void sdtp6_ctlinput(struct ip6ctlparam *ip6cp);

#endif
