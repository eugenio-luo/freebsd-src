/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2024 The FreeBSD Foundation
 *
 * This software was developed by Eugenio Luo <>
 * under sponsorship from the FreeBSD Foundation.
 */

#ifndef _SDTP_QUEUE_H_
#define _SDTP_QUEUE_H_

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/queue.h>

#include "sdtp_common.h"

/*
 * I make some assumptions here: the list or queue never change address,
 * if this happens, then the entry would be pointing to an invalid address;
 * Only one thread access the entry at a time, but the queue or the list can be
 * accessed by multiple threads.
 */

/*
 *  Thread-safe queue
 */

#define SDTP_QUEUE(NAME, TYPE)        \
	struct NAME {                 \
		struct mtx spinlock;  \
		TAILQ_HEAD(, TYPE) q; \
	}

#define SDTP_QUEUE_ENTRY(QUEUE_HEAD_TYPE, TYPE) \
	struct {                                \
		TAILQ_ENTRY(TYPE) entry;        \
		QUEUE_HEAD_TYPE *owner;         \
	}

#define SDTP_QUEUE_LOCK(Q)                       \
	do {                                     \
		mtx_lock_spin(&((Q)->spinlock)); \
	} while (0)

#define SDTP_QUEUE_UNLOCK(Q)                       \
	do {                                       \
		mtx_unlock_spin(&((Q)->spinlock)); \
	} while (0)

#define SDTP_QUEUE_OWNED(Q)                             \
	do {                                            \
		mtx_assert(&((Q)->spinlock), MA_OWNED); \
	} while (0)

#define SDTP_QUEUE_INIT(Q)                                             \
	do {                                                           \
		mtx_init(&((Q)->spinlock), #Q " queue spinlock", NULL, \
		    MTX_SPIN);                                         \
		TAILQ_INIT(&((Q)->q));                                 \
	} while (0)

#define SDTP_QUEUE_ENTRY_INIT(ELEM)   \
	do {                          \
		(ELEM)->owner = NULL; \
	} while (0)

#define SDTP_QUEUE_INSERT_TAIL_LOCKED(Q, ELEM, LINK)            \
	do {                                                    \
		SDTP_QUEUE_OWNED(Q);                            \
		MPASS((ELEM)->LINK.owner == NULL);              \
		TAILQ_INSERT_TAIL(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = Q;                         \
	} while (0)

#define SDTP_QUEUE_INSERT_TAIL(Q, ELEM, LINK)                   \
	do {                                                    \
		SDTP_QUEUE_LOCK(Q);                             \
		MPASS((ELEM)->LINK.owner == NULL);              \
		TAILQ_INSERT_TAIL(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = Q;                         \
		SDTP_QUEUE_UNLOCK(Q);                           \
	} while (0)

#define SDTP_QUEUE_FOREACH_LOCKED(VAR, Q, LINK) \
	SDTP_QUEUE_OWNED(Q);                    \
	TAILQ_FOREACH(VAR, &((Q)->q), LINK.entry)

#define SDTP_QUEUE_FOREACH_SAFE_LOCKED(VAR, Q, LINK, TEMP_VAR) \
	SDTP_LIST_OWNED(Q);                                    \
	TAILQ_FOREACH_SAFE(VAR, &((Q)->q), LINK.entry, TEMP_VAR)

#define SDTP_QUEUE_REMOVE(Q, ELEM, LINK)                   \
	do {                                               \
		SDTP_QUEUE_LOCK(Q);                        \
		MPASS((ELEM)->LINK.owner != NULL);         \
		MPASS((ELEM)->LINK.owner == (Q));          \
		TAILQ_REMOVE(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = NULL;                 \
		SDTP_QUEUE_UNLOCK(Q);                      \
	} while (0)

#define SDTP_QUEUE_REMOVE_LOCKED(Q, ELEM, LINK)            \
	do {                                               \
		SDTP_QUEUE_OWNED(Q);                       \
		MPASS((ELEM)->LINK.owner != NULL);         \
		MPASS((ELEM)->LINK.owner == (Q));          \
		TAILQ_REMOVE(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = NULL;                 \
	} while (0)

#define SDTP_QUEUE_EMPTY_LOCKED(Q)      \
	({                              \
		SDTP_QUEUE_OWNED(Q);    \
		TAILQ_EMPTY(&((Q)->q)); \
	})

#define SDTP_QUEUE_EMPTY(Q)                           \
	({                                            \
		SDTP_QUEUE_LOCK(Q);                   \
		bool retval = TAILQ_EMPTY(&((Q)->q)); \
		SDTP_QUEUE_UNLOCK(Q);                 \
		retval;                               \
	})

#define SDTP_QUEUE_FIRST(Q, TYPE)                             \
	({                                                    \
		SDTP_QUEUE_LOCK(Q);                           \
		struct TYPE *retval = TAILQ_FIRST(&((Q)->q)); \
		SDTP_QUEUE_UNLOCK(Q);                         \
		retval;                                       \
	})

// TODO: is this safe?
#define SDTP_QUEUE_LOCK_IF_LINKED(ELEM, LINK)                \
	({                                                   \
		bool linked = (ELEM)->LINK.owner != NULL;    \
		if (linked) {                                \
			SDTP_QUEUE_LOCK((ELEM)->LINK.owner); \
		}                                            \
		linked;                                      \
	})

#define SDTP_QUEUE_LINKED(ELEM, LINK) ((ELEM)->LINK.owner != NULL)

#define SDTP_QUEUE_FREE(Q)                     \
	do {                                   \
		mtx_destroy(&((Q)->spinlock)); \
	} while (0)

/*
 *  Thread-safe list
 */
#define SDTP_LIST(NAME, TYPE)        \
	struct NAME {                \
		struct mtx spinlock; \
		LIST_HEAD(, TYPE) q; \
	}

#define SDTP_LIST_ENTRY(LIST_HEAD_TYPE, TYPE) \
	struct {                              \
		LIST_ENTRY(TYPE) entry;       \
		LIST_HEAD_TYPE *owner;        \
	}

#define SDTP_LIST_LOCK(Q)                        \
	do {                                     \
		mtx_lock_spin(&((Q)->spinlock)); \
	} while (0)

#define SDTP_LIST_UNLOCK(Q)                        \
	do {                                       \
		mtx_unlock_spin(&((Q)->spinlock)); \
	} while (0)

#define SDTP_LIST_OWNED(Q)                              \
	do {                                            \
		mtx_assert(&((Q)->spinlock), MA_OWNED); \
	} while (0)

#define SDTP_LIST_INIT(Q)                                             \
	do {                                                          \
		mtx_init(&((Q)->spinlock), #Q " list spinlock", NULL, \
		    MTX_SPIN);                                        \
		LIST_INIT(&((Q)->q));                                 \
	} while (0)

#define SDTP_LIST_ENTRY_INIT(ELEM)    \
	do {                          \
		(ELEM)->owner = NULL; \
	} while (0)

#define SDTP_LIST_INSERT_HEAD_LOCKED(Q, ELEM, LINK)            \
	do {                                                   \
		SDTP_LIST_OWNED(Q);                            \
		MPASS((ELEM)->LINK.owner == NULL);             \
		LIST_INSERT_HEAD(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = Q;                        \
	} while (0)

#define SDTP_LIST_INSERT_HEAD(Q, ELEM, LINK)                   \
	do {                                                   \
		SDTP_LIST_LOCK(Q);                             \
		MPASS((ELEM)->LINK.owner == NULL);             \
		LIST_INSERT_HEAD(&((Q)->q), ELEM, LINK.entry); \
		(ELEM)->LINK.owner = Q;                        \
		SDTP_LIST_UNLOCK(Q);                           \
	} while (0)

#define SDTP_LIST_FOREACH_LOCKED(VAR, Q, LINK) \
	SDTP_LIST_OWNED(Q);                    \
	LIST_FOREACH(VAR, &((Q)->q), LINK.entry)

#define SDTP_LIST_FOREACH_SAFE_LOCKED(VAR, Q, LINK, TEMP_VAR) \
	SDTP_LIST_OWNED(Q);                                   \
	LIST_FOREACH_SAFE(VAR, &((Q)->q), LINK.entry, TEMP_VAR)

#define SDTP_LIST_REMOVE(ELEM, LINK)                  \
	do {                                          \
		MPASS((ELEM)->LINK.owner != NULL);    \
		SDTP_LIST_LOCK((ELEM)->LINK.owner);   \
		LIST_REMOVE(ELEM, LINK.entry);        \
		SDTP_LIST_UNLOCK((ELEM)->LINK.owner); \
		(ELEM)->LINK.owner = NULL;            \
	} while (0)

/* Only use this if you own the head of the list */
#define SDTP_LIST_REMOVE_LOCKED(ELEM, LINK)          \
	do {                                         \
		SDTP_LIST_OWNED((ELEM)->LINK.owner); \
		MPASS((ELEM)->LINK.owner != NULL);   \
		LIST_REMOVE(ELEM, LINK.entry);       \
		(ELEM)->LINK.owner = NULL;           \
	} while (0)

#define SDTP_LIST_REMOVE_LOCKED_THEN_UNLOCK(ELEM, LINK) \
	do {                                            \
		SDTP_LIST_OWNED((ELEM)->LINK.owner);    \
		MPASS((ELEM)->LINK.owner != NULL);      \
		LIST_REMOVE(ELEM, LINK.entry);          \
		SDTP_LIST_UNLOCK((ELEM)->LINK.owner);   \
		(ELEM)->LINK.owner = NULL;              \
	} while (0)

#define SDTP_LIST_EMPTY(Q)                           \
	({                                           \
		SDTP_LIST_LOCK(Q);                   \
		bool retval = LIST_EMPTY(&((Q)->q)); \
		SDTP_LIST_UNLOCK(Q);                 \
		retval;                              \
	})

#define SDTP_LIST_FIRST(Q, TYPE)                             \
	({                                                   \
		SDTP_LIST_LOCK(Q);                           \
		struct TYPE *retval = LIST_FIRST(&((Q)->q)); \
		SDTP_LIST_UNLOCK(Q);                         \
		retval;                                      \
	})

#define SDTP_LIST_LOCK_IF_LINKED(ELEM, LINK)                \
	({                                                  \
		bool linked = (ELEM)->LINK.owner != NULL;   \
		if (linked) {                               \
			SDTP_LIST_LOCK((ELEM)->LINK.owner); \
		}                                           \
		linked;                                     \
	})

#define SDTP_LIST_FREE(Q)                     \
	do {                                   \
		mtx_destroy(&((Q)->spinlock)); \
	} while (0)

#define SDTP_LIST_LINKED(ELEM, LINK) ((ELEM)->LINK.owner != NULL)

struct sdtp_pcbmap_link;
struct sdtp_rpc;
struct sdtp_interest;

SDTP_QUEUE(sdtp_rpc_mqueue, sdtp_rpc);
SDTP_QUEUE(sdtp_interest_mqueue, sdtp_interest);

SDTP_LIST(sdtp_rpc_mlist, sdtp_rpc);
SDTP_LIST(sdtp_pcbmap_link_mlist, sdtp_pcbmap_link);

#endif
