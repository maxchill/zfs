/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 */

#ifndef _SYS_ZFS_DEBUG_H
#define	_SYS_ZFS_DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/time.h>

#ifndef TRUE
#define	TRUE 1
#endif

#ifndef FALSE
#define	FALSE 0
#endif

extern int zfs_flags;
extern int zfs_recover;
extern int zfs_free_leak_on_eio;

#define	ZFS_DEBUG_DPRINTF		(1 << 0)
#define	ZFS_DEBUG_DBUF_VERIFY		(1 << 1)
#define	ZFS_DEBUG_DNODE_VERIFY		(1 << 2)
#define	ZFS_DEBUG_SNAPNAMES		(1 << 3)
#define	ZFS_DEBUG_MODIFY		(1 << 4)
#define	ZFS_DEBUG_SPA			(1 << 5)
#define	ZFS_DEBUG_ZIO_FREE		(1 << 6)
#define	ZFS_DEBUG_HISTOGRAM_VERIFY	(1 << 7)
#define	ZFS_DEBUG_METASLAB_VERIFY	(1 << 8)
#define	ZFS_DEBUG_SET_ERROR		(1 << 9)
#define	ZFS_DEBUG_ARC_WATCH		(1 << 10)

#define	ZFS_DEBUG_MASK \
	(ZFS_DEBUG_DPRINTF | ZFS_DEBUG_DBUF_VERIFY | ZFS_DEBUG_DNODE_VERIFY | \
	ZFS_DEBUG_SNAPNAMES | ZFS_DEBUG_MODIFY | ZFS_DEBUG_SPA | \
	ZFS_DEBUG_ZIO_FREE | ZFS_DEBUG_HISTOGRAM_VERIFY | \
	ZFS_DEBUG_METASLAB_VERIFY | ZFS_DEBUG_SET_ERROR)

#define	DPRINTF_TIME			(1 << 0)
#define	DPRINTF_PID			(1 << 1)
#define	DPRINTF_CPU			(1 << 2)
#define	DPRINTF_FFL			(1 << 3)

#define	DPRINTF_MASK \
	(DPRINTF_TIME | DPRINTF_PID | DPRINTF_CPU | DPRINTF_FFL)

extern void __dprintf(const char *file, const char *func,
    int line, const char *fmt, ...);
#define	dprintf(...) \
	if (zfs_flags & (ZFS_DEBUG_DPRINTF | ZFS_DEBUG_SET_ERROR)) \
		__dprintf(__FILE__, __func__, __LINE__, __VA_ARGS__)

extern void zfs_panic_recover(const char *fmt, ...);

typedef struct zfs_dbgmsg {
	list_node_t zdm_node;
	uint64_t zdm_timestamp;
	uint32_t zdm_size;
	uint32_t zdm_cpu;
	pid_t zdm_pid;
	pid_t zdm_tid;
	char *zdm_ffl;
	char *zdm_msg;
} zfs_dbgmsg_t;

extern void zfs_dbgmsg_init(void);
extern void zfs_dbgmsg_fini(void);
extern void zfs_dbgmsg(const char *fmt, ...);
extern void zfs_dbgmsg_print(const char *tag);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFS_DEBUG_H */
