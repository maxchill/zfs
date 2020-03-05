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
 * Copyright (c) 2018, Intel Corporation.
 */

#ifndef	_SYS_VDEV_SCAN_H
#define	_SYS_VDEV_SCAN_H

#include <sys/spa.h>

#ifdef	__cplusplus
extern "C" {
#endif

boolean_t vdev_scan_rebuilding(vdev_t *);
boolean_t vdev_scan_suspended(vdev_t *);
void vdev_scan_rebuild(vdev_t *, vdev_t *, boolean_t);
void vdev_scan_set_rate(vdev_t *, uint64_t);
void vdev_scan_restart(vdev_t *, boolean_t);
void vdev_scan_stop_wait(vdev_t *, vdev_scan_state_t);
int vdev_scan_get_stats(vdev_t *, vdev_rebuild_stat_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_VDEV_SCAN_H */
