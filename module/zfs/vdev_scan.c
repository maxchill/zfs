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
 *
 * Copyright (c) 2018, Intel Corporation.
 * Copyright (c) 2020 by Lawrence Livermore National Security, LLC.
 */

#include <sys/vdev_impl.h>
#include <sys/vdev_draid_impl.h>
#include <sys/spa_impl.h>
#include <sys/metaslab_impl.h>
#include <sys/dsl_scan.h>
#include <sys/vdev_scan.h>
#include <sys/zio.h>
#include <sys/dmu_tx.h>
#include <sys/arc.h>
#include <sys/zap.h>

/*
 * XXX - Explain scanning rebuild feature.
 */


/*
 * Maximum size of scan I/Os.  Individual I/Os may be smaller due to the
 * maxmimum pool block size and additional alignment restrictions.
 */
unsigned int zfs_scan_extent_bytes_max = SPA_MAXBLOCKSIZE;

/*
 * Maximum number of queued scan I/Os top-level vdev.  The number of
 * concurrent scan I/Os issued to the device is controlled by the
 * zfs_vdev_scrub_min_active and zfs_vdev_scrub_max_active module options.
 */
unsigned int zfs_scan_queue_limit = 20;

/*
 * The scan_args are a control structure which describe how a top-level vdev
 * should be rebuilt.  The core elements are the vdev, the metaslab being
 * rebuilt and a range tree containing the allocted extents.  All provided
 * ranges must be within the metaslab.
 */
typedef struct scan_args {
	vdev_t		*scan_vdev;		/* Top-level vdev to rebuild */
	metaslab_t	*scan_msp;		/* Disabled metaslab */
	range_tree_t	*scan_tree;		/* Scan ranges (in metaslab) */
	uint64_t	scan_extent_bytes_max;	/* Maximum rebuild I/O size */

	/*
	 * These fields are updated by vdev_scan_ranges().
	 */
	hrtime_t	scan_start_time;	/* Start time */
	uint64_t	scan_bytes_done;	/* Bytes rebuilt */
	vdev_t		*scan_fault_vdevs[3];	/* Faulted vdevs */
	uint64_t	scan_faults;		/* Total faulted vdevs */
} scan_args_t;

/*
 * Determines whether a vdev_scan_thread() should be stopped.
 */
static boolean_t
vdev_scan_should_stop(vdev_t *tvd)
{
	return (tvd->vdev_scan_exit_wanted || !vdev_writeable(tvd) ||
	    tvd->vdev_top->vdev_removing);
}

static void
vdev_scan_set_guid_impl(uint64_t *guid_array, uint64_t guid, int idx)
{
	ASSERT(idx >= -2 && idx <= 2);

	if (idx == -1) {
		/* Set all values to fault guid */
		for (int i = 0; i <= 2; i++)
			guid_array[i] = guid;

	} else if (idx == -2) {
		/* Set next zero value to fault guid */
		for (int i = 0; i <= 2; i++) {
			if (guid_array[i] == 0)
				guid_array[i] = guid;
		}
	} else {
		/* Set specified index to fault guid */
		guid_array[idx] = guid;
	}
}

static void
vdev_scan_set_fault_guid(vdev_t *vd, uint64_t guid, int idx)
{
	vdev_scan_set_guid_impl(vd->vdev_scan_fault_guids, guid, idx);
}

static void
vdev_scan_set_defer_guid(vdev_t *vd, uint64_t guid, int idx)
{
	vdev_scan_set_guid_impl(vd->vdev_scan_defer_guids, guid, idx);
}

/*
 * The sync task for updating the on-disk state of a scan.  This is scheduled
 * by vdev_scan_change_state() and vdev_scan_range().
 */
static void
vdev_scan_zap_update_sync(void *arg, dmu_tx_t *tx)
{
	uint64_t txg = dmu_tx_get_txg(tx);
	vdev_t *vd = arg;

	if (vd == NULL || vd->vdev_removing)
		return;

	uint64_t last_offset = vd->vdev_scan_offset[txg & TXG_MASK];
	vd->vdev_scan_offset[txg & TXG_MASK] = 0;

	VERIFY(vd->vdev_top == vd);

	spa_t *spa = vd->vdev_spa;
	objset_t *mos = spa->spa_meta_objset;

	if (last_offset > 0 || vd->vdev_scan_last_offset == UINT64_MAX) {

		if (vd->vdev_scan_last_offset == UINT64_MAX)
			last_offset = 0;

		vd->vdev_scan_last_offset = last_offset;
		VERIFY0(zap_update(mos, vd->vdev_top_zap,
		    VDEV_TOP_ZAP_SCAN_LAST_OFFSET,
		    sizeof (last_offset), 1, &last_offset, tx));
	}

	if (vd->vdev_scan_rate > 0) {
		uint64_t rate = (uint64_t)vd->vdev_scan_rate;

		if (rate == UINT64_MAX)
			rate = 0;

		VERIFY0(zap_update(mos, vd->vdev_top_zap,
		    VDEV_TOP_ZAP_SCAN_RATE, sizeof (rate), 1, &rate, tx));
	}

	VERIFY0(zap_update(mos, vd->vdev_top_zap,
	    VDEV_TOP_ZAP_SCAN_FAULT_GUIDS, sizeof (uint64_t), 3,
	    vd->vdev_scan_fault_guids, tx));

	VERIFY0(zap_update(mos, vd->vdev_top_zap,
	    VDEV_TOP_ZAP_SCAN_DEFER_GUIDS, sizeof (uint64_t), 3,
	    vd->vdev_scan_defer_guids, tx));

	VERIFY0(zap_update(mos, vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_START_TIME,
	    sizeof (uint64_t), 1, &vd->vdev_scan_start_time, tx));

	VERIFY0(zap_update(mos, vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_END_TIME,
	    sizeof (uint64_t), 1, &vd->vdev_scan_end_time, tx));

	VERIFY0(zap_update(mos, vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_ACTION_TIME,
	    sizeof (uint64_t), 1, &vd->vdev_scan_action_time, tx));

	VERIFY0(zap_update(mos, vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_STATE,
	    sizeof (uint64_t), 1, &vd->vdev_scan_state, tx));
}

/*
 * Update the on-disk state of a scan.  This is called to request that a scan
 * be started/suspended/canceled, or to change one of the scan options (rate).
 */
static void
vdev_scan_change_state(vdev_t *vd, vdev_scan_state_t new_state,
    uint64_t rate, vdev_t *fault_vdev, boolean_t defer)
{
	ASSERT(MUTEX_HELD(&vd->vdev_scan_lock));
	ASSERT(vd->vdev_top == vd);
	spa_t *spa = vd->vdev_spa;

	/*
	 * Update the last action time when changing state.
	 */
	if (new_state != vd->vdev_scan_state)
		vd->vdev_scan_action_time = gethrestime_sec();

	/*
	 * If we're activating, then preserve the requested rate and scan
	 * method.  Setting the last offset and rate to UINT64_MAX is used
	 * as a sentinel to indicate they should be reset to default values.
	 */
	if (new_state == VDEV_SCAN_ACTIVE) {
		if (vd->vdev_scan_state == VDEV_SCAN_NONE ||
		    vd->vdev_scan_state == VDEV_SCAN_COMPLETE ||
		    vd->vdev_scan_state == VDEV_SCAN_CANCELED) {
			vd->vdev_scan_last_offset = UINT64_MAX;
			vd->vdev_scan_rate = UINT64_MAX;
			vd->vdev_scan_start_time = gethrestime_sec();
			vd->vdev_scan_end_time = 0;
			vd->vdev_scan_action_time = vd->vdev_scan_start_time;
			vdev_scan_set_fault_guid(vd, 0, -1);
			vdev_scan_set_defer_guid(vd, 0, -1);
		}

		if (rate != 0)
			vd->vdev_scan_rate = rate;

		if (fault_vdev != NULL) {
			uint64_t guid = fault_vdev->vdev_guid;

			ASSERT(fault_vdev->vdev_ops->vdev_op_leaf);
			ASSERT(vd == fault_vdev->vdev_top);
			ASSERT(vdev_is_concrete(fault_vdev));

			if (defer) {
				vdev_scan_set_defer_guid(vd, guid, -2);
			} else {
				/*
				 * When adding a new faulted guid the scan
				 * must be restarted in order to rebuild
				 * skipped dRAID permutation groups.
				 */
				vd->vdev_scan_last_offset = UINT64_MAX;
				vdev_scan_set_fault_guid(vd, guid, -2);
			}
		}
	} else if (new_state == VDEV_SCAN_COMPLETE ||
	    new_state == VDEV_SCAN_CANCELED) {
		vd->vdev_scan_end_time = gethrestime_sec();
	}

	boolean_t resumed = !!(vd->vdev_scan_state == VDEV_SCAN_SUSPENDED);
	vd->vdev_scan_state = new_state;

	dmu_tx_t *tx = dmu_tx_create_dd(spa_get_dsl(spa)->dp_mos_dir);
	VERIFY0(dmu_tx_assign(tx, TXG_WAIT));
	dsl_sync_task_nowait(spa_get_dsl(spa), vdev_scan_zap_update_sync,
	    vd, 2, ZFS_SPACE_CHECK_NONE, tx);

	switch (new_state) {
	case VDEV_SCAN_ACTIVE:
		spa_event_notify(spa, vd, NULL,
		    resumed ? ESC_ZFS_SCAN_RESUME : ESC_ZFS_SCAN_START);
		spa_history_log_internal(spa, "scan", tx,
		    "vdev=%s activated", vd->vdev_path);
		break;
	case VDEV_SCAN_SUSPENDED:
		spa_event_notify(spa, vd, NULL, ESC_ZFS_SCAN_SUSPEND);
		spa_history_log_internal(spa, "scan", tx,
		    "vdev=%s suspended", vd->vdev_path);
		break;
	case VDEV_SCAN_CANCELED:
		spa_event_notify(spa, vd, NULL, ESC_ZFS_SCAN_CANCEL);
		spa_history_log_internal(spa, "scan", tx,
		    "vdev=%s canceled", vd->vdev_path);
		break;
	case VDEV_SCAN_COMPLETE:
		spa_event_notify(spa, vd, NULL, ESC_ZFS_SCAN_FINISH);
		spa_history_log_internal(spa, "scan", tx,
		    "vdev=%s complete", vd->vdev_path);
		break;
	default:
		panic("invalid state %llu", (unsigned long long)new_state);
	}

	dmu_tx_commit(tx);

	if (new_state != VDEV_SCAN_ACTIVE)
		spa_notify_waiters(spa);
}

/*
 * The zio_done_func_t done callback for each scan I/O issued.  It is
 * responsible for updating the scan I/O stats and limiting the number
 * of in flight scan I/Os.
 */
static void
vdev_scan_done(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;

	mutex_enter(&vd->vdev_scan_io_lock);
	if (zio->io_error == ENXIO && !vdev_writeable(vd)) {
		/*
		 * The I/O failed because the top-level vdev was unavailable.
		 * Attempt to roll back to the last completed offset, in order
		 * resume from the correct location if the pool is resumed.
		 * (This works because spa_sync waits on spa_txg_zio before
		 * it runs sync tasks.)
		 */
		uint64_t *off =
		    &vd->vdev_scan_offset[zio->io_txg & TXG_MASK];
		*off = MIN(*off, zio->io_offset);
	} else if (zio->io_error) {
		vd->vdev_scan_errors++;
	}

	abd_free(zio->io_abd);
	vd->vdev_scan_bytes_done += zio->io_orig_size;

	ASSERT3U(vd->vdev_scan_inflight, >, 0);
	vd->vdev_scan_inflight--;
	cv_broadcast(&vd->vdev_scan_io_cv);
	mutex_exit(&vd->vdev_scan_io_lock);

	spa_config_exit(vd->vdev_spa, SCL_STATE_ALL, vd);
}

/*
 * Rebuild the data in this range by constructing a special dummy block
 * pointer for the given range.  It has no relation to any existing blocks
 * in the pool.  But by disabling checksum verification and issuing a scrub
 * I/O, parity can be rebuilt for fixed-width dRAID vdevs.  Mirrored vdevs
 * will replicate the block using any available mirror leaf vdevs.
 *
 * XXX - Discuss mirror rebuilds.  They're potentially more dangerous than
 * dRAID rebuild because you could read a bad-copy from a mirror-leaf and
 * overwrite a good mirror leaf.  This is less likely with dRAID since
 * you're reconstructing from parity.
 */
static void
vdev_scan_rebuild_block(scan_args_t *sa, uint64_t start, uint64_t asize,
    uint64_t txg)
{
	vdev_t *vd = sa->scan_vdev;
	spa_t *spa = vd->vdev_spa;
	uint64_t psize = asize;

	ASSERT(vd->vdev_ops == &vdev_draid_ops ||
	    vd->vdev_ops == &vdev_mirror_ops);

	/* Calculate psize from asize */
	if (vd->vdev_ops == &vdev_draid_ops)
		psize = vdev_draid_asize2psize(vd, asize, start);

	blkptr_t blk, *bp = &blk;
	BP_ZERO(bp);

	DVA_SET_VDEV(&bp->blk_dva[0], vd->vdev_id);
	DVA_SET_OFFSET(&bp->blk_dva[0], start);
	DVA_SET_GANG(&bp->blk_dva[0], 0);
	DVA_SET_ASIZE(&bp->blk_dva[0], asize);

	BP_SET_BIRTH(bp, TXG_INITIAL, TXG_INITIAL);
	BP_SET_LSIZE(bp, psize);
	BP_SET_PSIZE(bp, psize);
	BP_SET_COMPRESS(bp, ZIO_COMPRESS_OFF);
	BP_SET_CHECKSUM(bp, ZIO_CHECKSUM_OFF);
	BP_SET_TYPE(bp, DMU_OT_NONE);
	BP_SET_LEVEL(bp, 0);
	BP_SET_DEDUP(bp, 0);
	BP_SET_BYTEORDER(bp, ZFS_HOST_BYTEORDER);

	zio_nowait(zio_read(spa->spa_txg_zio[txg & TXG_MASK], spa, bp,
	    abd_alloc(psize, B_FALSE), psize, vdev_scan_done, sa,
	    ZIO_PRIORITY_SCAN, ZIO_FLAG_RAW | ZIO_FLAG_CANFAIL |
	    ZIO_FLAG_RESILVER, NULL));
}

/*
 * Returns the number of currently faulted devices in the top-level vdev.
 * This includes the spare vdev we're actively rebuilding to, but which is
 * not in a faulted state.
 *
 * XXX - Return the number of vdev guids we're actively rebuilding.  This
 * may be larger than one if rebuilding multiple, or fewer than the whole
 * list if some are deffered.
 */
static int
vdev_scan_faults(vdev_t *tvd)
{
	int faulted = 1;

	for (int c = 0; c < tvd->vdev_children; c++) {
		vdev_t *child = tvd->vdev_child[c];

		if (!vdev_readable(child) ||
		    (!vdev_writeable(child) && spa_writeable(tvd->vdev_spa)))
			faulted++;
	}

	return (faulted);
}

/*
 * Returns the average scan rate in bytes/sec for the metaslab.  This is
 * allows for a reasonably accurate current scan rate to be calcualted.
 * Only issued scan I/O are considered, skipped ranged are ignored.
 */
static uint64_t
vdev_scan_calculate_rate(scan_args_t *sa)
{
	return (sa->scan_bytes_done * 1000 /
	    (NSEC2MSEC(gethrtime() - sa->scan_start_time) + 1));
}

/*
 * Determine if the range is degraded and needs to be rebuilt given the
 * list of faulted child vdevs.  When no list can be provided then all
 * dRAID groups must be rebuilt.
 */
static boolean_t
vdev_scan_draid_group_degraded(scan_args_t *sa, uint64_t start, uint64_t size)
{
	ASSERT(sa->scan_vdev->vdev_ops == &vdev_draid_ops);
	ASSERT3U(sa->scan_faults, <=, 3);

	if (sa->scan_faults == 0)
		return (B_TRUE);

	for (int i = 0; i < sa->scan_faults; i++) {
		if (vdev_draid_group_degraded(sa->scan_vdev,
		    sa->scan_fault_vdevs[i], start, size, B_FALSE)) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Issues a scrub I/O and takes care of rate limiting (bytes/sec) and number
 * of concurrent scrub I/Os.  The provided start and size must by properly
 * aligned for the top-level vdev type being rebuilt.
 */
static int
vdev_scan_range(scan_args_t *sa, uint64_t start, uint64_t size)
{
	uint64_t ms_id __maybe_unused = sa->scan_msp->ms_id;
	vdev_t *vd = sa->scan_vdev;
	spa_t *spa = vd->vdev_spa;

	ASSERT(vd->vdev_ops == &vdev_draid_ops ||
	    vd->vdev_ops == &vdev_mirror_ops);
	ASSERT3U(ms_id, ==, start >> vd->vdev_ms_shift);
	ASSERT3U(ms_id, ==, (start + size - 1) >> vd->vdev_ms_shift);

	/* Mirror dRAID rebuild unsupported */
	IMPLY(vd->vdev_ops == &vdev_draid_ops,
	    !vdev_draid_ms_mirrored(vd, ms_id));

	/*
	 * There's no need to issue a scrub I/O for this range because
	 * it does not overlap with the degraded dRAID group.
	 */
	if (vd->vdev_ops == &vdev_draid_ops &&
	    !vdev_scan_draid_group_degraded(sa, start, size)) {
		vd->vdev_scan_bytes_done += size;
		return (0);
	}

	mutex_enter(&vd->vdev_scan_io_lock);

	/*
	 * Limit scan I/Os to the requested rate, when the vd->vdev_scan_rate
	 * is set to zero no rate limiting is applied.
	 *
	 * XXX - Consider optionally rate limiting when there are other more
	 * critical IOs in the queues.  A helper function could be added to
	 * vdev_queue.c for this if the normal priority scheme is insufficient.
	 */
	while (vd->vdev_scan_rate != 0 && !vdev_scan_should_stop(vd) &&
	    vdev_scan_calculate_rate(sa) > vd->vdev_scan_rate) {

		/* Disable rate limiting when no redundancy remains. */
		if (vdev_scan_faults(vd) >= vd->vdev_nparity)
			break;

		cv_timedwait_sig(&vd->vdev_scan_io_cv,
		    &vd->vdev_scan_io_lock, ddi_get_lbolt() + MSEC_TO_TICK(10));
	}

	sa->scan_bytes_done += size;

	/* Limit in flight scrubbing I/Os */
	while (vd->vdev_scan_inflight >= zfs_scan_queue_limit)
		cv_wait(&vd->vdev_scan_io_cv, &vd->vdev_scan_io_lock);

	vd->vdev_scan_inflight++;
	mutex_exit(&vd->vdev_scan_io_lock);

	dmu_tx_t *tx = dmu_tx_create_dd(spa_get_dsl(spa)->dp_mos_dir);
	VERIFY0(dmu_tx_assign(tx, TXG_WAIT));
	uint64_t txg = dmu_tx_get_txg(tx);

	spa_config_enter(spa, SCL_STATE_ALL, vd, RW_READER);
	mutex_enter(&vd->vdev_scan_lock);

	/* This is the first I/O for this txg. */
	if (vd->vdev_scan_offset[txg & TXG_MASK] == 0) {
		vd->vdev_scan_rate_avg = vdev_scan_calculate_rate(sa);
		dsl_sync_task_nowait(spa_get_dsl(spa),
		    vdev_scan_zap_update_sync, vd, 2,
		    ZFS_SPACE_CHECK_RESERVED, tx);
	}

	/* When exiting write out our progress. */
	if (vdev_scan_should_stop(vd)) {
		mutex_enter(&vd->vdev_scan_io_lock);
		vd->vdev_scan_inflight--;
		mutex_exit(&vd->vdev_scan_io_lock);
		spa_config_exit(vd->vdev_spa, SCL_STATE_ALL, vd);
		mutex_exit(&vd->vdev_scan_lock);
		dmu_tx_commit(tx);
		return (SET_ERROR(EINTR));
	}
	mutex_exit(&vd->vdev_scan_lock);

	vd->vdev_scan_offset[txg & TXG_MASK] = start + size;
	vdev_scan_rebuild_block(sa, start, size, txg);

	dmu_tx_commit(tx);

	return (0);
}

/*
 * Issues scrub I/Os for all ranges in the provided sa->scan_tree range tree.
 * Additional parameters describing how the I/Os should be performed are
 * set in the scan_args structure.  See the scan_args definition for
 * additional information.
 */
static int
vdev_scan_ranges(scan_args_t *sa)
{
	vdev_t *vd = sa->scan_vdev;
	zfs_btree_t *t = &sa->scan_tree->rt_root;
	zfs_btree_index_t idx;
	uint64_t extent_bytes_max = sa->scan_extent_bytes_max;
	spa_t *spa = vd->vdev_spa;

	sa->scan_start_time = gethrtime();
	sa->scan_bytes_done = 0;

	for (range_seg_t *rs = zfs_btree_first(t, &idx); rs != NULL;
	    rs = zfs_btree_next(t, &idx, &idx)) {
		uint64_t start = rs_get_start(rs, sa->scan_tree);
		uint64_t size = rs_get_end(rs, sa->scan_tree) - start;

		/* Skip the known completed range of the metaslab. */
		if (start + size <= vd->vdev_scan_last_offset)
			continue;

		/*
		 * Split range into legally-sized logical chunk given the
		 * constraints of the top-level vdev type.  Block may not:
		 *
		 *   1) Exceed the pool's maximum allowed block size.
		 *   2) Exceed the zfs_scan_extent_bytes_max limit.
		 *   3) Span dRAID redundancy groups or metaslabs.
		 */
		while (size > 0) {
			uint64_t chunk_size;
			if (vd->vdev_ops == &vdev_draid_ops) {
				uint64_t group = vdev_draid_offset2group(vd,
				    start, B_FALSE);
				chunk_size = vdev_draid_max_rebuildable_asize(
				    vd, start);
				chunk_size = MIN(chunk_size,
				    vdev_draid_group2offset(vd,
				    group + 1, B_FALSE) - start);
			} else {
				chunk_size = vdev_psize_to_asize(vd,
				    start, SPA_MAXBLOCKSIZE);
			}

			chunk_size = MIN(size, spa_maxblocksize(spa));
			chunk_size = MIN(chunk_size, extent_bytes_max);

			int error = vdev_scan_range(sa, start, chunk_size);
			if (error != 0)
				return (error);

			size -= chunk_size;
			start += chunk_size;
		}
	}

	return (0);
}

static void
vdev_scan_calculate_progress(vdev_t *vd)
{
	ASSERT(spa_config_held(vd->vdev_spa, SCL_CONFIG, RW_READER) ||
	    spa_config_held(vd->vdev_spa, SCL_CONFIG, RW_WRITER));
	ASSERT(vd->vdev_top == vd);

	vd->vdev_scan_bytes_est = 0;
	vd->vdev_scan_bytes_done = 0;

	for (uint64_t i = 0; i < vd->vdev_ms_count; i++) {
		metaslab_t *msp = vd->vdev_ms[i];
		uint64_t last = vd->vdev_scan_last_offset;
		uint64_t alloc, ms_id;

		mutex_enter(&msp->ms_lock);

		alloc = metaslab_allocated_space(msp);
		if (alloc == 0) {
			mutex_exit(&msp->ms_lock);
			continue;
		}

		vd->vdev_scan_bytes_est += alloc;
		ms_id = last >> vd->vdev_ms_shift;

		if (msp->ms_id < ms_id) {
			vd->vdev_scan_bytes_done += alloc;
		} else if (msp->ms_id == ms_id) {
			range_tree_t *rt;
			zfs_btree_t *bt;
			zfs_btree_index_t idx;

			/*
			 * If we get here, we're in the middle of scaning this
			 * metaslab.  Load it and walk the allocated space map
			 * for an accurate progress estimation.
			 */
			rt = range_tree_create(NULL, RANGE_SEG64, NULL, 0, 0);
			bt = &rt->rt_root;

			VERIFY0(metaslab_load(msp));
			VERIFY0(space_map_load(msp->ms_sm, rt, SM_ALLOC));

			for (range_seg_t *rs = zfs_btree_first(bt, &idx);
			    rs != NULL; rs = zfs_btree_next(bt, &idx, &idx)) {
				uint64_t rs_start = rs_get_start(rs, rt);
				uint64_t rs_end = rs_get_end(rs, rt);
				uint64_t rs_size = rs_end - rs_start;

				if (rs_end <= last) {
					vd->vdev_scan_bytes_done += rs_size;
				} else if (rs_end > last && rs_start < last) {
					vd->vdev_scan_bytes_done +=
					    last - rs_start;
				} else {
					break;
				}
			}

			range_tree_vacate(rt, NULL, NULL);
		}

		mutex_exit(&msp->ms_lock);
	}
}

/*
 * Load from disk the top-level vdev's scan information.  This includes the
 * state, progress, and options provided when initiating the scan.
 */
static int
vdev_scan_load(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;
	int err = 0;

	ASSERT(spa_config_held(spa, SCL_CONFIG, RW_READER) ||
	    spa_config_held(spa, SCL_CONFIG, RW_WRITER));
	ASSERT(vd->vdev_top == vd);

	if (vd->vdev_scan_state == VDEV_SCAN_ACTIVE ||
	    vd->vdev_scan_state == VDEV_SCAN_SUSPENDED) {
		objset_t *mos = spa->spa_meta_objset;

		err = zap_lookup(mos, vd->vdev_top_zap,
		    VDEV_TOP_ZAP_SCAN_LAST_OFFSET, sizeof (uint64_t), 1,
		    &vd->vdev_scan_last_offset);
		if (err == ENOENT) {
			vd->vdev_scan_last_offset = 0;
			err = 0;
		}

		if (err == 0) {
			err = zap_lookup(mos, vd->vdev_top_zap,
			    VDEV_TOP_ZAP_SCAN_RATE, sizeof (uint64_t), 1,
			    &vd->vdev_scan_rate);
			if (err == ENOENT) {
				vd->vdev_scan_rate = 0;
				err = 0;
			}
		}

		if (err == 0) {
			err = zap_lookup(mos, vd->vdev_top_zap,
			    VDEV_TOP_ZAP_SCAN_START_TIME, sizeof (uint64_t), 1,
			    &vd->vdev_scan_start_time);
			if (err == ENOENT) {
				vd->vdev_scan_start_time = gethrestime_sec();
				err = 0;
			}
		}

		if (err == 0) {
			err = zap_lookup(mos, vd->vdev_top_zap,
			    VDEV_TOP_ZAP_SCAN_END_TIME, sizeof (uint64_t), 1,
			    &vd->vdev_scan_end_time);
			if (err == ENOENT) {
				vd->vdev_scan_end_time = 0;
				err = 0;
			}
		}

		if (err == 0) {
			err = zap_lookup(mos, vd->vdev_top_zap,
			    VDEV_TOP_ZAP_SCAN_FAULT_GUIDS,
			    sizeof (uint64_t), 3, vd->vdev_scan_fault_guids);
			if (err == ENOENT) {
				vdev_scan_set_fault_guid(vd, 0, -1);
				err = 0;
			}
		}

		if (err == 0) {
			err = zap_lookup(mos, vd->vdev_top_zap,
			    VDEV_TOP_ZAP_SCAN_DEFER_GUIDS,
			    sizeof (uint64_t), 3, vd->vdev_scan_defer_guids);
			if (err == ENOENT) {
				vdev_scan_set_defer_guid(vd, 0, -1);
				err = 0;
			}
		}
	}

	vdev_scan_calculate_progress(vd);

	return (err);
}

/*
 * Each scan thread is responsible for rebuilding a top-level vdev.  The
 * rebuild progress in tracked on disk using the VDEV_TOP_ZAP_SCAN_* entries.
 */
static void
vdev_scan_thread(void *arg)
{
	vdev_t *vd = arg;
	spa_t *spa = vd->vdev_spa;
	scan_args_t sa;
	int error = 0;

	/*
	 * The VDEV_TOP_ZAP_SCAN_* entries may have been updated.  Wait for
	 * the updated values, and for the new vdevs's DTL to propagate when
	 * spa_vdev_attach()->spa_vdev_exit() calls vdev_dtl_reassess().
	 */
	txg_wait_synced(spa_get_dsl(vd->vdev_spa), 0);

	mutex_enter(&vd->vdev_scan_lock);
	ASSERT3P(vd->vdev_top, ==, vd);
	ASSERT3P(vd->vdev_scan_thread, !=, NULL);
	mutex_exit(&vd->vdev_scan_lock);

	spa_config_enter(spa, SCL_CONFIG, FTAG, RW_READER);

	vd->vdev_scan_last_offset = 0;
	vd->vdev_scan_action_time = 0;
	vd->vdev_scan_rate = 0;
	bzero(vd->vdev_scan_fault_guids, sizeof (uint64_t) * 3);
	bzero(vd->vdev_scan_defer_guids, sizeof (uint64_t) * 3);

	VERIFY0(vdev_scan_load(vd));

	sa.scan_vdev = vd;
	sa.scan_msp = NULL;
	sa.scan_tree = range_tree_create(NULL, RANGE_SEG64, NULL, 0, 0);
	sa.scan_extent_bytes_max = zfs_scan_extent_bytes_max;
	sa.scan_faults = 0;

	/*
	 * Lookup the faulted vdev guids so a dRAID rebuild can skip offsets
	 * which are not degraded due to the fault.  If any of the guids
	 * cannot be located then all ranges in the dRAID must be rebuilt.
	 * Indicate this unexpected issue by setting sa.scan_faults = 0
	 * and clearing the invalid vd->vdev_scan_fault_guids.
	 */
	for (int i = 0; i < 3; i++) {
		uint64_t guid = vd->vdev_scan_fault_guids[i];
		vdev_t *fvd;

		if (guid != 0) {
			fvd = vdev_lookup_by_guid(vd, guid);
			if (fvd != NULL) {
				sa.scan_faults++;
				sa.scan_fault_vdevs[i] = fvd;
			} else {
				bzero(vd->vdev_scan_fault_guids,
				    sizeof (uint64_t) * 3);
				sa.scan_faults = 0;
				break;
			}
		} else {
			break;
		}
	}

	uint64_t ms_count = 0;
	for (uint64_t i = 0; i < vd->vdev_ms_count; i++) {
		metaslab_t *msp = vd->vdev_ms[i];

		/*
		 * Skip metaslabs which have already been rebuilt based on the
		 * last offset.  This will happen when restarting a scan after
		 * exporting and re-importing the pool.  vdev_scan_ranges() is
		 * responsible for skipping the rebuilt range of individual
		 * metaslabs.
		 */
		if (vd->vdev_scan_last_offset <= msp->ms_start + msp->ms_size)
			continue;

		/*
		 * If we've expanded the top-level vdev or it's our
		 * first pass, calculate our progress.
		 */
		if (vd->vdev_ms_count != ms_count) {
			vdev_scan_calculate_progress(vd);
			ms_count = vd->vdev_ms_count;
		}

		spa_config_exit(spa, SCL_CONFIG, FTAG);
		metaslab_disable(msp);
		mutex_enter(&msp->ms_lock);
		VERIFY0(metaslab_load(msp));

		/*
		 * Skip metaslabs which have never been allocated from
		 * and therefore do not contain a space map.
		 */
		if (msp->ms_sm == NULL) {
			mutex_exit(&msp->ms_lock);
			metaslab_enable(msp, B_FALSE, B_FALSE);
			spa_config_enter(spa, SCL_CONFIG, FTAG, RW_READER);
			vdev_scan_calculate_progress(vd);
			continue;
		}

		ASSERT0(range_tree_space(sa.scan_tree));

		sa.scan_msp = msp;
		VERIFY0(space_map_load(msp->ms_sm, sa.scan_tree, SM_ALLOC));
		mutex_exit(&msp->ms_lock);

		error = vdev_scan_ranges(&sa);
		metaslab_enable(msp, B_TRUE, B_FALSE);
		spa_config_enter(spa, SCL_CONFIG, FTAG, RW_READER);

		range_tree_vacate(sa.scan_tree, NULL, NULL);

		if (error != 0)
			break;
	}

	spa_config_exit(spa, SCL_CONFIG, FTAG);
	mutex_enter(&vd->vdev_scan_io_lock);
	while (vd->vdev_scan_inflight > 0)
		cv_wait(&vd->vdev_scan_io_cv, &vd->vdev_scan_io_lock);

	mutex_exit(&vd->vdev_scan_io_lock);

	range_tree_destroy(sa.scan_tree);

	mutex_enter(&vd->vdev_scan_lock);
	if (!vd->vdev_scan_exit_wanted && vdev_writeable(vd)) {
		vdev_scan_change_state(vd, VDEV_SCAN_COMPLETE,
		    vd->vdev_scan_rate, NULL, B_FALSE);
		zfs_dbgmsg("All %d metaslabs rebuilt %llu / %llu bytes",
		    vd->vdev_ms_count, (u_longlong_t)vd->vdev_scan_bytes_done,
		    (u_longlong_t)vd->vdev_scan_bytes_est);
	}

	/*
	 * Drop the vdev_scan_lock while we sync out the txg since it's
	 * possible that a device might be trying to come online and must
	 * check to see if it needs to restart a scan. That thread will be
	 * holding the spa_config_lock which would prevent the txg_wait_synced
	 * from completing.
	 */
	mutex_exit(&vd->vdev_scan_lock);
	txg_wait_synced(spa_get_dsl(spa), 0);
	mutex_enter(&vd->vdev_scan_lock);

	vd->vdev_scan_thread = NULL;
	cv_broadcast(&vd->vdev_scan_cv);
	mutex_exit(&vd->vdev_scan_lock);
}

/*
 * Starts a scan thread, as needed, for each top-level vdev which is in
 * the active state but no scan thread has yet been created.
 */
static void
vdev_scan_start(vdev_t *vd, boolean_t reset)
{
	spa_t *spa = vd->vdev_spa;

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++)
			vdev_scan_start(vd->vdev_child[i], reset);

	} else if (vd->vdev_top_zap != 0) {
		ASSERT(vd == vd->vdev_top);

		mutex_enter(&vd->vdev_scan_lock);
		if (vdev_writeable(vd) && !vd->vdev_removing &&
		    vd->vdev_scan_thread == NULL) {
			vd->vdev_scan_reset_wanted = reset;
			vd->vdev_scan_thread = thread_create(NULL, 0,
			    vdev_scan_thread, vd, 0, &p0, TS_RUN,
			    maxclsyspri);
			ASSERT(vd->vdev_scan_thread != NULL);
		}
		mutex_exit(&vd->vdev_scan_lock);
	}
}

/*
 * Returns B_TRUE if any top-level vdev is actively being rebuilt.
 */
boolean_t
vdev_scan_rebuilding(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;
	boolean_t ret = B_FALSE;

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++) {
			ret = vdev_scan_rebuilding(vd->vdev_child[i]);
			if (ret)
				return (ret);
		}
	} else if (vd->vdev_top_zap != 0) {
		mutex_enter(&vd->vdev_scan_lock);
		ret = (vd->vdev_scan_thread != NULL);
		mutex_exit(&vd->vdev_scan_lock);
	}

	return (ret);
}

/*
 * Returns B_TRUE if any top-level vdev is suspended.
 */
boolean_t
vdev_scan_suspended(vdev_t *vd)
{
	spa_t *spa = vd->vdev_spa;
	boolean_t ret = B_FALSE;

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++) {
			ret = vdev_scan_suspended(vd->vdev_child[i]);
			if (ret)
				return (ret);
		}
	} else if (vd->vdev_top_zap != 0) {
		mutex_enter(&vd->vdev_scan_lock);
		ret = (vd->vdev_scan_state == VDEV_SCAN_SUSPENDED);
		mutex_exit(&vd->vdev_scan_lock);
	}

	return (ret);
}

/*
 * Enqueue or start a rebuild operation.  The rebuild may be deferred if
 * the top-level vdev is currently actively rebuilding.  When the fault_vdev
 * is NULL it indicates a restart, rate change, or both were requested.
 */
void
vdev_scan_rebuild(vdev_t *tvd, vdev_t *fault_vdev, boolean_t reset)
{
	boolean_t start = B_FALSE;

	mutex_enter(&tvd->vdev_scan_lock);
	if (vdev_scan_rebuilding(tvd)) {
		if (reset) {
			/*
			 * Top-level vdev is actively rebuilding and deferring
			 * the new rebuild is NOT preferred.  In this case,
			 * the active rebuild must be cancelled, the new
			 * faulted guid added, and the rebuild operation
			 * reset and started from the beginning.
			 */
			mutex_exit(&tvd->vdev_scan_lock);
			vdev_scan_stop_wait(tvd, VDEV_SCAN_CANCELED);
			mutex_enter(&tvd->vdev_scan_lock);
			vdev_scan_change_state(tvd, VDEV_SCAN_ACTIVE,
			    tvd->vdev_scan_rate, fault_vdev, B_FALSE);
			start = B_TRUE;
		} else {
			/*
			 * Top-level vdev is actively rebuilding and deferring
			 * the new rebuild is preferred.  Add it to the list
			 * of deferred guids and allow the running rebuild
			 * to continue.  A new rebuild will be automatically
			 * started when the active rebuild completes.
			 */
			vdev_scan_change_state(tvd, VDEV_SCAN_ACTIVE,
			    tvd->vdev_scan_rate, fault_vdev, B_TRUE);
		}
	} else {
		/*
		 * No rebuild is active for the top-level vdev.  Add the
		 * faulted vdev guid and start the rebuild operation.
		 */
		vdev_scan_change_state(tvd, VDEV_SCAN_ACTIVE,
		    tvd->vdev_scan_rate, fault_vdev, B_FALSE);
		start = B_TRUE;
	}
	mutex_exit(&tvd->vdev_scan_lock);

	if (start)
		vdev_scan_start(tvd, reset);
}

/*
 * Sets the requested maximum rebuild rate.
 */
void
vdev_scan_set_rate(vdev_t *vd, uint64_t rate)
{
	spa_t *spa = vd->vdev_spa;

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++)
			vdev_scan_set_rate(vd->vdev_child[i], rate);

	} else if (vd->vdev_top_zap != 0) {
		mutex_enter(&vd->vdev_scan_lock);
		if (vd->vdev_scan_state == VDEV_SCAN_ACTIVE ||
		    vd->vdev_scan_state == VDEV_SCAN_SUSPENDED) {
			vdev_scan_change_state(vd, vd->vdev_scan_state,
			    rate, NULL, B_FALSE);
			vd->vdev_scan_rate = rate;
		}
		mutex_exit(&vd->vdev_scan_lock);
	}
}

/*
 * Conditionally restart all of the vdev_scan_thread's when provided
 * the root of the vdev tree, or individual top-level vdevs.
 */
void
vdev_scan_restart(vdev_t *vd, boolean_t reset)
{
	spa_t *spa = vd->vdev_spa;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));
	ASSERT(!spa_config_held(vd->vdev_spa, SCL_ALL, RW_WRITER));

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++)
			vdev_scan_restart(vd->vdev_child[i], reset);

	} else if (vd->vdev_top_zap != 0) {
		ASSERT(vd == vd->vdev_top);

		mutex_enter(&vd->vdev_scan_lock);
		uint64_t scan_state = VDEV_SCAN_NONE;
		int err = zap_lookup(spa->spa_meta_objset,
		    vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_STATE,
		    sizeof (scan_state), 1, &scan_state);
		ASSERT(err == 0 || err == ENOENT);
		vd->vdev_scan_state = scan_state;

		uint64_t timestamp = 0;
		err = zap_lookup(spa->spa_meta_objset,
		    vd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_ACTION_TIME,
		    sizeof (timestamp), 1, &timestamp);
		ASSERT(err == 0 || err == ENOENT);
		vd->vdev_scan_action_time = timestamp;

		if (vd->vdev_scan_state == VDEV_SCAN_SUSPENDED) {
			/* load progress for reporting, but don't resume */
			VERIFY0(vdev_scan_load(vd));
		} else if (vd->vdev_scan_state == VDEV_SCAN_ACTIVE &&
		    vdev_writeable(vd) && !vd->vdev_removing &&
		    vd->vdev_scan_thread == NULL) {
			VERIFY0(vdev_scan_load(vd));
			vdev_scan_start(vd, reset);
		}

		mutex_exit(&vd->vdev_scan_lock);
	}
}

/*
 * Stop and wait for all of the vdev_scan_thread's associated with the
 * vdev tree provide to be terminated (canceled or stopped).
 */
void
vdev_scan_stop_wait(vdev_t *vd, vdev_scan_state_t tgt_state)
{
	spa_t *spa = vd->vdev_spa;

	ASSERT(MUTEX_HELD(&spa_namespace_lock));

	if (vd == spa->spa_root_vdev) {
		for (uint64_t i = 0; i < vd->vdev_children; i++)
			vdev_scan_stop_wait(vd->vdev_child[i], tgt_state);

	} else if (vd->vdev_top_zap != 0) {
		ASSERT(vd == vd->vdev_top);

		mutex_enter(&vd->vdev_scan_lock);
		if (vd->vdev_scan_thread != NULL) {
			vdev_scan_change_state(vd, tgt_state, 0, NULL, B_FALSE);
			vd->vdev_scan_exit_wanted = B_TRUE;

			while (vd->vdev_scan_thread != NULL)
				cv_wait(&vd->vdev_scan_cv, &vd->vdev_scan_lock);

			ASSERT3P(vd->vdev_scan_thread, ==, NULL);
			vd->vdev_scan_exit_wanted = B_FALSE;
		}
		mutex_exit(&vd->vdev_scan_lock);
	}
}

int
vdev_scan_get_stats(vdev_t *tvd, vdev_rebuild_stat_t *vrs)
{
	if (!spa_feature_is_active(tvd->vdev_spa, SPA_FEATURE_DEVICE_REBUILD))
		return (SET_ERROR(ENOTSUP));

	if (tvd != tvd->vdev_top || tvd->vdev_top_zap == 0)
		return (SET_ERROR(EINVAL));

	int error = zap_contains(spa_meta_objset(tvd->vdev_spa),
	    tvd->vdev_top_zap, VDEV_TOP_ZAP_SCAN_STATE);
	ASSERT(error == 0 || error == ENOENT);

	if (error == ENOENT) {
		bzero(vrs, sizeof (vdev_rebuild_stat_t));
		vrs->vrs_state = VDEV_SCAN_NONE;
	} else {
		mutex_enter(&tvd->vdev_scan_lock);
		vrs->vrs_state = tvd->vdev_scan_state;
		vrs->vrs_start_time = tvd->vdev_scan_start_time;
		vrs->vrs_end_time = tvd->vdev_scan_end_time;
		vrs->vrs_action_time = tvd->vdev_scan_action_time;
		vrs->vrs_bytes_done = tvd->vdev_scan_bytes_done;
		vrs->vrs_bytes_est = tvd->vdev_scan_bytes_est;
		vrs->vrs_errors = tvd->vdev_scan_errors;
		vrs->vrs_rate_avg = tvd->vdev_scan_rate_avg;
		vrs->vrs_rate = tvd->vdev_scan_rate;
		mutex_exit(&tvd->vdev_scan_lock);
	}

	return (0);
}

/* BEGIN CSTYLED */
ZFS_MODULE_PARAM(zfs_scan, zfs_scan_, extent_bytes_max, UINT, ZMOD_RW,
    "Max size of scan I/Os, larger will be split");

ZFS_MODULE_PARAM(zfs_scan, zfs_scan_, queue_limit, UINT, ZMOD_RW,
    "Max queued scan I/Os per top-level vdev");
/* END CSTYLED */
