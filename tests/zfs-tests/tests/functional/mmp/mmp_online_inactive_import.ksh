#!/bin/ksh -p
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2017 by Lawrence Livermore National Security, LLC.
#

# DESCRIPTION:
#	Ensure that a pool can be forcefully imported from another
#	host when the pool is inactive with the expected amount of
#	delay for activity checks.
#
# STRATEGY:
#	1. Set hostid to x
#	2. Create a pool
#	3. Run zpool export -F <pool>
#	4. Run zpool import -f, should succeed
#	5. Run zpool export -F <pool>
#	6. Run zpool import, should succeed
#	7. Run zpool export -F <pool>
#	8. Set hostid to y to simulate another node
#	9. Run zpool import <pool>, should fail
#	10. Run zpool import -f <pool>, should succeed
#
# NOTES:
#	Not mentioned in the strategy, but all attempted imports
#	are timed to determine if an activity check occured.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/mmp/mmp.cfg

verify_runnable "both"

function cleanup
{
	default_cleanup_noexit
	set_tunable64 zfs_mmp_interval $MMP_INTERVAL_DEFAULT
	set_spl_tunable spl_hostid $SPL_HOSTID_DEFAULT
}

log_assert "zpool import behaves correcly with inactive ONLINE pools"
log_onexit cleanup

if ! set_spl_tunable spl_hostid $SPL_HOSTID1; then
	log_fail "Failed to set spl_hostid to $SPL_HOSTID1"
fi

if ! set_tunable64 zfs_mmp_interval $MMP_INTERVAL_LONG; then
	log_fail "Failed to set zfs_mmp_interval"
fi

default_setup_noexit $DISK

log_note "SPL hostid is $(get_spl_tunable spl_hostid)"

# perform forced import when pool appears online and hostid matches,
# should succeed without delay
log_must zpool export -F $TESTPOOL
SECONDS=0
log_must zpool import -f $TESTPOOL
DURATION=$SECONDS
if [[ $DURATION -gt $ZPOOL_IMPORT_DURATION ]]; then
	log_fail "unexpected mmp activity check ($DURATION seconds)"
fi

# perform import when pool appears online and hostid matches,
# should succeed without delay
log_must zpool export -F $TESTPOOL
SECONDS=0
log_must zpool import $TESTPOOL
DURATION=$SECONDS
if [[ $DURATION -gt $ZPOOL_IMPORT_DURATION ]]; then
	log_fail "unexpected mmp activity check ($DURATION seconds)"
fi

# export pool and keep it ONLINE and change hostid to simulate a second node
log_must zpool export -F $TESTPOOL
if ! set_spl_tunable spl_hostid $SPL_HOSTID2 ; then
	log_fail "Failed to set spl_hostid to $SPL_HOSTID2"
fi

log_note "SPL hostid is $(get_spl_tunable spl_hostid)"

# perform a normal import while hostids do not match, should fail immediately
SECONDS=0
log_mustnot zpool import $TESTPOOL
DURATION=$SECONDS
if [[ $DURATION -gt $ZPOOL_IMPORT_DURATION ]]; then
	log_fail "unexpected mmp activity check ($DURATION seconds)"
fi

# perform a forced import while hostids do not match, should succeed with delay
SECONDS=0
log_must zpool import -f $TESTPOOL
DURATION=$SECONDS
if [[ $DURATION -le $ZPOOL_IMPORT_DURATION ]]; then
	log_fail "expected mmp activity check ($DURATION seconds)"
fi

log_pass "zpool import behaves correcly with inactive ONLINE pools passed"
