#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Use is subject to license terms.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_clear/zpool_clear.cfg

#
# DESCRIPTION:
# Verify 'zpool clear' can clear pool errors.
#
# STRATEGY:
# 1. Create various configuration pools
# 2. Make errors to pool
# 3. Use zpool clear to clear errors
# 4. Verify the errors has been cleared.
#

verify_runnable "global"

function cleanup
{
	log_must zinject -c all
	log_must zpool clear $TESTPOOL1

        poolexists $TESTPOOL1 && \
                log_must zpool destroy -f $TESTPOOL1

        for file in `ls $TESTDIR/file.*`; do
		log_must rm -f $file
        done
}


log_assert "Verify 'zpool clear' only can resume inactive pools"
log_onexit cleanup

log_must mkdir -p $TESTDIR
typeset -i i=0
while (( i < 3 )); do
	log_must truncate -s $FILESIZE $TESTDIR/file.$i

	(( i = i + 1 ))
done

fbase=$TESTDIR/file
set -A poolconf "$fbase.0 $fbase.1 $fbase.2"

function check_err # <pool> [<vdev>]
{
	typeset pool=$1
	shift
	if (( $# > 0 )); then
		typeset	checkvdev=$1
	else
		typeset checkvdev=""
	fi
	typeset -i errnum=0
	typeset c_read=0
	typeset c_write=0
	typeset c_cksum=0
	typeset tmpfile=/var/tmp/file.$$
	typeset healthstr="pool '$pool' is healthy"
	typeset output="`zpool status -x $pool`"

	[[ "$output" ==  "$healthstr" ]] && return $errnum

	zpool status -x $pool | grep -v "^$" | grep -v "pool:" \
			| grep -v "state:" | grep -v "config:" \
			| grep -v "errors:" > $tmpfile
	typeset line
	typeset -i fetchbegin=1
	while read line; do
		if (( $fetchbegin != 0 )); then
                        echo $line | grep "NAME" >/dev/null 2>&1
                        (( $? == 0 )) && (( fetchbegin = 0 ))
                         continue
                fi

		if [[ -n $checkvdev ]]; then
			echo $line | grep $checkvdev >/dev/null 2>&1
			(( $? != 0 )) && continue
			c_read=`echo $line | awk '{print $3}'`
			c_write=`echo $line | awk '{print $4}'`
			c_cksum=`echo $line | awk '{print $5}'`
			if [ $c_read != 0 ] || [ $c_write != 0 ] || \
			    [ $c_cksum != 0 ]
			then
				(( errnum = errnum + 1 ))
			fi
			break
		fi

		c_read=`echo $line | awk '{print $3}'`
		c_write=`echo $line | awk '{print $4}'`
		c_cksum=`echo $line | awk '{print $5}'`
		if [ $c_read != 0 ] || [ $c_write != 0 ] || \
		    [ $c_cksum != 0 ]
		then
			(( errnum = errnum + 1 ))
		fi
	done <$tmpfile

	return $errnum
}

function do_testing #<clear type> <vdevs>
{
	typeset FS=$TESTPOOL1/fs
	typeset file=/$FS/f
	typeset type=$1
	shift
	typeset vdevs="$@"

	log_must zpool create -f $TESTPOOL1 $vdevs
	log_must zfs create $FS
	#
	# Partially fill up the zfs filesystem in order to make data block
	# errors.  It's not necessary to fill the entire filesystem.
	#
	avail=$(get_prop available $FS)
	fill_mb=$(((avail / 1024 / 1024) * 10 / 100))
	log_must dd if=/dev/urandom of=$file.$i bs=$BLOCKSZ count=$fill_mb

	# Make a random vdev return IO errors for all IO operations.
	(( i = $RANDOM % 3 ))
	sync_pool $TESTPOOL1
	log_must zinject -d $fbase.$i -e nxio $TESTPOOL1

	# Scrub the pool to suspend it.
	log_must zpool scrub $TESTPOOL1 &

	sleep 15

	if is_pool_suspended; then
		log_fail "Suspended"
	else
		log_fail "Not Suspended"
	fi

	# Wait for pool to transition to a suspended state then clear the
	# persistent IO errors injected.
	while ! is_pool_suspended $TESTPOOL1; do
		sleep 1
	done

	log_must zinject -c all

	if [[ $type == "inactive" ]]; then
		log_must zpool clear $TESTPOOL1 $fbase.$i
	elif [[ $type == "active" ]]; then
		# XXX - Modify pool
		log_mustnot zpool clear $TESTPOOL1 $fbase.$i
	else
		log_fail "Invalid type: $type"
	fi

	while is_pool_scrubbing; do
		sleep 1
	done

	if check_err $TESTPOOL1 $fbase.$1; then
		log_fail "'zpool clear' detected errors after resume"
	fi

	log_must zpool destroy $TESTPOOL1
}

log_note "'zpool clear' can resume inactive pools."
for devconf in "${poolconf[@]}"; do
	do_testing "inactive" $devconf
done
log_note "'zpool clear' cannot resume active pools."
for devconf in "${poolconf[@]}"; do
#	do_testing "active" $devconf
done

log_pass "'zpool clear' only resumes idle pools."
