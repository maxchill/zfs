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
# Copyright (c) 2018 by Lawrence Livermore National Security, LLC.
#

# DESCRIPTION:
#	Verify fiemap property reports extents.
#
# STRATEGY:
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/fiemap/fiemap.kshlib

verify_runnable "both"

function cleanup
{
	default_cleanup_noexit
}

log_assert "FIEMAP reports extents"
log_onexit cleanup

default_setup_noexit $DISK

log_pass "FIEMAP reported extents"
