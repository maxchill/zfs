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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2014 by Delphix. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/kstat.h>
#include <sys/processor.h>

list_t zfs_dbgmsgs;
kmutex_t zfs_dbgmsgs_lock;
kstat_t *zfs_dbgmsg_kstat;
unsigned int zfs_dbgmsg_size = 0;

/*
 * By default enable the internal ZFS debug log.  The log will contain
 * messages from the dprintf() and zfs_logmsg() log functions.
 *
 * # Set the kernel debug log size to N bytes, set to 0 to disable.
 * echo <bytes> >/sys/module/zfs/parameters/zfs_dbgmsg_maxsize
 *
 * # Print the kernel debug log.
 * cat /proc/spl/kstat/zfs/dbgmsg
 *
 * # Clear the kernel debug log.
 * echo 0 >/proc/spl/kstat/zfs/dbgmsg
 */

/*
 * Maximum debug log size, once the limit is reached older entries are
 * removed from the list in a FIFO fashion.
 */
unsigned int zfs_dbgmsg_maxsize = 1048576; /* 1M default */

/*
 * A configuration string which controls which dprintf messages are logged.
 * Valid values are: time, pid, cpu, ffl, func, on, all.
 */
static char *zfs_dprintf_string = "time,pid,cpu,ffl";
static int dprintf_filter;

/*
 */
#ifdef ZFS_DEBUG
int zfs_flags = (ZFS_DEBUG_MASK & ~(ZFS_DEBUG_DPRINTF | ZFS_DEBUG_SET_ERROR));
#else
int zfs_flags = 0;
#endif


static int
zfs_dbgmsg_headers(char *buf, size_t size)
{
	(void) snprintf(buf, size, "%s %s %s %s %s\n",
	    "time", "pid:tid", "cpu", "file:line:func", "message");

	return (0);
}

static int
zfs_dbgmsg_data(char *buf, size_t size, void *data)
{
	zfs_dbgmsg_t *zdm = (zfs_dbgmsg_t *)data;

	(void) snprintf(buf, size, "%llu.%09llu %u:%u %u %s %s\n",
	    (u_longlong_t)zdm->zdm_timestamp / NANOSEC,
	    (u_longlong_t)zdm->zdm_timestamp % NANOSEC,
	    zdm->zdm_pid, zdm->zdm_tid,
	    zdm->zdm_cpu,
	    zdm->zdm_ffl ? zdm->zdm_ffl : "-",
	    zdm->zdm_msg ? zdm->zdm_msg : "-");

	return (0);
}

static void *
zfs_dbgmsg_addr(kstat_t *ksp, loff_t n)
{
	zfs_dbgmsg_t *zdm = (zfs_dbgmsg_t *)ksp->ks_private;

	ASSERT(MUTEX_HELD(&zfs_dbgmsgs_lock));

	if (n == 0)
		ksp->ks_private = list_head(&zfs_dbgmsgs);
	else if (zdm)
		ksp->ks_private = list_next(&zfs_dbgmsgs, zdm);

	return (ksp->ks_private);
}

static zfs_dbgmsg_t *
zfs_dbgmsg_alloc(const char *file, const char *func, int line,
    const char *fmt, va_list adx)
{
	zfs_dbgmsg_t *zdm;

	zdm = kmem_zalloc(sizeof (zfs_dbgmsg_t), KM_SLEEP);
	zdm->zdm_size = sizeof (zfs_dbgmsg_t);

	/*
	 * When file, function, and line are all provided include them in
	 * the debug message encoded as a "file:function:line" string.
	 * For brevity the leading prefix to the filename is stripped.
	 */
	if (file != NULL && func != NULL && line) {
		const char *newfile;

		newfile	= strrchr(file, '/');
		newfile = (newfile != NULL) ? newfile + 1 : file;

		zdm->zdm_ffl = kmem_asprintf("%s:%d:%s()", newfile, line, func);
		zdm->zdm_size += strlen(zdm->zdm_ffl);
	}

	/*
	 * Generate the message with the trailing newline stripped.
	 */
	zdm->zdm_msg = kmem_vasprintf(fmt, adx);
	zdm->zdm_size += strlen(zdm->zdm_msg);

	char *nl = strrchr(zdm->zdm_msg, '\n');
	if (nl != NULL)
		*nl = '\0';

	/*
	 * Add information describing the context of the caller.
	 */
	zdm->zdm_timestamp = gethrtime();
	zdm->zdm_pid = getpid();
	zdm->zdm_tid = (uintptr_t)curthread;
	zdm->zdm_cpu = getcpuid();

	return (zdm);
}

static void
zfs_dbgmsg_free(zfs_dbgmsg_t *zdm)
{

	if (zdm->zdm_ffl != NULL)
		strfree(zdm->zdm_ffl);

	if (zdm->zdm_msg != NULL)
		strfree(zdm->zdm_msg);

	kmem_free(zdm, sizeof (zfs_dbgmsg_t));
}

static void
zfs_dbgmsg_purge(unsigned int max_size)
{
	zfs_dbgmsg_t *zdm;

	mutex_enter(&zfs_dbgmsgs_lock);

	while (zfs_dbgmsg_size > max_size) {
		zdm = list_remove_head(&zfs_dbgmsgs);
		if (zdm == NULL)
			break;

		zfs_dbgmsg_size -= zdm->zdm_size;
		zfs_dbgmsg_free(zdm);
	}

	mutex_exit(&zfs_dbgmsgs_lock);
}

static void
zfs_dbgmsg_insert(zfs_dbgmsg_t *zdm)
{
	mutex_enter(&zfs_dbgmsgs_lock);

	zfs_dbgmsg_size += zdm->zdm_size;
	list_insert_tail(&zfs_dbgmsgs, zdm);

	mutex_exit(&zfs_dbgmsgs_lock);
}

static int
zfs_dbgmsg_update(kstat_t *ksp, int rw)
{
	if (rw == KSTAT_WRITE)
		zfs_dbgmsg_purge(0);

	return (0);
}

int
dprintf_find_string(const char *string)
{
	char *tmp_str = zfs_dprintf_string;
	int len = strlen(string);

	/*
	 * Find out if this is a string we want to print.
	 * String format: file1.c,function_name1,file2.c,file3.c
	 */
	while (tmp_str != NULL) {
		if (strncmp(tmp_str, string, len) == 0 &&
		    (tmp_str[len] == ',' || tmp_str[len] == '\0'))
			return (1);
		tmp_str = strchr(tmp_str, ',');
		if (tmp_str != NULL)
			tmp_str++; /* Get rid of , */
	}

	return (0);
}

static void
dprintf_set_filter(void)
{
	dprintf_filter = 0;

	if (dprintf_find_string("time"))
		dprintf_filter |= DPRINTF_TIME;

	if (dprintf_find_string("pid"))
		dprintf_filter |= DPRINTF_PID;

	if (dprintf_find_string("cpu"))
		dprintf_filter |= DPRINTF_CPU;

	if (dprintf_find_string("ffl") || dprintf_find_string("func"))
		dprintf_filter |= DPRINTF_FFL;

	if (dprintf_find_string("on") || dprintf_find_string("all"))
		dprintf_filter |= DPRINTF_MASK;
}

#ifdef _KERNEL
/*
 * Print one message as a trace point, they may be enabled as shown.
 *
 * # Enable zfs__dprintf tracepoint, clear the tracepoint ring buffer
 * $ echo 1 > /sys/module/zfs/parameters/zfs_flags
 * $ echo 1 > /sys/kernel/debug/tracing/events/zfs/enable
 * $ echo 0 > /sys/kernel/debug/tracing/trace
 *
 * # Dump the ring buffer.
 * $ cat /sys/kernel/debug/tracing/trace
 */
static void
zfs_dbgmsg_print_one(zfs_dbgmsg_t *zdm)
{
	DTRACE_PROBE1(zfs__dprintf, char *, zdm->zdm_buf);
}

#else

static void
zfs_dbgmsg_print_headers(const char *tag)
{
	flockfile(stdout);

	if (dprintf_filter & DPRINTF_TIME)
		(void) printf("%s ", "time");
	if (dprintf_filter & DPRINTF_PID)
		(void) printf("%s ", "pid:tid");
	if (dprintf_filter & DPRINTF_CPU)
		(void) printf("%s ", "cpu");
	if (dprintf_filter & DPRINTF_FFL)
		(void) printf("%s ", "file:line:func");

	(void) printf("%s (%s)\n", "message", "tag");

	funlockfile(stdout);
}

/*
 * Print these messages to the terminal by setting the ZFS_DEBUG environment
 * variable or include the "debug=..." argument on the command line.
 */
static void
zfs_dbgmsg_print_one(zfs_dbgmsg_t *zdm)
{
	flockfile(stdout);

	if (dprintf_filter & DPRINTF_TIME)
		(void) printf("%llu.%09llu ",
		    (u_longlong_t)zdm->zdm_timestamp / NANOSEC,
		    (u_longlong_t)zdm->zdm_timestamp % NANOSEC);
	if (dprintf_filter & DPRINTF_PID)
		(void) printf("%u:%u ", zdm->zdm_pid, zdm->zdm_tid);
	if (dprintf_filter & DPRINTF_CPU)
		(void) printf("%u ", zdm->zdm_cpu);
	if (dprintf_filter & DPRINTF_FFL)
		(void) printf("%s ", zdm->zdm_ffl);

	(void) printf("%s\n", zdm->zdm_msg);

	funlockfile(stdout);
}

void
zfs_dbgmsg_print(const char *tag)
{
	zfs_dbgmsg_t *zdm;

	zfs_dbgmsg_print_headers(tag);

	mutex_enter(&zfs_dbgmsgs_lock);

	for (zdm = list_head(&zfs_dbgmsgs); zdm;
	    zdm = list_next(&zfs_dbgmsgs, zdm))
		zfs_dbgmsg_print_one(zdm);

	mutex_exit(&zfs_dbgmsgs_lock);
}

void
dprintf_setup(int *argc, char **argv)
{
	char *dprintf_string = NULL;

	/*
	 * Debugging can be specified two ways: by setting the
	 * environment variable ZFS_DEBUG, or by including a
	 * "debug=..."  argument on the command line.  The command
	 * line setting overrides the environment variable.
	 */
	for (int i = 1; i < *argc; i++) {
		int j, len = strlen("debug=");
		/* First look for a command line argument */
		if (strncmp("debug=", argv[i], len) == 0) {
			dprintf_string = argv[i] + len;
			/* Remove from args */
			for (j = i; j < *argc; j++)
				argv[j] = argv[j+1];
			argv[j] = NULL;
			(*argc)--;
		}
	}

	/* Look for ZFS_DEBUG environment variable */
	if (dprintf_string == NULL)
		dprintf_string = getenv("ZFS_DEBUG");

	/* Enable dprintf and set filter if requested. */
	if (dprintf_string != NULL) {
		zfs_dprintf_string = dprintf_string;
		dprintf_set_filter();
		zfs_flags |= ZFS_DEBUG_DPRINTF;
	} else {
		zfs_dprintf_string = NULL;
	}
}
#endif /* !_KERNEL */

void
zfs_dbgmsg_init(void)
{
	list_create(&zfs_dbgmsgs, sizeof (zfs_dbgmsg_t),
	    offsetof(zfs_dbgmsg_t, zdm_node));
	mutex_init(&zfs_dbgmsgs_lock, NULL, MUTEX_DEFAULT, NULL);

	zfs_dbgmsg_kstat = kstat_create("zfs", 0, "dbgmsg", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VIRTUAL);
	if (zfs_dbgmsg_kstat) {
		zfs_dbgmsg_kstat->ks_lock = &zfs_dbgmsgs_lock;
		zfs_dbgmsg_kstat->ks_ndata = UINT32_MAX;
		zfs_dbgmsg_kstat->ks_private = NULL;
		zfs_dbgmsg_kstat->ks_update = zfs_dbgmsg_update;
		kstat_set_raw_ops(zfs_dbgmsg_kstat, zfs_dbgmsg_headers,
		    zfs_dbgmsg_data, zfs_dbgmsg_addr);
		kstat_install(zfs_dbgmsg_kstat);
	}

	dprintf_set_filter();
}

void
zfs_dbgmsg_fini(void)
{
	if (zfs_dbgmsg_kstat)
		kstat_delete(zfs_dbgmsg_kstat);

	zfs_dbgmsg_purge(0);
	mutex_destroy(&zfs_dbgmsgs_lock);

	ASSERT0(zfs_dbgmsg_size);
}

void
__set_error(const char *file, const char *func, int line, int err)
{
	if (zfs_flags & ZFS_DEBUG_SET_ERROR)
		__dprintf(file, func, line, "error %lu", err);
}

void
__dprintf(const char *file, const char *func, int line, const char *fmt, ...)
{
	zfs_dbgmsg_t *zdm;
	va_list adx;

	va_start(adx, fmt);
	zdm = zfs_dbgmsg_alloc(file, func, line, fmt, adx);
	va_end(adx);

	zfs_dbgmsg_print_one(zdm);

	if (zfs_dbgmsg_maxsize) {
		zfs_dbgmsg_insert(zdm);
		zfs_dbgmsg_purge(zfs_dbgmsg_maxsize);
	} else {
		zfs_dbgmsg_free(zdm);
	}
}

void
zfs_dbgmsg(const char *fmt, ...)
{
	zfs_dbgmsg_t *zdm;
	va_list adx;

	if (!zfs_dbgmsg_maxsize)
		return;

	va_start(adx, fmt);
	zdm = zfs_dbgmsg_alloc(NULL, NULL, 0, fmt, adx);
	va_end(adx);

	DTRACE_PROBE1(zfs__dbgmsg, char *, zdm->zdm_msg);

	zfs_dbgmsg_insert(zdm);
	zfs_dbgmsg_purge(zfs_dbgmsg_maxsize);
}

#ifdef _KERNEL

#include <linux/mod_compat.h>

static int
param_set_dbgmsg_maxsize(const char *val, zfs_kernel_param_t *kp)
{
	int error;

	error = param_set_uint(val, kp);
	if (error == 0)
		zfs_dbgmsg_purge(zfs_dbgmsg_maxsize);

	return (error);
}

static int
param_set_dprintf_string(const char *val, zfs_kernel_param_t *kp)
{
	int error;
	char *p;

	if (val == NULL)
		return (SET_ERROR(-EINVAL));

	if ((p = strchr(val, '\n')) != NULL)
		*p = '\0';

	error = param_set_charp(val, kp);
	if (error == 0) {
		dprintf_set_filter();
		zfs_flags |= ZFS_DEBUG_DPRINTF;
	}

	return (error);
}

module_param_call(zfs_dbgmsg_maxsize, param_set_dbgmsg_maxsize,
    param_get_uint, &zfs_dbgmsg_maxsize, 0644);
MODULE_PARM_DESC(zfs_dbgmsg_maxsize, "Maximum ZFS debug log size");

module_param_call(zfs_dprintf_string, param_set_dprintf_string,
    param_get_charp, &zfs_dprintf_string, 0644);
MODULE_PARM_DESC(zfs_dprintf_string, "Filter rules for dprintf log messages");
#endif
