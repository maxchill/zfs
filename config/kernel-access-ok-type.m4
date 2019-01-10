dnl #
dnl # Linux 5.0: access_ok() drops 'type' parameter:
dnl #
dnl # - access_ok(type, addr, size)
dnl # + access_ok(addr, size)
dnl #
AC_DEFUN([ZFS_AC_KERNEL_ACCESS_OK_TYPE], [
	AC_MSG_CHECKING([whether access_ok() has 'type' parameter])
	ZFS_LINUX_TRY_COMPILE([
		#include <linux/kernel.h>
	],[
		access_ok(0, NULL, 0);
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_ACCESS_OK_TYPE, 1, [kernel has access_ok with 'type' parameter])
	],[
		AC_MSG_RESULT(no)
	])
])
