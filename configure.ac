#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.64)
AC_INIT([idevicerestore], [1.0], [https://github.com/libimobiledevice/idevicerestore/issues],, [http://libimobiledevice.org])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])


# Minimum package versions
LIBIRECOVERY_VERSION=0.2.0
LIBIMOBILEDEVICE_VERSION=1.2.1
LIBPLIST_VERSION=1.12
LIBZIP_VERSION=0.8
LIBCURL_VERSION=7.0
OPENSSL_VERSION=0.9.8

AC_SUBST(LIBIRECOVERY_VERSION)
AC_SUBST(LIBIMOBILEDEVICE_VERSION)
AC_SUBST(LIBPLIST_VERSION)
AC_SUBST(LIBZIP_VERSION)
AC_SUBST(LIBCURL_VERSION)
AC_SUBST(OPENSSL_VERSION)

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

# Checks for libraries.
PKG_CHECK_MODULES(libirecovery, libirecovery >= $LIBIRECOVERY_VERSION)
PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= $LIBIMOBILEDEVICE_VERSION)
PKG_CHECK_MODULES(libplist, libplist >= $LIBPLIST_VERSION)
PKG_CHECK_MODULES(libzip, libzip >= $LIBZIP_VERSION)
PKG_CHECK_MODULES(libcurl, libcurl >= $LIBCURL_VERSION)
PKG_CHECK_MODULES(openssl, openssl >= $OPENSSL_VERSION)
PKG_CHECK_MODULES(zlib, zlib)

GLOBAL_CFLAGS="-Wno-multichar "
AC_LDADD=""
AC_LDFLAGS=""
AC_MSG_CHECKING([whether we need platform-specific build settings])
case ${host_os} in
  *mingw32*|*cygwin*)
    AC_MSG_RESULT([yes])
    win32=true
    GLOBAL_CFLAGS+="-DWIN32 -D__LITTLE_ENDIAN__=1"
    AC_LDFLAGS+="-static-libgcc"
    ;;
  darwin*)
    AC_MSG_RESULT([yes])
    AC_DEFINE([_DARWIN_BETTER_REALPATH], [1], [Use better method for realpath])
    AX_PTHREAD([], [AC_MSG_ERROR([pthread is required to build $PACKAGE])])
    ;;
  *)
    AC_MSG_RESULT([yes])
    AX_PTHREAD([], [AC_MSG_ERROR([pthread is required to build $PACKAGE])])
    ;;
esac
AM_CONDITIONAL(WIN32, test x$win32 = xtrue)

AC_CHECK_FUNCS([strsep strcspn mkstemp realpath])
if test x$ac_cv_func_strsep != xyes; then
  if test x$ac_cv_func_strcspn != xyes; then
    AC_MSG_ERROR([You need either strsep or strcspn to build $PACKAGE])
  fi
fi

# check if libimobiledevice has timeout errors
AC_CACHE_CHECK(for IDEVICE_E_TIMEOUT in enum idevice_error_t, ac_cv_idevice_error_has_timeout,
	AC_TRY_COMPILE([
		#include <libimobiledevice/libimobiledevice.h>
		], [
			return IDEVICE_E_TIMEOUT;
		], ac_cv_idevice_error_has_timeout=yes, ac_cv_idevice_error_has_timeout=no))

if test "$ac_cv_idevice_error_has_timeout" = "yes"; then
	AC_DEFINE(HAVE_IDEVICE_E_TIMEOUT, 1, [Define if enum idevice_error_t defines IDEVICE_E_TIMEOUT])
fi
AC_CACHE_CHECK(for RESTORE_E_RECEIVE_TIMEOUT in enum restored_error_t, ac_cv_restored_error_has_timeout,
	AC_TRY_COMPILE([
		#include <libimobiledevice/restore.h>
		], [
			return RESTORE_E_RECEIVE_TIMEOUT;
		], ac_cv_restored_error_has_timeout=yes, ac_cv_restored_error_has_timeout=no))

if test "$ac_cv_restored_error_has_timeout" = "yes"; then
	AC_DEFINE(HAVE_RESTORE_E_RECEIVE_TIMEOUT, 1, [Define if enum restored_error_t defines RESTORE_E_RECEIVE_TIMEOUT])
fi

AC_SUBST(GLOBAL_CFLAGS)
AC_SUBST(AC_LDFLAGS)
AC_SUBST(AC_LDADD)

# check for large file support
AC_SYS_LARGEFILE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_OUTPUT([
Makefile
src/Makefile
docs/Makefile
])

echo "
Configuration for $PACKAGE $VERSION:
-------------------------------------------

  Install prefix: .........: $prefix

  Now type 'make' to build $PACKAGE $VERSION,
  and then 'make install' for installation.
"
