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
LIBIMOBILEDEVICE_VERSION=1.1.6
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

GLOBAL_CFLAGS=""
AC_LDADD=""
AC_LDFLAGS=""
case "$host_os" in
	darwin*)
	;;
	linux*)
	;;
	mingw*)
		GLOBAL_CFLAGS+="-DWIN32 -D__LITTLE_ENDIAN__=1"
		AC_LDFLAGS+="-static-libgcc"
		AC_LDADD="-lsetupapi"
	;;
	*)
	;;
esac

AC_SUBST(GLOBAL_CFLAGS)
AC_SUBST(AC_LDFLAGS)
AC_SUBST(AC_LDADD)

# check for large file support
AC_SYS_LARGEFILE
LFS_CFLAGS=''
if test "$enable_largefile" != no; then
	if test "$ac_cv_sys_file_offset_bits" != 'no'; then
		LFS_CFLAGS="$LFS_CFLAGS -D_FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits"
	else
		AC_MSG_CHECKING(for native large file support)
		AC_RUN_IFELSE([AC_LANG_SOURCE([#include <unistd.h>
		  int main (int argc, char **argv)
		  {
		      exit(!(sizeof(off_t) == 8));
		  }])],
		[ac_cv_sys_file_offset_bits=64; AC_DEFINE(_FILE_OFFSET_BITS,64)
		 AC_MSG_RESULT(yes)],
		[AC_MSG_RESULT(no)])
	fi
	if test "$ac_cv_sys_large_files" != 'no'; then
		LFS_CFLAGS="$LFS_CFLAGS -D_LARGE_FILES=1"
	fi
	AC_FUNC_FSEEKO
	if test "$ac_cv_sys_largefile_source" != 'no'; then
		LFS_CFLAGS="$LFS_CFLAGS -D_LARGEFILE_SOURCE=1"
	fi
fi
AC_SUBST(LFS_CFLAGS)

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
