dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(idevicerestore, 1.0)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(libirecovery, libirecovery >= 0.2.0)
PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= 1.1.6)
PKG_CHECK_MODULES(libplist, libplist >= 1.11)
PKG_CHECK_MODULES(libzip, libzip >= 0.8)
PKG_CHECK_MODULES(libcurl, libcurl >= 7.0)
PKG_CHECK_MODULES(openssl, openssl >= 0.9.8)

GLOBAL_CFLAGS=""
AC_LDADD=""
AC_LDFLAGS=""
case "$host_os" in
	darwin*)
		AC_LDADD="-lusb-1.0"
	;;
	linux*)
		AC_LDADD="-lusb-1.0"
	;;
	mingw32)
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
