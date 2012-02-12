dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(idevicerestore, 1.0)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= 1.1.0)
PKG_CHECK_MODULES(libplist, libplist >= 0.15)
PKG_CHECK_MODULES(libzip, libzip >= 0.8)
PKG_CHECK_MODULES(libcurl, libcurl >= 7.0)

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

AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT

