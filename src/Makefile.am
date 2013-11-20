AM_CFLAGS =	                   \
	$(GLOBAL_CFLAGS)           \
	$(libirecovery_CFLAGS)     \
	$(libimobiledevice_CFLAGS) \
	$(libplist_CFLAGS)         \
	$(libzip_CFLAGS)           \
	$(openssl_CFLAGS)          \
	$(libcurl_CFLAGS)

AM_LDFLAGS =\
	$(AC_LDFLAGS)              \
	$(libirecovery_LIBS)       \
	$(libimobiledevice_LIBS)   \
	$(libplist_LIBS)           \
	$(libzip_LIBS)             \
	$(openssl_LIBS)            \
	$(libcurl_LIBS)

AM_LDADD = $(AC_LDADD)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = idevicerestore.c common.c tss.c fls.c mbn.c img3.c img4.c ipsw.c normal.c dfu.c recovery.c restore.c asr.c limera1n.c download.c locking.c
idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)
idevicerestore_LDADD = $(AM_LDADD)
