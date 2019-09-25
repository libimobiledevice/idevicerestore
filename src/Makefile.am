AM_CFLAGS =	                   \
	$(GLOBAL_CFLAGS)           \
	$(LFS_CFLAGS)              \
	$(libirecovery_CFLAGS)     \
	$(libimobiledevice_CFLAGS) \
	$(libplist_CFLAGS)         \
	$(libzip_CFLAGS)           \
	$(zlib_CFLAGS)             \
	$(openssl_CFLAGS)          \
	$(libcurl_CFLAGS)

AM_LDFLAGS =\
	$(AC_LDFLAGS)              \
	$(libirecovery_LIBS)       \
	$(libimobiledevice_LIBS)   \
	$(libplist_LIBS)           \
	$(libzip_LIBS)             \
	$(zlib_LIBS)               \
	$(openssl_LIBS)            \
	$(libcurl_LIBS)

AM_LDADD = $(AC_LDADD)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = idevicerestore.c common.c tss.c fls.c mbn.c img3.c img4.c ftab.c ipsw.c normal.c dfu.c recovery.c restore.c asr.c fdr.c limera1n.c download.c locking.c socket.c thread.c jsmn.c json_plist.c
idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)
idevicerestore_LDADD = $(AM_LDADD)
