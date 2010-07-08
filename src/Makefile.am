libirecovery_CFLAGS = -I/usr/local/include
libirecovery_LIBS = -L/usr/local/lib -lirecovery -lusb-1.0

AM_CFLAGS =	                   \
	$(GLOBAL_CFLAGS)           \
	$(libimobiledevice_CFLAGS) \
	$(libplist_CFLAGS)         \
	$(libzip_CFLAGS)           \
	$(libcurl_CFLAGS)          \
	$(libirecovery_CFLAGS)

AM_LDFLAGS =\
	$(libimobiledevice_LIBS)   \
	$(libplist_LIBS)           \
	$(libzip_LIBS)             \
	$(libcurl_LIBS)            \
	$(libirecovery_LIBS)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = idevicerestore.c common.c tss.c img3.c ipsw.c normal.c dfu.c recovery.c restore.c asr.c
idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)
