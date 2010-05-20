AM_CFLAGS =	                   \
	$(GLOBAL_CFLAGS)           \
	$(libimobiledevice_CFLAGS) \
	$(libplist_CFLAGS)         \
	$(libzip_CFLAGS)           \
	$(libcurl_CFLAGS)

AM_LDFLAGS =\
	$(libimobiledevice_LIBS)   \
	$(libplist_LIBS)           \
	$(libzip_LIBS)             \
	$(libcurl_LIBS)

bin_PROGRAMS = idevicerestore

idevicerestore_SOURCES = idevicerestore.c ipsw.c tss.c base64.c
idevicerestore_CFLAGS = $(AM_CFLAGS)
idevicerestore_LDFLAGS = $(AM_LDFLAGS)