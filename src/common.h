/*
 * common.h
 * Misc functions used in idevicerestore
 *
 * Copyright (c) 2010 Joshua Hill. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef IDEVICERESTORE_COMMON_H
#define IDEVICERESTORE_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <plist/plist.h>
#include <libirecovery.h>

#define info(...) printf(__VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)
#define debug(...) if(idevicerestore_debug) fprintf(stderr, __VA_ARGS__)

#define MODE_UNKNOWN        -1
#define MODE_WTF             0
#define MODE_DFU             1
#define MODE_RECOVERY        2
#define MODE_RESTORE         3
#define MODE_NORMAL          4

#define FLAG_QUIT            1

struct dfu_client_t;
struct normal_client_t;
struct restore_client_t;
struct recovery_client_t;

struct idevicerestore_mode_t {
	int index;
	const char* string;
};

struct idevicerestore_entry_t {
	char* name;
	char* path;
	char* filename;
	char* blob_data;
	uint32_t blob_size;
	struct idevicerestore_entry* next;
	struct idevicerestore_entry* prev;
};

struct idevicerestore_client_t {
	int flags;
	plist_t tss;
	char* tss_url;
	plist_t version_data;
	uint64_t ecid;
	unsigned char* nonce;
	int nonce_size;
	char* udid;
	char* srnm;
	char* ipsw;
	const char* filesystem;
	struct dfu_client_t* dfu;
	struct normal_client_t* normal;
	struct restore_client_t* restore;
	struct recovery_client_t* recovery;
	struct irecv_device* device;
	struct idevicerestore_entry_t** entries;
	struct idevicerestore_mode_t* mode;
	char* version;
	char* build;
	char* restore_boot_args;
	char* cache_dir;
};

static struct idevicerestore_mode_t idevicerestore_modes[] = {
	{  0, "WTF"      },
	{  1, "DFU"      },
	{  2, "Recovery" },
	{  3, "Restore"  },
	{  4, "Normal"   },
	{ -1,  NULL      }
};

extern int idevicerestore_debug;

void debug_plist(plist_t plist);
void print_progress_bar(double progress);
int read_file(const char* filename, void** data, size_t* size);
int write_file(const char* filename, const void* data, size_t size);

char *generate_guid();

#ifdef WIN32
#include <windows.h>
#define __mkdir(path, mode) mkdir(path)
#define FMT_qu "%I64u"
#ifndef sleep
#define sleep(x) Sleep(x*1000)
#endif
#else
#define __mkdir(path, mode) mkdir(path, mode)
#define FMT_qu "%qu"
#endif

int mkdir_with_parents(const char *dir, int mode);

#ifdef __cplusplus
}
#endif

#endif
