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

#define info(...) printf(__VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)
#define debug(...) if(idevicerestore_debug) fprintf(stderr, __VA_ARGS__)

#define CPID_UNKNOWN        -1
#define CPID_IPHONE2G     8900
#define CPID_IPOD1G       8900
#define CPID_IPHONE3G     8900
#define CPID_IPOD2G       8720
#define CPID_IPHONE3GS    8920
#define CPID_IPOD3G       8922
#define CPID_IPAD1G       8930
#define CPID_IPHONE4      8930
#define CPID_IPOD4G       8930
#define CPID_APPLETV2     8930
#define CPID_IPHONE42     8930
#define CPID_IPAD21       8940
#define CPID_IPAD22       8940
#define CPID_IPAD23       8940
#define CPID_IPHONE4S     8940

#define BDID_UNKNOWN        -1
#define BDID_IPHONE2G        0
#define BDID_IPOD1G          2
#define BDID_IPHONE3G        4
#define BDID_IPOD2G          0
#define BDID_IPHONE3GS       0
#define BDID_IPOD3G          2
#define BDID_IPAD1G          2
#define BDID_IPHONE4         0
#define BDID_IPOD4G          8
#define BDID_APPLETV2       10
#define BDID_IPHONE42        6
#define BDID_IPAD21          4
#define BDID_IPAD22          6
#define BDID_IPAD23          2
#define BDID_IPHONE4S        8

#define DEVICE_UNKNOWN      -1
#define DEVICE_IPHONE2G      0
#define DEVICE_IPOD1G        1
#define DEVICE_IPHONE3G      2
#define DEVICE_IPOD2G        3
#define DEVICE_IPHONE3GS     4
#define DEVICE_IPOD3G        5
#define DEVICE_IPAD1G        6
#define DEVICE_IPHONE4       7
#define DEVICE_IPOD4G        8
#define DEVICE_APPLETV2      9
#define DEVICE_IPHONE42     10
#define DEVICE_IPAD21       11
#define DEVICE_IPAD22       12
#define DEVICE_IPAD23       13
#define DEVICE_IPHONE4S     14

#define MODE_UNKNOWN        -1
#define MODE_WTF             0
#define MODE_DFU             1
#define MODE_RECOVERY        2
#define MODE_RESTORE         3
#define MODE_NORMAL          4

#define FLAG_QUIT            1
#define FLAG_DEBUG           2
#define FLAG_ERASE           4
#define FLAG_CUSTOM          8
#define FLAG_EXCLUDE        16
#define FLAG_PWN            32

extern int use_apple_server;

struct dfu_client_t;
struct normal_client_t;
struct restore_clien_t;
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

struct idevicerestore_device_t {
	int index;
	const char* product;
	const char* model;
	uint32_t board_id;
	uint32_t chip_id;
};

struct idevicerestore_client_t {
	int flags;
	plist_t tss;
	plist_t version_data;
	uint64_t ecid;
	unsigned char* nonce;
	int nonce_size;
	char* uuid;
	char* srnm;
	const char* ipsw;
	const char* filesystem;
	struct dfu_client_t* dfu;
	struct normal_client_t* normal;
	struct restore_client_t* restore;
	struct recovery_client_t* recovery;
	struct idevicerestore_device_t* device;
	struct idevicerestore_entry_t** entries;
	struct idevicerestore_mode_t* mode;
	char* version;
	char* build;
	char* restore_boot_args;
};

static struct idevicerestore_mode_t idevicerestore_modes[] = {
	{  0, "WTF"      },
	{  1, "DFU"      },
	{  2, "Recovery" },
	{  3, "Restore"  },
	{  4, "Normal"   },
	{ -1,  NULL      }
};

static struct idevicerestore_device_t idevicerestore_devices[] = {
	{  0, "iPhone1,1", "M68AP",  0,  8900 },
	{  1, "iPod1,1",   "N45AP",  2,  8900 },
	{  2, "iPhone1,2", "N82AP",  4,  8900 },
	{  3, "iPod2,1",   "N72AP",  0,  8720 },
	{  4, "iPhone2,1", "N88AP",  0,  8920 },
	{  5, "iPod3,1",   "N18AP",  2,  8922 },
	{  6, "iPad1,1",   "K48AP",  2,  8930 },
	{  7, "iPhone3,1", "N90AP",  0,  8930 },
	{  8, "iPod4,1", "N81AP",  8,  8930 },
	{  9, "AppleTV2,1", "K66AP",  10,  8930 },
	{  10, "iPhone3,3", "N92AP",  6,  8930 },
	{  11, "iPad2,1", "K93AP",  4,  8940 },
	{  12, "iPad2,2", "K94AP",  6,  8940 },
	{  13, "iPad2,3", "K95AP",  2,  8940 },
	{  14, "iPhone4,1", "N94AP",  8,  8940 },
	{ -1,  NULL,        NULL,   -1,    -1 }
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
#define sleep(x) Sleep(x*1000)
#else
#define __mkdir(path, mode) mkdir(path, mode)
#define FMT_qu "%qu"
#endif

extern struct idevicerestore_client_t* idevicerestore;

#ifdef __cplusplus
}
#endif

#endif
