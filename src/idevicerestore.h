/*
 * idevicerestore.g
 * Restore device firmware and filesystem
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

#ifndef IDEVICERESTORE_H
#define IDEVICERESTORE_H

#include <stdint.h>
#include <plist/plist.h>

#define info(...) printf(__VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)
#define debug(...) if(idevicerestore_debug >= 1) fprintf(stderr, __VA_ARGS__)

#define IPHONE2G_CPID    8900
#define IPHONE3G_CPID    8900
#define IPHONE3GS_CPID   8920
#define IPOD1G_CPID      8900
#define IPOD2G_CPID      8720
#define IPOD3G_CPID      8922
#define IPAD1G_CPID      8930

#define IPHONE2G_BDID       0
#define IPHONE3G_BDID       4
#define IPHONE3GS_BDID      0
#define IPOD1G_BDID         2
#define IPOD2G_BDID         0
#define IPOD3G_BDID         2
#define IPAD1G_BDID         2

typedef enum {
	UNKNOWN_MODE =       -1,
	DFU_MODE =            0,
	RECOVERY_MODE =       1,
	RESTORE_MODE =        2,
	NORMAL_MODE =         3,
} idevicerestore_mode_t;

typedef enum {
	UNKNOWN_DEVICE =     -1,
	IPHONE2G_DEVICE =     0,
	IPHONE3G_DEVICE =     1,
	IPOD1G_DEVICE =       2,
	IPOD2G_DEVICE =       3,
	IPHONE3GS_DEVICE =    4,
	IPOD3G_DEVICE =       5,
	IPAD1G_DEVICE =       6
} idevicerestore_device_t;

static char* idevicerestore_products[] = {
	"iPhone1,1",
	"iPhone1,2",
	"iPhone2,1",
	"iPod1,1",
	"iPod2,1",
	"iPod3,1",
	"iPad1,1",
	NULL
};

extern int idevicerestore_quit;
extern int idevicerestore_debug;
extern int idevicerestore_erase;
extern int idevicerestore_custom;
extern int idevicerestore_exclude;
extern int idevicerestore_verbose;
extern idevicerestore_mode_t idevicerestore_mode;
extern idevicerestore_device_t idevicerestore_device;

int check_mode(const char* uuid);
int check_device(const char* uuid);
void usage(int argc, char* argv[]);
int get_ecid(const char* uuid, uint64_t* ecid);
int get_bdid(const char* uuid, uint32_t* bdid);
int get_cpid(const char* uuid, uint32_t* cpid);
int extract_buildmanifest(const char* ipsw, plist_t* buildmanifest);
plist_t get_build_identity(plist_t buildmanifest, uint32_t identity);
int write_file(const char* filename, const void* data, size_t size);
int get_shsh_blobs(uint64_t ecid, plist_t build_identity, plist_t* tss);
int extract_filesystem(const char* ipsw, plist_t buildmanifest, char** filesystem);
int get_signed_component(char* ipsw, plist_t tss, const char* path, char** data, uint32_t* size);


#endif
