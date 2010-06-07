/*
 * idevicerestore.h
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

#include <stdio.h>
#include <stdlib.h>
#include <plist/plist.h>

#define info(...) printf(__VA_ARGS__)
#define error(...) fprintf(stderr, __VA_ARGS__)
#define debug(...) if(idevicerestore_debug >= 1) fprintf(stderr, __VA_ARGS__)

#define MODE_UNKNOWN        -1
#define MODE_DFU             0
#define MODE_RECOVERY        1
#define MODE_RESTORE         2
#define MODE_NORMAL          3

#define CPID_UNKNOWN        -1
#define CPID_IPHONE2G     8900
#define CPID_IPOD1G       8900
#define CPID_IPHONE3G     8900
#define CPID_IPOD2G       8720
#define CPID_IPHONE3GS    8920
#define CPID_IPOD3G       8922
#define CPID_IPAD1G       8930

#define BDID_UNKNOWN        -1
#define BDID_IPHONE2G        0
#define BDID_IPOD1G          2
#define BDID_IPHONE3G        4
#define BDID_IPOD2G          0
#define BDID_IPHONE3GS       0
#define BDID_IPOD3G          2
#define BDID_IPAD1G          2

#define DEVICE_UNKNOWN      -1
#define DEVICE_IPHONE2G      0
#define DEVICE_IPOD1G        1
#define DEVICE_IPHONE3G      2
#define DEVICE_IPOD2G        3
#define DEVICE_IPHONE3GS     4
#define DEVICE_IPOD3G        5
#define DEVICE_IPAD1G        6

typedef struct {
	int device_id;
	const char* product;
	const char* model;
	int board_id;
	int chip_id;
} idevicerestore_device_t;

static idevicerestore_device_t idevicerestore_devices[] = {
	{  0, "iPhone1,1", "M68AP",  0,  8900 },
	{  1, "iPod1,1",   "N45AP",  2,  8900 },
	{  2, "iPhone1,2", "N82AP",  4,  8900 },
	{  3, "iPod2,1",   "N72AP",  0,  8720 },
	{  4, "iPhone2,1", "N88AP",  0,  8920 },
	{  5, "iPod3,1",   "N18AP",  2,  8922 },
	{  6, "iPad1,1",   "K48AP",  2,  8930 },
	{ -1,  NULL,        NULL,   -1,    -1 }
};

extern int idevicerestore_mode;
extern int idevicerestore_quit;
extern int idevicerestore_debug;
extern int idevicerestore_erase;
extern int idevicerestore_custom;
extern int idevicerestore_exclude;
extern int idevicerestore_verbose;
extern idevicerestore_device_t* idevicerestore_device;

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
int get_signed_component(const char* ipsw, plist_t tss, const char* path, char** data, uint32_t* size);

inline static void debug_plist(plist_t plist) {
	int size = 0;
	char* data = NULL;
	plist_to_xml(plist, &data, &size);
	debug("%s", data);
	free(data);
}

inline static void print_progress_bar(const char* operation, double progress) {
	int i = 0;
	if(progress < 0) return;
	if(progress > 100) progress = 100;
	info("\r%s [", operation);
	for(i = 0; i < 50; i++) {
		if(i < progress / 2) info("=");
		else info(" ");
	}
	info("] %3.1f%%", progress);
	if(progress == 100) info("\n");
	fflush(stdout);
}

#endif
