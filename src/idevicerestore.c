/*
 * idevicerestore.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <plist/plist.h>
#include <libirecovery.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>

#include "ipsw.h"

#define error(...) fprintf(stderr, __VA_ARGS__)
#define info(...) if(verbose >= 1) fprintf(stderr, __VA_ARGS__)
#define debug(...) if(verbose >= 2) fprintf(stderr, __VA_ARGS__)

#define UNKNOWN_MODE   0
#define RECOVERY_MODE  1
#define NORMAL_MODE    2

static int verbose = 0;

void usage(int argc, char* argv[]);

int main(int argc, char* argv[]) {
	int opt = 0;
	int mode = 0;
	char* ipsw = NULL;
	char* uuid = NULL;
	while ((opt = getopt(argc, argv, "vdhi:u:")) > 0) {
		switch (opt) {
		case 'h':
			usage(argc, argv);
			break;

		case 'v':
			verbose += 1;
			break;

		case 'd':
			verbose = 3;
			break;

		case 'i':
			ipsw = optarg;
			break;

		case 'u':
			uuid = optarg;
			break;

		default:
			usage(argc, argv);
			break;
		}
	}

	if(ipsw == NULL) {
		error("ERROR: Please supply an IPSW\n");
		return -1;
	}

	idevice_t device = NULL;
	irecv_device_t* recovery = NULL;
	irecv_error_t recovery_error = IRECV_SUCCESS;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	info("Checking for device in normal mode\n");
	if(uuid != NULL) {
		device_error = idevice_new(&device, uuid);
		if(device_error != IDEVICE_E_SUCCESS) {
			info("Unable to find device in normal mode\n");
			recovery = irecv_init();
			recovery_error = irecv_open(recovery, uuid);
			if(recovery_error != IRECV_SUCCESS) {
				info("Unable to find device in recovery mode\n");
				error("ERROR: Unable to find device, is it plugged in?\n");
				irecv_exit(recovery);
				return -1;
			}
			info("Found device in recovery mode\n");
			mode = RECOVERY_MODE;

		} else {
			info("Found device in normal mode\n");
			mode = NORMAL_MODE;
		}

	} else {
		device_error = idevice_new(&device, NULL);
		if(device_error != IDEVICE_E_SUCCESS) {
			info("Unable to find device in normal mode\n");
			recovery = irecv_init();
			recovery_error = irecv_open(recovery, NULL);
			if(recovery_error != IRECV_SUCCESS) {
				info("Unable to find device in recovery mode\n");
				error("ERROR: Unable to find device, is it plugged in?\n");
				irecv_exit(recovery);
				return -1;
			}
			info("Found device in recovery mode\n");
			mode = RECOVERY_MODE;

		} else {
			info("Found device in normal mode\n");
			mode = NORMAL_MODE;
		}
	}

	info("Extracting BuildManifest.plist from IPSW\n");
	ipsw_archive* archive = ipsw_open(ipsw);
	ipsw_file* buildmanifest = ipsw_extract_file(archive, "BuildManifest.plist");
	if(buildmanifest == NULL) {
		error("ERRPR: Unable to extract BuildManifest.plist IPSW\n");
		ipsw_close(archive);
		return -1;
	}

	plist_t manifest = NULL;
	plist_from_xml(buildmanifest->data, buildmanifest->size, &manifest);
	ipsw_free_file(buildmanifest);
	ipsw_close(archive);

	info("Creating TSS request\n");
	plist_t tss_request = tss_create_request(manifest);
	if(tss_request == NULL) {
		error("ERROR: Unable to create TSS request\n");
		plist_free(manifest);
		return -1;
	}

	plist_free(manifest);
	return 0;
}

void usage(int argc, char* argv[]) {
	char *name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS]\n", (name ? name + 1: argv[0]));
	printf("Restore firmware and filesystem to iPhone/iPod Touch.\n");
	printf("  -d, \t\tenable communication debugging\n");
	printf("  -v, \t\tenable incremental levels of verboseness\n");
	//printf("  -r, \t\tput device into recovery mode\n");
	printf("  -i, \t\ttarget filesystem to install onto device\n");
	printf("  -u, \t\ttarget specific device by its 40-digit device UUID\n");
	printf("  -h, \t\tprints usage information\n");
	printf("\n");
	exit(1);
}
