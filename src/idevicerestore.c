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

#include "tss.h"
#include "img3.h"
#include "ipsw.h"
#include "idevicerestore.h"

#define UNKNOWN_MODE   0
#define RECOVERY_MODE  1
#define NORMAL_MODE    2

int idevicerestore_debug = 0;

void usage(int argc, char* argv[]);
int write_file(const char* filename, char* data, int size);
int send_ibec(char* ipsw, plist_t tss);
int send_devicetree(char* ipsw, plist_t tss);
int send_ramdisk(char* ipsw, plist_t tss);
int send_kernelcache(char* ipsw, plist_t tss);
int get_tss_data(plist_t tss, const char* entry, char** path, char** blob);

int main(int argc, char* argv[]) {
	int opt = 0;
	int mode = 0;
	char* ipsw = NULL;
	char* uuid = NULL;
	uint64_t ecid = 0;
	while ((opt = getopt(argc, argv, "vdhi:u:")) > 0) {
		switch (opt) {
		case 'h':
			usage(argc, argv);
			break;

		case 'v':
			idevicerestore_debug += 1;
			break;

		case 'd':
			idevicerestore_debug = 3;
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

	if (ipsw == NULL) {
		error("ERROR: Please supply an IPSW\n");
		return -1;
	}

	idevice_t device = NULL;
	irecv_client_t recovery = NULL;
	lockdownd_client_t lockdown = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;

	info("Checking for device in normal mode...\n");
	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		info("Checking for the device in recovery mode...\n");
		recovery_error = irecv_open(&recovery);
		if (recovery_error != IRECV_E_SUCCESS) {
			error("ERROR: Unable to find device, is it plugged in?\n");
			return -1;
		}
		info("Found device in recovery mode\n");
		mode = RECOVERY_MODE;

	} else {
		info("Found device in normal mode\n");
		mode = NORMAL_MODE;
	}

	if (mode == NORMAL_MODE) {
		lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
		if (lockdown_error != LOCKDOWN_E_SUCCESS) {
			error("ERROR: Unable to connect to lockdownd\n");
			idevice_free(device);
			return -1;
		}

		plist_t unique_chip_node = NULL;
		lockdown_error = lockdownd_get_value(lockdown, NULL, "UniqueChipID", &unique_chip_node);
		if (lockdown_error != LOCKDOWN_E_SUCCESS) {
			error("ERROR: Unable to get UniqueChipID from lockdownd\n");
			lockdownd_client_free(lockdown);
			idevice_free(device);
			return -1;
		}

		if (!unique_chip_node || plist_get_node_type(unique_chip_node) != PLIST_UINT) {
			error("ERROR: Unable to get ECID\n");
			lockdownd_client_free(lockdown);
			idevice_free(device);
			return -1;
		}

		plist_get_uint_val(unique_chip_node, &ecid);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		lockdown = NULL;
		device = NULL;
	} else if (mode == RECOVERY_MODE) {
		recovery_error = irecv_get_ecid(recovery, &ecid);
		if (recovery_error != IRECV_E_SUCCESS) {
			error("ERROR: Unable to get device ECID\n");
			irecv_close(recovery);
			return -1;
		}
		irecv_close(recovery);
		recovery = NULL;
	}

	if (ecid != 0) {
		info("Found ECID %llu\n", ecid);
	} else {
		error("Unable to find device ECID\n");
		return -1;
	}

	info("Extracting BuildManifest.plist from IPSW\n");
	ipsw_file* buildmanifest = ipsw_extract_file(ipsw, "BuildManifest.plist");
	if (buildmanifest == NULL) {
		error("ERROR: Unable to extract BuildManifest.plist IPSW\n");
		return -1;
	}

	plist_t manifest = NULL;
	plist_from_xml(buildmanifest->data, buildmanifest->size, &manifest);
	ipsw_free_file(buildmanifest);

	info("Creating TSS request\n");
	plist_t tss_request = tss_create_request(manifest, ecid);
	if (tss_request == NULL) {
		error("ERROR: Unable to create TSS request\n");
		plist_free(manifest);
		return -1;
	}
	plist_free(manifest);

	info("Sending TSS request\n");
	plist_t tss_response = tss_send_request(tss_request);
	if (tss_response == NULL) {
		error("ERROR: Unable to get response from TSS server\n");
		plist_free(tss_request);
		return -1;
	}
	plist_free(tss_request);
	info("Got TSS response\n");

	if (mode == NORMAL_MODE) {
		// Place the device in recovery mode
		info("Entering recovery mode...\n");
		device_error = idevice_new(&device, uuid);
		if (device_error != IDEVICE_E_SUCCESS) {
			error("ERROR: Unable to find device\n");
			plist_free(tss_response);
			return -1;
		}

		lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
		if (lockdown_error != LOCKDOWN_E_SUCCESS) {
			error("ERROR: Unable to connect to lockdownd service\n");
			plist_free(tss_response);
			idevice_free(device);
			return -1;
		}

		lockdown_error = lockdownd_enter_recovery(lockdown);
		if (lockdown_error != LOCKDOWN_E_SUCCESS) {
			error("ERROR: Unable to place device in recovery mode\n");
			lockdownd_client_free(lockdown);
			plist_free(tss_response);
			idevice_free(device);
			return -1;
		}

		lockdownd_client_free(lockdown);
		idevice_free(device);
		lockdown = NULL;
		device = NULL;
	}

	if (send_ibec(ipsw, tss_response) < 0) {
		error("ERROR: Unable to send iBEC\n");
		return -1;
	}

	// Reconnect to iBEC
	info("Connecting to iBEC\n");
	recovery_error = irecv_open(&recovery);
	while (recovery_error != IRECV_E_SUCCESS) {
		sleep(1);
		info("Retrying connection...\n");
		recovery_error = irecv_open(&recovery);
		if (recovery_error == IRECV_E_SUCCESS) {
			break;
		}
	}

	// Sending DeviceTree
	info("Extracting DeviceTree from IPSW\n");
	plist_t devicetree_entry = plist_dict_get_item(tss_response, "RestoreDeviceTree");
	if (!devicetree_entry || plist_get_node_type(devicetree_entry) != PLIST_DICT) {
		error("ERROR: Unable to find DeviceTree entry in TSS response\n");
		plist_free(tss_response);
		irecv_close(recovery);
		return -1;
	}

	char* devicetree_path = NULL;
	plist_t devicetree_path_node = plist_dict_get_item(devicetree_entry, "Path");
	if (!devicetree_path_node || plist_get_node_type(devicetree_path_node) != PLIST_STRING) {
		error("ERROR: Unable to find DeviceTree path in entry\n");
		plist_free(tss_response);
		plist_free(devicetree_entry);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}
	plist_get_string_val(devicetree_path_node, &devicetree_path);

	char* devicetree_blob = NULL;
	uint64_t devicetree_blob_size = 0;
	plist_t devicetree_blob_node = plist_dict_get_item(devicetree_entry, "Blob");
	if (!devicetree_blob_node || plist_get_node_type(devicetree_blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find DeviceTree blob in entry\n");
		plist_free(tss_response);
		plist_free(devicetree_entry);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}
	plist_get_data_val(devicetree_blob_node, &devicetree_blob, &devicetree_blob_size);
	plist_free(devicetree_blob_node);
	plist_free(devicetree_entry);

	ipsw_file* devicetree = ipsw_extract_file(ipsw, devicetree_path);
	if (devicetree == NULL) {
		error("ERROR: Unable to extract %s from IPSW\n", devicetree_path);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}

	img3_file* devicetree_img3 = img3_parse_file(devicetree->data, devicetree->size);
	if (devicetree_img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", devicetree_path);
		irecv_close(recovery);
		ipsw_free_file(devicetree);
		recovery = NULL;
		return -1;
	}
	ipsw_free_file(devicetree);

	img3_replace_signature(devicetree_img3, devicetree_blob);
	free(devicetree_blob);

	int devicetree_size = 0;
	char* devicetree_data = NULL;
	img3_get_data(devicetree_img3, &devicetree_data, &devicetree_size);
	write_file("devicetree.img3", devicetree_data, devicetree_size);
	recovery_error = irecv_send_buffer(recovery, devicetree_data, devicetree_size);
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send IMG3: %s\n", devicetree_path);
		irecv_close(recovery);
		img3_free(devicetree_img3);
		recovery = NULL;
		return -1;
	}
	img3_free(devicetree_img3);

	recovery_error = irecv_send_command(recovery, "devicetree");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute DeviceTree\n");
		irecv_close(recovery);
		img3_free(devicetree_img3);
		recovery = NULL;
		return -1;
	}
	free(devicetree_data);
	sleep(1);

	// Sending RestoreRamdisk
	info("Extracting Ramdisk from IPSW\n");
	plist_t ramdisk_entry = plist_dict_get_item(tss_response, "RestoreRamDisk");
	if (!ramdisk_entry || plist_get_node_type(ramdisk_entry) != PLIST_DICT) {
		error("ERROR: Unable to find RestoreRamDisk entry in TSS response\n");
		plist_free(tss_response);
		irecv_close(recovery);
		return -1;
	}

	char* ramdisk_path = NULL;
	plist_t ramdisk_path_node = plist_dict_get_item(ramdisk_entry, "Path");
	if (!ramdisk_path_node || plist_get_node_type(ramdisk_path_node) != PLIST_STRING) {
		error("ERROR: Unable to find RestoreRamDisk path in entry\n");
		plist_free(tss_response);
		plist_free(ramdisk_entry);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}
	plist_get_string_val(ramdisk_path_node, &ramdisk_path);

	char* ramdisk_blob = NULL;
	uint64_t ramdisk_blob_size = 0;
	plist_t ramdisk_blob_node = plist_dict_get_item(ramdisk_entry, "Blob");
	if (!ramdisk_blob_node || plist_get_node_type(ramdisk_blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find RestoreRamdisk blob in entry\n");
		plist_free(tss_response);
		plist_free(ramdisk_entry);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}
	plist_get_data_val(ramdisk_blob_node, &ramdisk_blob, &ramdisk_blob_size);
	plist_free(ramdisk_blob_node);
	plist_free(ramdisk_entry);

	ipsw_file* ramdisk = ipsw_extract_file(ipsw, ramdisk_path);
	if (ramdisk == NULL) {
		error("ERROR: Unable to extract %s from IPSW\n", ramdisk_path);
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}

	img3_file* ramdisk_img3 = img3_parse_file(ramdisk->data, ramdisk->size);
	if (ramdisk_img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", ramdisk_path);
		irecv_close(recovery);
		ipsw_free_file(ramdisk);
		recovery = NULL;
		return -1;
	}
	ipsw_free_file(ramdisk);

	img3_replace_signature(ramdisk_img3, ramdisk_blob);
	free(ramdisk_blob);

	int ramdisk_size = 0;
	char* ramdisk_data = NULL;
	img3_get_data(ramdisk_img3, &ramdisk_data, &ramdisk_size);
	write_file("ramdisk.dmg", ramdisk_data, ramdisk_size);
	recovery_error = irecv_send_buffer(recovery, ramdisk_data, ramdisk_size);
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send IMG3: %s\n", ramdisk_path);
		irecv_close(recovery);
		img3_free(ramdisk_img3);
		recovery = NULL;
		return -1;
	}
	img3_free(ramdisk_img3);

	recovery_error = irecv_send_command(recovery, "ramdisk");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute DeviceTree\n");
		irecv_close(recovery);
		recovery = NULL;
		return -1;
	}
	free(ramdisk_data);
	irecv_close(recovery);
	recovery = NULL;

	printf("Please unplug your device, then plug it back in, hit any key to continue\n");
	getchar();

	// Reconnect to iBEC
	recovery_error = irecv_open(&recovery);
	while (recovery_error != IRECV_E_SUCCESS) {
		sleep(1);
		info("Retrying connection...\n");
		recovery_error = irecv_open(&recovery);
		if (recovery_error == IRECV_E_SUCCESS) {
			break;
		}
	}

	irecv_close(recovery);
	recovery = NULL;
	plist_free(tss_response);
	return 0;
}

void usage(int argc, char* argv[]) {
	char *name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS]\n", (name ? name + 1 : argv[0]));
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

int write_file(const char* filename, char* data, int size) {
	debug("Writing data to %s\n", filename);
	FILE* file = fopen(filename, "wb");
	if (file == NULL) {
		error("read_file: Unable to open file %s\n", filename);
		return -1;
	}

	int bytes = fwrite(data, 1, size, file);
	fclose(file);

	if (bytes != size) {
		error("ERROR: Unable to write entire file: %s: %d %d\n", filename, bytes, size);
		return -1;
	}

	return size;
}

int get_tss_data(plist_t tss, const char* entry, char** ppath, char** pblob) {
	*ppath = NULL;
	*pblob = NULL;

	plist_t node = plist_dict_get_item(tss, entry);
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to find %s entry in TSS response\n", entry);
		return -1;
	}

	char* path = NULL;
	plist_t path_node = plist_dict_get_item(node, "Path");
	if (!path_node || plist_get_node_type(path_node) != PLIST_STRING) {
		error("ERROR: Unable to find %s path in entry\n", entry);
		plist_free(node);
		return -1;
	}
	plist_get_string_val(path_node, &path);
	plist_free(path_node);

	char* blob = NULL;
	uint64_t blob_size = 0;
	plist_t blob_node = plist_dict_get_item(node, "Blob");
	if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find %s blob in entry\n", entry);
		plist_free(node);
		free(path);
		return -1;
	}

	plist_get_data_val(blob_node, &blob, &blob_size);
	plist_free(blob_node);
	plist_free(node);

	*ppath = path;
	*pblob = blob;
	return 0;
}

int send_ibec(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_client_t client = NULL;
	info("Connecting to iBoot...\n");
	irecv_error_t error = irecv_open(&client);
	for (i = 10; i > 0; i--) {
		if (error == IRECV_E_SUCCESS) {
			irecv_send_command(client, "setenv auto-boot true");
			irecv_send_command(client, "saveenv");
			break;
		}
		sleep(1);
		info("Retrying connection...\n");
		error = irecv_open(&client);
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting iBEC data from TSS response\n");
	if (get_tss_data(tss, "iBEC", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	info("Extracting %s from %s\n", path, ipsw);
	ipsw_file* ibec = ipsw_extract_file(ipsw, path);
	if (ibec == NULL) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(ibec->data, ibec->size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		ipsw_free_file(ibec);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}
	if (ibec) {
		ipsw_free_file(ibec);
		ibec = NULL;
	}

	if (img3_replace_signature(img3, blob) < 0) {
		error("ERROR: Unable to replace IMG3 signature\n");
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}
	if (blob) {
		free(blob);
		blob = NULL;
	}

	int size = 0;
	char* data = NULL;
	if (img3_get_data(img3, &data, &size) < 0) {
		error("ERROR: Unable to reconstruct IMG3\n");
		irecv_close(client);
		img3_free(img3);
		client = NULL;
		free(path);
		return -1;
	}

	path = strrchr(path, '/');
	write_file(path + 1, data, size);
	error = irecv_send_buffer(client, data, size);
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send IMG3: %s\n", path);
		irecv_close(client);
		img3_free(img3);
		client = NULL;
		free(data);
		free(path);
		return -1;
	}
	if (img3) {
		img3_free(img3);
		img3 = NULL;
	}
	if (data) {
		free(data);
		data = NULL;
	}
	if (path) {
		free(path);
		path = NULL;
	}

	error = irecv_send_command(client, "go");
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute iBEC\n");
		irecv_close(client);
		client = NULL;
		free(data);
		return -1;
	}

	irecv_close(client);
	client = NULL;
	return 0;
}

int send_devicetree(char* ipsw, plist_t tss) {
	int i = 0;
	info("Sending devicetree\n");
	irecv_client_t client = NULL;
	irecv_error_t error = irecv_open(&client);
	for (i = 10; i > 0; i--) {
		if (error == IRECV_E_SUCCESS) {
			break;
		}
		sleep(1);
		info("Retrying connection...\n");
		error = irecv_open(&client);
	}

	irecv_close(client);
	return 0;
}

int send_ramdisk(char* ipsw, plist_t tss) {
	int i = 0;
	info("Sending ramdisk\n");
	irecv_client_t client = NULL;
	irecv_error_t error = irecv_open(&client);
	for (i = 10; i > 0; i--) {
		if (error == IRECV_E_SUCCESS) {
			break;
		}
		sleep(1);
		info("Retrying connection...\n");
		error = irecv_open(&client);
	}

	irecv_close(client);
	return 0;
}

int send_kernelcache(char* ipsw, plist_t tss) {
	int i = 0;
	info("Sending kernelcache\n");
	irecv_client_t client = NULL;
	irecv_error_t error = irecv_open(&client);
	for (i = 10; i > 0; i--) {
		if (error == IRECV_E_SUCCESS) {
			break;
		}
		sleep(1);
		info("Retrying connection...\n");
		error = irecv_open(&client);
	}

	irecv_close(client);
	return 0;
}
