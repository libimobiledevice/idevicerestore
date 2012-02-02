/*
 * restore.c
 * Functions for handling idevices in restore mode
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
#include <libimobiledevice/restore.h>

#include "asr.h"
#include "tss.h"
#include "common.h"
#include "restore.h"

#define WAIT_FOR_STORAGE       11
#define CREATE_PARTITION_MAP   12
#define CREATE_FILESYSTEM      13
#define RESTORE_IMAGE          14
#define VERIFY_RESTORE         15
#define CHECK_FILESYSTEM       16
#define MOUNT_FILESYSTEM       17
#define FLASH_NOR              19
#define UPDATE_BASEBAND        20
#define FINIALIZE_NAND         21
#define MODIFY_BOOTARGS        26
#define LOAD_KERNEL_CACHE      27
#define PARTITION_NAND_DEVICE  28
#define WAIT_FOR_NAND          29
#define UNMOUNT_FILESYSTEM     30
#define WAIT_FOR_DEVICE        33
#define LOAD_NOR               36

#define CREATE_SYSTEM_KEY_BAG  49

static int restore_finished = 0;

static int restore_device_connected = 0;

int restore_client_new(struct idevicerestore_client_t* client) {
	struct restore_client_t* restore = (struct restore_client_t*) malloc(sizeof(struct restore_client_t));
	if (restore == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}

	if (restore_open_with_timeout(client) < 0) {
		restore_client_free(client);
		return -1;
	}

	client->restore = restore;
	return 0;
}

void restore_client_free(struct idevicerestore_client_t* client) {
	if (client) {
		if(client->restore) {
			if(client->restore->client) {
				restored_client_free(client->restore->client);
				client->restore->client = NULL;
			}
			if(client->restore->device) {
				idevice_free(client->restore->device);
				client->restore->device = NULL;
			}
			free(client->restore);
			client->restore = NULL;
		}
	}
}

int restore_check_mode(const char* uuid) {
	char* type = NULL;
	uint64_t version = 0;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_free(device);
		return -1;
	}

	restore_error = restored_query_type(restore, &type, &version);
	if (restore_error != RESTORE_E_SUCCESS) {
		restored_client_free(restore);
		idevice_free(device);
		return -1;
	}

	restored_client_free(restore);
	idevice_free(device);
	restore = NULL;
	device = NULL;
	return 0;
}

int restore_check_device(const char* uuid) {
	int i = 0;
	char* type = NULL;
	char* model = NULL;
	plist_t node = NULL;
	uint64_t version = 0;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_free(device);
		return -1;
	}

	restore_error = restored_query_type(restore, &type, &version);
	if (restore_error != RESTORE_E_SUCCESS) {
		restored_client_free(restore);
		idevice_free(device);
		return -1;
	}

	restore_error = restored_get_value(restore, "HardwareModel", &node);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to get HardwareModel from restored\n");
		restored_client_free(restore);
		idevice_free(device);
		return -1;
	}

	restored_client_free(restore);
	idevice_free(device);
	restore = NULL;
	device = NULL;

	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to get HardwareModel information\n");
		if (node)
			plist_free(node);
		return -1;
	}
	plist_get_string_val(node, &model);

	for (i = 0; idevicerestore_devices[i].model != NULL; i++) {
		if (!strcasecmp(model, idevicerestore_devices[i].model)) {
			break;
		}
	}

	return idevicerestore_devices[i].index;
}

void restore_device_callback(const idevice_event_t* event, void* userdata) {
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) userdata;
	if (event->event == IDEVICE_DEVICE_ADD) {
		restore_device_connected = 1;
		client->uuid = strdup(event->uuid);
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		restore_device_connected = 0;
		client->flags |= FLAG_QUIT;
	}
}

int restore_reboot(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	if(client->restore == NULL) {
		if (restore_open_with_timeout(client) < 0) {
			error("ERROR: Unable to open device in restore mode\n");
			return -1;
		}
	}

	restored_reboot(client->restore->client);

	// FIXME: wait for device disconnect here

	return 0;
}

int restore_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 20;
	char *type = NULL;
	uint64_t version = 0;
	idevice_t device = NULL;
	restored_client_t restored = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	// no context exists so bail
	if(client == NULL) {
		return -1;
	}

	// create our restore client if it doesn't yet exist
	if(client->restore == NULL) {
		client->restore = (struct restore_client_t*) malloc(sizeof(struct restore_client_t));
		if(client->restore == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
		memset(client->restore, '\0', sizeof(struct restore_client_t));
	}

	info("waiting for device...\n");
	sleep(15);
	info("trying to connect...\n");
	for (i = 0; i < attempts; i++) {
		device_error = idevice_new(&device, client->uuid);
		if (device_error == IDEVICE_E_SUCCESS) {
			restore_error = restored_client_new(device, &restored, "idevicerestore");
			if (restore_error == RESTORE_E_SUCCESS) {
				restore_error = restored_query_type(restored, &type, &version);
				if ((restore_error == RESTORE_E_SUCCESS) && type && (strcmp(type, "com.apple.mobile.restored") == 0)) {
					debug("Connected to %s, version %d\n", type, (int)version);
					restore_device_connected = 1;
				} else {
					error("ERROR: Unable to connect to restored, error=%d\n", restore_error);
				}
			}
			restored_client_free(restored);
			idevice_free(device);
		} else {
			printf("%d\n", device_error);
		}

		if (restore_device_connected == 1) {
			break;
		}

		if (i == attempts) {
			error("ERROR: Unable to connect to device in restore mode\n");
			return -1;
		}

		sleep(2);
	}

	if (!restore_device_connected) {
		error("hm... could not connect\n");
		return -1;
	}

	info("Connecting now\n");
	device_error = idevice_new(&device, client->uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(device, &restored, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		//idevice_event_unsubscribe();
		idevice_free(device);
		return -1;
	}

	restore_error = restored_query_type(restored, &type, &version);
	if ((restore_error == RESTORE_E_SUCCESS) && type && (strcmp(type, "com.apple.mobile.restored") == 0)) {
		client->restore->protocol_version = version;
		info("Connected to %s, version %d\n", type, (int)version);
	} else {
		error("ERROR: Unable to connect to restored, error=%d\n", restore_error);
		restored_client_free(restored);
		//idevice_event_unsubscribe();
		idevice_free(device);
		return -1;
	}

	client->restore->device = device;
	client->restore->client = restored;
	return 0;
}

const char* restore_progress_string(unsigned int operation) {
	switch (operation) {
	case WAIT_FOR_STORAGE:
		return "Waiting for storage device";

	case CREATE_PARTITION_MAP:
		return "Creating partition map";

	case CREATE_FILESYSTEM:
		return "Creating filesystem";

	case RESTORE_IMAGE:
		return "Restoring image";

	case VERIFY_RESTORE:
		return "Verifying restore";

	case CHECK_FILESYSTEM:
		return "Checking filesystems";

	case MOUNT_FILESYSTEM:
		return "Mounting filesystems";

	case FLASH_NOR:
		return "Flashing NOR";

	case UPDATE_BASEBAND:
		return "Updating baseband";

	case FINIALIZE_NAND:
		return "Finalizing NAND epoch update";

	case MODIFY_BOOTARGS:
		return "Modifying persistent boot-args";

	case UNMOUNT_FILESYSTEM:
		return "Unmounting filesystems";

	case PARTITION_NAND_DEVICE:
		return "Partition NAND device";

	case WAIT_FOR_NAND:
		return "Waiting for NAND";

	case WAIT_FOR_DEVICE:
		return "Waiting for device";

	case LOAD_KERNEL_CACHE:
		return "Loading kernelcache";

	case LOAD_NOR:
		return "Loading NOR data to flash";

	default:
		return "Unknown operation";
	}
}

static int lastop = 0;

int restore_handle_progress_msg(restored_client_t client, plist_t msg) {
	plist_t node = NULL;
	uint64_t progress = 0;
	uint64_t operation = 0;

	node = plist_dict_get_item(msg, "Operation");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		debug("Failed to parse operation from ProgressMsg plist\n");
		return -1;
	}
	plist_get_uint_val(node, &operation);

	node = plist_dict_get_item(msg, "Progress");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		debug("Failed to parse progress from ProgressMsg plist \n");
		return -1;
	}
	plist_get_uint_val(node, &progress);

	if ((progress > 0) && (progress < 100)) {
		if (operation != lastop) {
			info("%s (%d)\n", restore_progress_string(operation), (int)operation);
		}
		print_progress_bar((double) progress);
	} else {
		info("%s (%d)\n", restore_progress_string(operation), (int)operation);
	}
	lastop = operation;

	return 0;
}

int restore_handle_status_msg(restored_client_t client, plist_t msg) {
	uint64_t value = 0;
	info("Got status message\n");
	debug_plist(msg);

	plist_t node = plist_dict_get_item(msg, "Status");
	plist_get_uint_val(node, &value);

	switch(value) {
		case 0:
			info("Status: Restore Finished\n");
			restore_finished = 1;
			break;
		case 6:
			info("Status: Disk Failure\n");
			break;
		case 14:
			info("Status: Fail\n");
			break;
		default:
			info("Unknown status message.\n");
	}

	return 0;
}

int restore_send_filesystem(idevice_t device, const char* filesystem) {
	int i = 0;
	FILE* file = NULL;
	plist_t data = NULL;
	idevice_connection_t asr = NULL;
	idevice_error_t device_error = IDEVICE_E_UNKNOWN_ERROR;

	if (asr_open_with_timeout(device, &asr) < 0) {
		error("ERROR: Unable to connect to ASR\n");
		return -1;
	}
	info("Connected to ASR\n");

	/* receive Initiate command message */
	if (asr_receive(asr, &data) < 0) {
		error("ERROR: Unable to receive data from ASR\n");
		asr_close(asr);
		return -1;
	}
	plist_free(data);

	// this step sends requested chunks of data from various offsets to asr so
	// it can validate the filesystem before installing it
	info("Validating the filesystem\n");
	if (asr_perform_validation(asr, filesystem) < 0) {
		error("ERROR: ASR was unable to validate the filesystem\n");
		asr_close(asr);
		return -1;
	}
	info("Filesystem validated\n");

	// once the target filesystem has been validated, ASR then requests the
	// entire filesystem to be sent.
	info("Sending filesystem now...\n");
	if (asr_send_payload(asr, filesystem) < 0) {
		error("ERROR: Unable to send payload to ASR\n");
		asr_close(asr);
		return -1;
	}
	info("Filesystem sent\n");

	asr_close(asr);
	return 0;
}

int restore_send_root_ticket(restored_client_t restore, struct idevicerestore_client_t* client)
{
	restored_error_t restore_error;
	plist_t dict;
	unsigned char* data = NULL;
	uint32_t len = 0;

	if (!client->tss && !(client->flags & FLAG_CUSTOM)) {
		error("ERROR: Cannot send RootTicket without TSS\n");
		return -1;
	}

	if (!(client->flags & FLAG_CUSTOM) && (tss_get_ticket(client->tss, &data, &len) < 0)) {
		error("ERROR: Unable to get ticket from TSS\n");
		return -1;
	}

	dict = plist_new_dict();
	if (data && (len > 0)) {
		plist_dict_insert_item(dict, "RootTicketData", plist_new_data(data, (uint64_t)len));
	} else {
		info("NOTE: not sending RootTicketData (no data present)\n");
	}

	restore_error = restored_send(restore, dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send RootTicket (%d)\n", restore_error);
		plist_free(dict);
		return -1;
	}

	info("Done sending RootTicket\n");
	plist_free(dict);
	free(data);
	return 0;
}

int restore_send_kernelcache(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity) {
	int size = 0;
	char* data = NULL;
	char* path = NULL;
	plist_t blob = NULL;
	plist_t dict = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	info("Sending kernelcache\n");

	if (client->tss) {
		if (tss_get_entry_path(client->tss, "KernelCache", &path) < 0) {
			debug("NOTE: No path for component KernelCache in TSS, will fetch from build_identity\n");
		}
	}
	if (!path) {
		if (build_identity_get_component_path(build_identity, "KernelCache", &path) < 0) {
			error("ERROR: Unable to find kernelcache path\n");
			if (path)
				free(path);
			return -1;
		}
	}

	if (ipsw_get_component_by_path(client->ipsw, client->tss, "KernelCache", path, &data, &size) < 0) {
		error("ERROR: Unable to get kernelcache file\n");
		return -1;
	}

	dict = plist_new_dict();
	blob = plist_new_data(data, size);
	plist_dict_insert_item(dict, "KernelCacheFile", blob);

	restore_error = restored_send(restore, dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		plist_free(dict);
		return -1;
	}

	info("Done sending kernelcache\n");
	plist_free(dict);
	free(data);
	return 0;
}

int restore_send_nor(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity) {
	char* llb_path = NULL;
	char* llb_filename = NULL;
	char firmware_path[256];
	char manifest_file[256];
	int manifest_size = 0;
	char* manifest_data = NULL;
	char firmware_filename[256];
	int llb_size = 0;
	char* llb_data = NULL;
	plist_t dict = NULL;
	char* filename = NULL;
	int nor_size = 0;
	char* nor_data = NULL;
	plist_t norimage_array = NULL;
	restored_error_t ret = RESTORE_E_SUCCESS;

	if (client->tss) {
		if (tss_get_entry_path(client->tss, "LLB", &llb_path) < 0) {
			debug("NOTE: could not get LLB path from TSS data, will fetch from build identity\n");
		}
	}
	if (llb_path == NULL) {
		if (build_identity_get_component_path(build_identity, "LLB", &llb_path) < 0) {
			error("ERROR: Unable to get component path for LLB\n");
			if (llb_path)
				free(llb_path);
			return -1;
		}
	}

	llb_filename = strstr(llb_path, "LLB");
	if (llb_filename == NULL) {
		error("ERROR: Unable to extract firmware path from LLB filename\n");
		free(llb_path);
		return -1;
	}

	memset(firmware_path, '\0', sizeof(firmware_path));
	memcpy(firmware_path, llb_path, (llb_filename - 1) - llb_path);
	info("Found firmware path %s\n", firmware_path);

	memset(manifest_file, '\0', sizeof(manifest_file));
	snprintf(manifest_file, sizeof(manifest_file), "%s/manifest", firmware_path);
	info("Getting firmware manifest %s\n", manifest_file);

	if (ipsw_extract_to_memory(client->ipsw, manifest_file, &manifest_data, &manifest_size) < 0) {
		error("ERROR: Unable to extract firmware manifest from ipsw\n");
		free(llb_path);
		return -1;
	}

	dict = plist_new_dict();

	if (ipsw_get_component_by_path(client->ipsw, client->tss, "LLB", llb_path, &llb_data, &llb_size) < 0) {
		error("ERROR: Unable to get signed LLB\n");
		return -1;
	}

	plist_dict_insert_item(dict, "LlbImageData", plist_new_data(llb_data, (uint64_t) llb_size));

	norimage_array = plist_new_array();

	filename = strtok(manifest_data, "\r\n");
	while (filename != NULL) {
		if (!strncmp("LLB", filename, 3)) {
			// skip LLB, it's already passed in LlbImageData
			filename = strtok(NULL, "\r\n");
			continue;
		}
		memset(firmware_filename, '\0', sizeof(firmware_filename));
		snprintf(firmware_filename, sizeof(firmware_filename), "%s/%s", firmware_path, filename);
		if (ipsw_get_component_by_path(client->ipsw, client->tss, get_component_name(filename), firmware_filename, &nor_data, &nor_size) < 0) {
			error("ERROR: Unable to get signed firmware file %s\n", firmware_filename);
			break;
		}

		plist_array_append_item(norimage_array, plist_new_data(nor_data, (uint64_t)nor_size));
		free(nor_data);
		nor_data = NULL;
		nor_size = 0;
		filename = strtok(NULL, "\r\n");
	}
	plist_dict_insert_item(dict, "NorImageData", norimage_array);

	if (idevicerestore_debug)
		debug_plist(dict);

	ret = restored_send(restore, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send NORImageData data\n");
		plist_free(dict);
		return -1;
	}

	plist_free(dict);
	return 0;
}

int restore_handle_data_request_msg(struct idevicerestore_client_t* client, idevice_t device, restored_client_t restore, plist_t message, plist_t build_identity, const char* filesystem) {
	char* type = NULL;
	plist_t node = NULL;

	// checks and see what kind of data restored is requests and pass
	// the request to its own handler
	node = plist_dict_get_item(message, "DataType");
	if (node && PLIST_STRING == plist_get_node_type(node)) {
		plist_get_string_val(node, &type);

		// this request is sent when restored is ready to receive the filesystem
		if (!strcmp(type, "SystemImageData")) {
			if(restore_send_filesystem(device, filesystem) < 0) {
				error("ERROR: Unable to send filesystem\n");
				return -1;
			}
		}

		// send RootTicket (== APTicket from the TSS request)
		else if (!strcmp(type, "RootTicket")) {
			if (restore_send_root_ticket(restore, client) < 0) {
				error("ERROR: Unable to send RootTicket\n");
				return -1;
			}
		}
		// send KernelCache
		else if (!strcmp(type, "KernelCache")) {
			if(restore_send_kernelcache(restore, client, build_identity) < 0) {
				error("ERROR: Unable to send kernelcache\n");
				return -1;
			}
		}

		else if (!strcmp(type, "NORData")) {
			if((client->flags & FLAG_EXCLUDE) == 0) {
				info("Sending NORData\n");
				if(restore_send_nor(restore, client, build_identity) < 0) {
					error("ERROR: Unable to send NOR data\n");
					return -1;
				}
			} else {
				info("Not sending NORData... Quitting...\n");
				client->flags |= FLAG_QUIT;
			}

		} else {
			// Unknown DataType!!
			error("Unknown data request '%s' received\n", type);
			if (idevicerestore_debug)
				debug_plist(message);
		}
	}
	return 0;
}

int restore_device(struct idevicerestore_client_t* client, plist_t build_identity, const char* filesystem) {
	int error = 0;
	char* type = NULL;
	char* kernel = NULL;
	plist_t node = NULL;
	plist_t message = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	restore_finished = 0;

	// open our connection to the device and verify we're in restore mode
	if (restore_open_with_timeout(client) < 0) {
		error("ERROR: Unable to open device in restore mode\n");
		return -1;
	}
	info("Device has successfully entered restore mode\n");

	restore = client->restore->client;
	device = client->restore->device;

	plist_t opts = plist_new_dict();
	// FIXME: required?
	//plist_dict_insert_item(opts, "AuthInstallRestoreBehavior", plist_new_string("Erase"));
	plist_dict_insert_item(opts, "AutoBootDelay", plist_new_uint(0));
	// FIXME: new on iOS 5 ?
	plist_dict_insert_item(opts, "BootImageType", plist_new_string("UserOrInternal"));
	// FIXME: required?
	//plist_dict_insert_item(opts, "BootImageFile", plist_new_string("018-7923-347.dmg"));
	plist_dict_insert_item(opts, "CreateFilesystemPartitions", plist_new_bool(1));
	plist_dict_insert_item(opts, "DFUFileType", plist_new_string("RELEASE"));
	plist_dict_insert_item(opts, "DataImage", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "DeviceTreeFile", plist_new_string("DeviceTree.k48ap.img3"));
	plist_dict_insert_item(opts, "FirmwareDirectory", plist_new_string("."));
	// FIXME: usable if false? (-x parameter)
	plist_dict_insert_item(opts, "FlashNOR", plist_new_bool(1));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "KernelCacheFile", plist_new_string("kernelcache.release.k48"));
	// FIXME: new on iOS 5 ?
	plist_dict_insert_item(opts, "KernelCacheType", plist_new_string("Release"));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "NORImagePath", plist_new_string("."));
	// FIXME: new on iOS 5 ?
	plist_dict_insert_item(opts, "NORImageType", plist_new_string("production"));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "PersonalizedRestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	if (client->restore_boot_args) {
		plist_dict_insert_item(opts, "RestoreBootArgs", plist_new_string(client->restore_boot_args));
	}
	plist_dict_insert_item(opts, "RestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	plist_dict_insert_item(opts, "RootToInstall", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "SourceRestoreBundlePath", plist_new_string("/tmp"));
	plist_dict_insert_item(opts, "SystemImage", plist_new_bool(1));
	plist_t spp = plist_new_dict();
	{
		plist_dict_insert_item(spp, "16", plist_new_uint(160));
		plist_dict_insert_item(spp, "32", plist_new_uint(320));
		plist_dict_insert_item(spp, "64", plist_new_uint(640));
		plist_dict_insert_item(spp, "8", plist_new_uint(80));
	}
	// FIXME: new on iOS 5 ?
	plist_dict_insert_item(opts, "SystemImageType", plist_new_string("User"));

	plist_dict_insert_item(opts, "SystemPartitionPadding", spp);
	char* guid = generate_guid();
	if (guid) {
		plist_dict_insert_item(opts, "UUID", plist_new_string(guid));
		free(guid);
	}
	// FIXME: does this have any effect actually?
	plist_dict_insert_item(opts, "UpdateBaseband", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_insert_item(opts, "UserLocale", plist_new_string("en_US"));

	// start the restore process
	restore_error = restored_start_restore(restore, opts, client->restore->protocol_version);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start the restore process\n");
		plist_free(opts);
		restore_client_free(client);
		return -1;
	}
	plist_free(opts);

	// this is the restore process loop, it reads each message in from
	// restored and passes that data on to it's specific handler
	while ((client->flags & FLAG_QUIT) == 0) {
		restore_error = restored_receive(restore, &message);
		if (restore_error != RESTORE_E_SUCCESS) {
			debug("No data to read\n");
			message = NULL;
			continue;
		}

		// discover what kind of message has been received
		node = plist_dict_get_item(message, "MsgType");
		if (!node || plist_get_node_type(node) != PLIST_STRING) {
			debug("Unknown message received:\n");
			//if (idevicerestore_debug)
				debug_plist(message);
			plist_free(message);
			message = NULL;
			continue;
		}
		plist_get_string_val(node, &type);

		// data request messages are sent by restored whenever it requires
		// files sent to the server by the client. these data requests include
		// SystemImageData, KernelCache, and NORData requests
		if (!strcmp(type, "DataRequestMsg")) {
			error = restore_handle_data_request_msg(client, device, restore, message, build_identity, filesystem);
		}

		// progress notification messages sent by the restored inform the client
		// of it's current operation and sometimes percent of progress is complete
		else if (!strcmp(type, "ProgressMsg")) {
			error = restore_handle_progress_msg(restore, message);
		}

		// status messages usually indicate the current state of the restored
		// process or often to signal an error has been encountered
		else if (!strcmp(type, "StatusMsg")) {
			error = restore_handle_status_msg(restore, message);
			if (restore_finished) {
				client->flags |= FLAG_QUIT;
			}
		}

		// there might be some other message types i'm not aware of, but I think
		// at least the "previous error logs" messages usually end up here
		else {
			debug("Unknown message type received\n");
			//if (idevicerestore_debug)
				debug_plist(message);
		}

		// finally, if any of these message handlers returned -1 then we encountered
		// an unrecoverable error, so we need to bail.
		if (error < 0) {
			error("ERROR: Unable to successfully restore device\n");
			client->flags |= FLAG_QUIT;
		}

		plist_free(message);
		message = NULL;
	}

	restore_client_free(client);
	return 0;
}
