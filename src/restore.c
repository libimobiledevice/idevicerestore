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
#include "restore.h"
#include "idevicerestore.h"

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
#define WAIT_FOR_NAND          29
#define UNMOUNT_FILESYSTEM     30
#define WAIT_FOR_DEVICE        33
#define LOAD_NOR               36

static int restore_device_connected = 0;

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

	return idevicerestore_devices[i].device_id;
}

void restore_device_callback(const idevice_event_t* event, void* user_data) {
	if (event->event == IDEVICE_DEVICE_ADD) {
		restore_device_connected = 1;

	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		restore_device_connected = 0;
		idevicerestore_quit = 1;
	}
}

int restore_reboot(const char* uuid) {
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;
	if (restore_open_with_timeout(uuid, &device, &restore) < 0) {
		error("ERROR: Unable to open device in restore mode\n");
		return -1;
	}

	restore_error = restored_reboot(restore);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to reboot the device from restore mode\n");
		restore_close(device, restore);
		return -1;
	}

	restore_close(device, restore);
	restore = NULL;
	device = NULL;
	return 0;
}

int restore_open_with_timeout(const char* uuid, idevice_t* device, restored_client_t* restore) {
	int i = 0;
	int attempts = 10;
	idevice_t context = NULL;
	restored_client_t client = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	*device = NULL;
	*restore = NULL;

	device_error = idevice_event_subscribe(&restore_device_callback, NULL);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to subscribe to device events\n");
		return -1;
	}

	for (i = 1; i <= attempts; i++) {
		if (restore_device_connected == 1) {
			break;
		}

		if (i == attempts) {
			error("ERROR: Unable to connect to device in restore mode\n");
		}

		sleep(2);
	}

	device_error = idevice_new(&context, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(context, &client, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_event_unsubscribe();
		idevice_free(context);
		return -1;
	}

	restore_error = restored_query_type(client, NULL, NULL);
	if (restore_error != RESTORE_E_SUCCESS) {
		restored_client_free(client);
		idevice_event_unsubscribe();
		idevice_free(context);
		return -1;
	}

	*device = context;
	*restore = client;
	return 0;
}

void restore_close(idevice_t device, restored_client_t restore) {
	if (restore)
		restored_client_free(restore);
	if (device)
		idevice_free(device);
}

const char* restore_progress_string(unsigned int operation) {
	switch (operation) {
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

	case WAIT_FOR_NAND:
		return "Waiting for NAND...";

	case WAIT_FOR_DEVICE:
		return "Waiting for Device...";

	case LOAD_NOR:
		return "Loading NOR data to flash";

	default:
		return "Unknown operation";
	}
}

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
		print_progress_bar(restore_progress_string(operation), (double) progress);

	} else {
		info("%s\n", restore_progress_string(operation));
	}

	return 0;
}

int restore_handle_status_msg(restored_client_t client, plist_t msg) {
	info("Got status message\n");
	debug_plist(msg);
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

	// we don't really need to do anything with this,
	// we're just clearing the output buffer
	if (asr_receive(asr, &data) < 0) {
		error("ERROR: Unable to receive data from ASR\n");
		asr_close(asr);
		return -1;
	}
	plist_free(data);

	// this step sends requested chunks of data from various offsets to asr so
	// it can validate the filesystem before installing it
	debug("Preparing to validate the filesystem\n");
	if (asr_perform_validation(asr, filesystem) < 0) {
		error("ERROR: ASR was unable to validate the filesystem\n");
		asr_close(asr);
		return -1;
	}
	info("Filesystem validated\n");

	// once the target filesystem has been validated, ASR then requests the
	// entire filesystem to be sent.
	debug("Preparing to send filesystem\n");
	if (asr_send_payload(asr, filesystem) < 0) {
		error("ERROR: Unable to send payload to ASR\n");
		asr_close(asr);
		return -1;
	}
	info("Filesystem finished\n");

	asr_close(asr);
	return 0;
}

int restore_send_kernelcache(restored_client_t client, char* kernel_data, int len) {
	info("Sending kernelcache\n");

	plist_t kernelcache_node = plist_new_data(kernel_data, len);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "KernelCacheFile", kernelcache_node);

	restored_error_t ret = restored_send(client, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		plist_free(dict);
		return -1;
	}

	info("Done sending kernelcache\n");
	plist_free(dict);
	return 0;
}

int restore_send_nor(restored_client_t client, const char* ipsw, plist_t tss) {
	char* llb_path = NULL;
	if (tss_get_entry_path(tss, "LLB", &llb_path) < 0) {
		error("ERROR: Unable to get LLB info from TSS response\n");
		return -1;
	}

	char* llb_filename = strstr(llb_path, "LLB");
	if (llb_filename == NULL) {
		error("ERROR: Unable to extract firmware path from LLB filename\n");
		free(llb_path);
		return -1;
	}

	char firmware_path[256];
	memset(firmware_path, '\0', sizeof(firmware_path));
	memcpy(firmware_path, llb_path, (llb_filename - 1) - llb_path);
	info("Found firmware path %s\n", firmware_path);

	char manifest_file[256];
	memset(manifest_file, '\0', sizeof(manifest_file));
	snprintf(manifest_file, sizeof(manifest_file), "%s/manifest", firmware_path);
	info("Getting firmware manifest %s\n", manifest_file);

	int manifest_size = 0;
	char* manifest_data = NULL;
	if (ipsw_extract_to_memory(ipsw, manifest_file, &manifest_data, &manifest_size) < 0) {
		error("ERROR: Unable to extract firmware manifest from ipsw\n");
		free(llb_path);
		return -1;
	}

	char firmware_filename[256];
	memset(firmware_filename, '\0', sizeof(firmware_filename));

	int llb_size = 0;
	char* llb_data = NULL;
	plist_t dict = plist_new_dict();
	char* filename = strtok(manifest_data, "\n");
	if (filename != NULL) {
		memset(firmware_filename, '\0', sizeof(firmware_filename));
		snprintf(firmware_filename, sizeof(firmware_filename), "%s/%s", firmware_path, filename);
		if (get_signed_component(ipsw, tss, firmware_filename, &llb_data, &llb_size) < 0) {
			error("ERROR: Unable to get signed LLB\n");
			return -1;
		}

		plist_dict_insert_item(dict, "LlbImageData", plist_new_data(llb_data, (uint64_t) llb_size));
	}

	int nor_size = 0;
	char* nor_data = NULL;
	filename = strtok(NULL, "\n");
	plist_t norimage_array = plist_new_array();
	while (filename != NULL) {
		memset(firmware_filename, '\0', sizeof(firmware_filename));
		snprintf(firmware_filename, sizeof(firmware_filename), "%s/%s", firmware_path, filename);
		if (get_signed_component(ipsw, tss, firmware_filename, &nor_data, &nor_size) < 0) {
			error("ERROR: Unable to get signed firmware %s\n", firmware_filename);
			break;
		}

		plist_array_append_item(norimage_array, plist_new_data(nor_data, (uint64_t) nor_size));
		free(nor_data);
		nor_data = NULL;
		nor_size = 0;
		filename = strtok(NULL, "\n");
	}
	plist_dict_insert_item(dict, "NorImageData", norimage_array);

	debug_plist(dict);

	restored_error_t ret = restored_send(client, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		plist_free(dict);
		return -1;
	}

	plist_free(dict);
	return 0;
}

int restore_handle_data_request_msg(idevice_t device, restored_client_t restore, plist_t message, plist_t tss, const char* ipsw, const char* filesystem) {
	char* type = NULL;
	plist_t node = NULL;

	// checks and see what kind of data restored is requests and pass
	// the request to its own handler
	node = plist_dict_get_item(message, "DataType");
	if (node && PLIST_STRING == plist_get_node_type(node)) {
		plist_get_string_val(node, &type);

		// this request is sent when restored is ready to receive the filesystem
		if (!strcmp(type, "SystemImageData")) {
			restore_send_filesystem(device, filesystem);

		}

		else if (!strcmp(type, "KernelCache")) {
			int kernelcache_size = 0;
			char* kernelcache_data = NULL;
			char* kernelcache_path = NULL;
			if (tss_get_entry_path(tss, "KernelCache", &kernelcache_path) < 0) {
				error("ERROR: Unable to find kernelcache path\n");
				return -1;
			}

			if (get_signed_component(ipsw, tss, kernelcache_path, &kernelcache_data, &kernelcache_size) < 0) {
				error("ERROR: Unable to get kernelcache file\n");
				return -1;
			}
			restore_send_kernelcache(restore, kernelcache_data, kernelcache_size);
			free(kernelcache_data);

		}

		else if (!strcmp(type, "NORData")) {
			if(!idevicerestore_exclude) {
				restore_send_nor(restore, ipsw, tss);
			} else {
				idevicerestore_quit = 1;
			}

		} else {
			// Unknown DataType!!
			debug("Unknown data request received\n");
		}
	}
	return 0;
}

int restore_device(const char* uuid, const char* ipsw, plist_t tss, const char* filesystem) {
	int error = 0;
	char* type = NULL;
	char* kernel = NULL;
	plist_t node = NULL;
	plist_t message = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	// open our connection to the device and verify we're in restore mode
	if (restore_open_with_timeout(uuid, &device, &restore) < 0) {
		error("ERROR: Unable to open device in restore mode\n");
		return -1;
	}
	info("Device has successfully entered restore mode\n");

	// start the restore process
	restore_error = restored_start_restore(restore);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start the restore process\n");
		restore_close(device, restore);
		return -1;
	}

	// this is the restore process loop, it reads each message in from
	// restored and passes that data on to it's specific handler
	while (!idevicerestore_quit) {
		restore_error = restored_receive(restore, &message);
		if (restore_error != RESTORE_E_SUCCESS) {
			debug("No data to read\n");
			message = NULL;
			continue;
		}

		// discover what kind of message has been received
		node = plist_dict_get_item(message, "MsgType");
		if (!node || plist_get_node_type(node) != PLIST_STRING) {
			debug("Unknown message received\n");
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
			error = restore_handle_data_request_msg(device, restore, message, tss, ipsw, filesystem);
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
		}

		// there might be some other message types i'm not aware of, but I think
		// at least the "previous error logs" messages usually end up here
		else {
			debug("Unknown message type received\n");
			debug_plist(message);
		}

		// finally, if any of these message handlers returned -1 then we encountered
		// an unrecoverable error, so we need to bail.
		if (error < 0) {
			error("ERROR: Unable to successfully restore device\n");
			idevicerestore_quit = 1;
		}

		plist_free(message);
		message = NULL;
	}

	restore_close(device, restore);
	return 0;
}
