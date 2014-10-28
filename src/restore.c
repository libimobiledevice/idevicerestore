/*
 * restore.c
 * Functions for handling idevices in restore mode
 *
 * Copyright (c) 2010-2013 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012-2013 Nikias Bassen. All Rights Reserved.
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
#include <libimobiledevice/restore.h>
#include <zip.h>
#include <libirecovery.h>

#include "idevicerestore.h"
#include "asr.h"
#include "fls.h"
#include "mbn.h"
#include "tss.h"
#include "ipsw.h"
#include "restore.h"
#include "common.h"

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
			if(client->restore->bbtss) {
				plist_free(client->restore->bbtss);
				client->restore->bbtss = NULL;
			}
			free(client->restore);
			client->restore = NULL;
		}
	}
}

static int restore_idevice_new(struct idevicerestore_client_t* client, idevice_t* device)
{
	int num_devices = 0;
	char **devices = NULL;
	idevice_get_device_list(&devices, &num_devices);
	if (num_devices == 0) {
		return -1;
	}
	*device = NULL;
	idevice_t dev = NULL;
	idevice_error_t device_error;
	restored_client_t restore = NULL;
	int j;
	for (j = 0; j < num_devices; j++) {
		if (restore != NULL) {
			restored_client_free(restore);
			restore = NULL;
		}
		if (dev != NULL) {
			idevice_free(dev);
			dev = NULL;
		}
		device_error = idevice_new(&dev, devices[j]);
		if (device_error != IDEVICE_E_SUCCESS) {
			error("ERROR: %s: can't open device with UDID %s", __func__, devices[j]);
			continue;
		}

		if (restored_client_new(dev, &restore, "idevicerestore") != RESTORE_E_SUCCESS) {
			error("ERROR: %s: can't connect to restored on device with UDID %s", __func__, devices[j]);
			continue;

		}
		char* type = NULL;
		uint64_t version = 0;
		if (restored_query_type(restore, &type, &version) != RESTORE_E_SUCCESS) {
			continue;
		}
		if (strcmp(type, "com.apple.mobile.restored") != 0) {
			free(type);
			continue;
		}
		free(type);

		if (client->ecid != 0) {
			plist_t node = NULL;
			plist_t hwinfo = NULL;

			if (restored_query_value(restore, "HardwareInfo", &hwinfo) != RESTORE_E_SUCCESS) {
				
				continue;
			}

			node = plist_dict_get_item(hwinfo, "UniqueChipID");
			if (!node || plist_get_node_type(node) != PLIST_UINT) {
				if (hwinfo) {
					plist_free(hwinfo);
				}
				continue;
			}
			restored_client_free(restore);
			restore = NULL;

			uint64_t this_ecid = 0;
			plist_get_uint_val(node, &this_ecid);
			plist_free(hwinfo);

			if (this_ecid != client->ecid) {
				continue;
			}
		}
		if (restore) {
			restored_client_free(restore);
			restore = NULL;
		}
		client->udid = strdup(devices[j]);
		*device = dev;
		break;
	}
	idevice_device_list_free(devices);

	return 0;
}

int restore_check_mode(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;

	restore_idevice_new(client, &device);
	if (!device) {
		return -1;
	}
	idevice_free(device);

	return 0;
}

const char* restore_check_product_type(struct idevicerestore_client_t* client) {
	char* model = NULL;
	plist_t node = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;
	char* product_type = NULL;
	irecv_device_t irecv_device = NULL;

	restore_idevice_new(client, &device);
	if (!device) {
		return product_type;
	}

	restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		idevice_free(device);
		return product_type;
	}

	if (restored_query_type(restore, NULL, NULL) != RESTORE_E_SUCCESS) {
		restored_client_free(restore);
		idevice_free(device);
		return product_type;
	}

	if (client->srnm == NULL) {
		restore_error = restored_get_value(restore, "SerialNumber", &node);
		if (restore_error != RESTORE_E_SUCCESS || !node || plist_get_node_type(node) != PLIST_STRING) {
			error("ERROR: Unable to get SerialNumber from restored\n");
			restored_client_free(restore);
			idevice_free(device);
			return product_type;
		}

		plist_get_string_val(node, &client->srnm);
		info("INFO: device serial number is %s\n", client->srnm);
		node = NULL;
	}

	restore_error = restored_get_value(restore, "HardwareModel", &node);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to get HardwareModel from restored\n");
		restored_client_free(restore);
		idevice_free(device);
		return product_type;
	}

	restored_client_free(restore);
	idevice_free(device);
	restore = NULL;
	device = NULL;

	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to get HardwareModel information\n");
		if (node)
			plist_free(node);
		return product_type;
	}
	plist_get_string_val(node, &model);

	irecv_devices_get_device_by_hardware_model(model, &irecv_device);
	if (irecv_device && irecv_device->product_type) {
		return irecv_device->product_type;
	}

	return product_type;
}

void restore_device_callback(const idevice_event_t* event, void* userdata) {
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) userdata;
	if (event->event == IDEVICE_DEVICE_ADD) {
		restore_device_connected = 1;
		client->udid = strdup(event->udid);
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		restore_device_connected = 0;
		client->flags |= FLAG_QUIT;
	}
}

int restore_reboot(struct idevicerestore_client_t* client) {
	if(client->restore == NULL) {
		if (restore_open_with_timeout(client) < 0) {
			error("ERROR: Unable to open device in restore mode\n");
			return -1;
		}
	}

	info("Rebooting restore mode device...\n");
	restored_reboot(client->restore->client);

	restored_client_free(client->restore->client);

	// FIXME: wait for device disconnect here
	sleep(10);

	return 0;
}

static int restore_is_current_device(struct idevicerestore_client_t* client, const char* udid)
{
	if (!client) {
		return 0;
	}
	if (!client->srnm) {
		error("ERROR: %s: no SerialNumber given in client data\n", __func__);
		return 0;
	}

	idevice_t device = NULL;
	idevice_error_t device_error;
	restored_client_t restored = NULL;
	restored_error_t restore_error;
	char *type = NULL;
	uint64_t version = 0;

	device_error = idevice_new(&device, udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: %s: can't open device with UDID %s", __func__, udid);
		return 0;
	}

	restore_error = restored_client_new(device, &restored, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: %s: can't connect to restored\n", __func__);
		idevice_free(device);
		return 0;
	}
	restore_error = restored_query_type(restored, &type, &version);
	if ((restore_error == RESTORE_E_SUCCESS) && type && (strcmp(type, "com.apple.mobile.restored") == 0)) {
		debug("%s: Connected to %s, version %d\n", __func__, type, (int)version);
	} else {
		info("%s: device %s is not in restore mode\n", __func__, udid);
		restored_client_free(restored);
		idevice_free(device);
		return 0;
	}

	plist_t node = NULL;
	restore_error = restored_get_value(restored, "SerialNumber", &node);
	if ((restore_error != RESTORE_E_SUCCESS) || !node || (plist_get_node_type(node) != PLIST_STRING)) {
		error("ERROR: %s: Unable to get SerialNumber from restored\n", __func__);
		restored_client_free(restored);
		idevice_free(device);
		if (node) {
			plist_free(node);
		}
		return 0;
	}
	restored_client_free(restored);
	idevice_free(device);

	char* this_srnm = NULL;
	plist_get_string_val(node, &this_srnm);
	plist_free(node);

	if (!this_srnm) {
		return 0;
	}

	return (strcasecmp(this_srnm, client->srnm) == 0);
}

static void restore_device_event_cb(const idevice_event_t *event, void *user_data)
{
	if (event->event == IDEVICE_DEVICE_ADD) {
		struct idevicerestore_client_t* client = (struct idevicerestore_client_t*)user_data;
		if (!restore_device_connected && restore_is_current_device(client, event->udid)) {
			restore_device_connected = 1;
			client->udid = strdup(event->udid);
		}
	}
}

int restore_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 180;
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

	if(client->srnm == NULL) {
		error("ERROR: no SerialNumber in client data!\n");
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

	restore_device_connected = 0;

	info("Waiting for device...\n");
	idevice_event_subscribe(restore_device_event_cb, client);
	i = 0;
	while (i++ < attempts) {
		debug("Attempt %d to connect to restore mode device...\n", i);
		if (restore_device_connected) {
			info("Device is now connected in restore mode...\n");
			break;
		}
		sleep(1);
	}
	idevice_event_unsubscribe();

	if (!restore_device_connected) {
		error("ERROR: Unable to connect to device in restore mode\n");
		return (i == attempts ? -2:-1);
	}

	info("Connecting now...\n");
	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	restore_error = restored_client_new(device, &restored, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
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

int restore_handle_previous_restore_log_msg(restored_client_t client, plist_t msg) {
	plist_t node = NULL;
	char* restorelog = NULL;

	node = plist_dict_get_item(msg, "PreviousRestoreLog");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		debug("Failed to parse restore log from PreviousRestoreLog plist\n");
		return -1;
	}
	plist_get_string_val(node, &restorelog);

	info("Previous Restore Log Received:\n%s\n", restorelog);
	free(restorelog);

	return 0;
}

int restore_handle_progress_msg(struct idevicerestore_client_t* client, plist_t msg) {
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

	if ((progress > 0) && (progress <= 100)) {
		if ((int)operation != lastop) {
			info("%s (%d)\n", restore_progress_string(operation), (int)operation);
		}
		switch ((int)operation) {
		case 14:
			idevicerestore_progress(client, RESTORE_STEP_FLASH_FS, progress / 100.0);
			break;
		case 18:
			idevicerestore_progress(client, RESTORE_STEP_FLASH_FW, progress / 100.0);
			break;
		case 19:
			idevicerestore_progress(client, RESTORE_STEP_FLASH_BB, progress / 100.0);
			break;
		default:
			debug("Unhandled progress operation %d\n", (int)operation);
			break;
		}
	} else {
		info("%s (%d)\n", restore_progress_string(operation), (int)operation);
	}
	lastop = (int)operation;

	return 0;
}

int restore_handle_status_msg(restored_client_t client, plist_t msg) {
	int result = 0;
	uint64_t value = 0;
	char* log = NULL;
	info("Got status message\n");

	// read status code
	plist_t node = plist_dict_get_item(msg, "Status");
	plist_get_uint_val(node, &value);

	switch(value) {
		case 0:
			info("Status: Restore Finished\n");
			restore_finished = 1;
			break;
		case 0xFFFFFFFFFFFFFFFFLL:
			info("Status: Verification Error\n");
			break;
		case 6:
			info("Status: Disk Failure\n");
			break;
		case 14:
			info("Status: Fail\n");
			break;
		case 27:
			info("Status: Failed to mount filesystems.\n");
			break;
		case 51:
			info("Status: Failed to load SEP Firmware.\n");
			break;
		case 1015:
			info("Status: X-Gold Baseband Update Failed. Defective Unit?\n");
			break;
		default:
			info("Unhandled status message (" FMT_qu ")\n", (long long unsigned int)value);
			debug_plist(msg);
			break;
	}

	// read error code
	node = plist_dict_get_item(msg, "AMRError");
	if (node && plist_get_node_type(node) == PLIST_UINT) {
		plist_get_uint_val(node, &value);
		result = -value;
		if (result > 0) {
			result = -result;
		}
	}

	// check if log is available
	node = plist_dict_get_item(msg, "Log");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &log);
		info("Log is available:\n%s\n", log);
		free(log);
		log = NULL;
	}

	return result;
}

int restore_handle_bb_update_status_msg(restored_client_t client, plist_t msg)
{
	int result = -1;
	plist_t node = plist_dict_get_item(msg, "Accepted");
	uint8_t accepted = 0;
	plist_get_bool_val(node, &accepted);

	if (!accepted) {
		error("ERROR: device didn't accept BasebandData\n");
		return result;
	}

	uint8_t done = 0;
	node = plist_access_path(msg, 2, "Output", "done");
	if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
		plist_get_bool_val(node, &done);
	}

	if (done) {
		info("Updating Baseband completed.\n");
		plist_t provisioning = plist_access_path(msg, 2, "Output", "provisioning");
		if (provisioning && plist_get_node_type(provisioning) == PLIST_DICT) {
			char* sval = NULL;
			node = plist_dict_get_item(provisioning, "IMEI");
			if (node && plist_get_node_type(node) == PLIST_STRING) {
				plist_get_string_val(node, &sval);
				info("Provisioning:\n");
				info("IMEI:%s\n", sval);
				free(sval);
				sval = NULL;
			}
		}
	} else {
		info("Updating Baseband in progress...\n");
	}
	result = 0;

	return result;
}

static void restore_asr_progress_cb(double progress, void* userdata)
{
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*)userdata;
	if (client) {
		idevicerestore_progress(client, RESTORE_STEP_UPLOAD_FS, progress);
	}
}

int restore_send_filesystem(struct idevicerestore_client_t* client, idevice_t device, const char* filesystem) {
	asr_client_t asr = NULL;

	info("About to send filesystem...\n");

	if (asr_open_with_timeout(device, &asr) < 0) {
		error("ERROR: Unable to connect to ASR\n");
		return -1;
	}
	info("Connected to ASR\n");

	asr_set_progress_callback(asr, restore_asr_progress_cb, (void*)client);

	// this step sends requested chunks of data from various offsets to asr so
	// it can validate the filesystem before installing it
	info("Validating the filesystem\n");
	if (asr_perform_validation(asr, filesystem) < 0) {
		error("ERROR: ASR was unable to validate the filesystem\n");
		asr_free(asr);
		return -1;
	}
	info("Filesystem validated\n");

	// once the target filesystem has been validated, ASR then requests the
	// entire filesystem to be sent.
	info("Sending filesystem now...\n");
	if (asr_send_payload(asr, filesystem) < 0) {
		error("ERROR: Unable to send payload to ASR\n");
		asr_free(asr);
		return -1;
	}
	info("Done sending filesystem\n");

	asr_free(asr);
	return 0;
}

int restore_send_root_ticket(restored_client_t restore, struct idevicerestore_client_t* client)
{
	restored_error_t restore_error;
	plist_t dict;
	unsigned char* data = NULL;
	unsigned int len = 0;

	info("About to send RootTicket...\n");

	if (!client->tss && !(client->flags & FLAG_CUSTOM)) {
		error("ERROR: Cannot send RootTicket without TSS\n");
		return -1;
	}

	if (client->image4supported) {
		if (!tss_response_get_ap_img4_ticket(client->tss, &data, &len) < 0) {
			error("ERROR: Unable to get ApImg4Ticket from TSS\n");
			return -1;
		}
	} else {
		if (!(client->flags & FLAG_CUSTOM) && (tss_response_get_ap_ticket(client->tss, &data, &len) < 0)) {
			error("ERROR: Unable to get ticket from TSS\n");
			return -1;
		}
	}

	dict = plist_new_dict();
	if (data && (len > 0)) {
		plist_dict_set_item(dict, "RootTicketData", plist_new_data((char*)data, len));
	} else {
		info("NOTE: not sending RootTicketData (no data present)\n");
	}

	info("Sending RootTicket now...\n");
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
	unsigned int size = 0;
	unsigned char* data = NULL;
	char* path = NULL;
	plist_t blob = NULL;
	plist_t dict = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	info("About to send KernelCache...\n");

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, "KernelCache", &path) < 0) {
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

	const char* component = "KernelCache";
	unsigned char* component_data = NULL;
	unsigned int component_size = 0;

	if (extract_component(client->ipsw, path, &component_data, &component_size) < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		free(path);
		return -1;
	}

	if (personalize_component(component, component_data, component_size, client->tss, &data, &size) < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		free(component_data);
		free(path);
		return -1;
	}
	free(component_data);
	component_data = NULL;

	dict = plist_new_dict();
	blob = plist_new_data((char*)data, size);
	plist_dict_set_item(dict, "KernelCacheFile", blob);

	info("Sending KernelCache now...\n");
	restore_error = restored_send(restore, dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		plist_free(dict);
		return -1;
	}

	info("Done sending KernelCache\n");
	plist_free(dict);
	free(data);
	return 0;
}

int restore_send_nor(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity) {
	char* llb_path = NULL;
	char* llb_filename = NULL;
	char* sep_path = NULL;
	char* restore_sep_path = NULL;
	char firmware_path[256];
	char manifest_file[256];
	unsigned int manifest_size = 0;
	unsigned char* manifest_data = NULL;
	char firmware_filename[256];
	unsigned int llb_size = 0;
	unsigned char* llb_data = NULL;
	plist_t dict = NULL;
	char* filename = NULL;
	unsigned int nor_size = 0;
	unsigned char* nor_data = NULL;
	plist_t norimage_array = NULL;
	restored_error_t ret = RESTORE_E_SUCCESS;

	info("About to send NORData...\n");

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, "LLB", &llb_path) < 0) {
			debug("NOTE: Could not get LLB path from TSS data, will fetch from build identity\n");
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

	const char* component = "LLB";
	unsigned char* component_data = NULL;
	unsigned int component_size = 0;

	if (extract_component(client->ipsw, llb_path, &component_data, &component_size) < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		free(llb_path);
		return -1;
	}

	if (personalize_component(component, component_data, component_size, client->tss, &llb_data, &llb_size) < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		free(component_data);
		free(llb_path);
		return -1;
	}
	free(component_data);
	component_data = NULL;
	component_size = 0;

	dict = plist_new_dict();
	plist_dict_set_item(dict, "LlbImageData", plist_new_data((char*)llb_data, (uint64_t) llb_size));
	if (llb_data)
		free(llb_data);

	norimage_array = plist_new_array();

	filename = strtok((char*)manifest_data, "\r\n");
	while (filename != NULL) {
		if ((!strncmp("LLB", filename, 3)) || (!strncmp("sep", filename, 3))) {
			// skip LLB, it's already passed in LlbImageData
			filename = strtok(NULL, "\r\n");
			continue;
		}
		memset(firmware_filename, '\0', sizeof(firmware_filename));
		snprintf(firmware_filename, sizeof(firmware_filename), "%s/%s", firmware_path, filename);

		component = get_component_name(filename);
		component_data = NULL;
		unsigned int component_size = 0;

		if (extract_component(client->ipsw, firmware_filename, &component_data, &component_size) < 0) {
			error("ERROR: Unable to extract component: %s\n", component);
			free(llb_path);
			return -1;
		}

		if (personalize_component(component, component_data, component_size, client->tss, &nor_data, &nor_size) < 0) {
			error("ERROR: Unable to get personalized component: %s\n", component);
			free(component_data);
			free(llb_path);
			return -1;
		}
		free(component_data);
		component_data = NULL;
		component_size = 0;

		/* make sure iBoot is the first entry in the array */
		if (!strncmp("iBoot", filename, 4)) {
			plist_array_insert_item(norimage_array, plist_new_data((char*)nor_data, (uint64_t)nor_size), 0);
		} else {
			plist_array_append_item(norimage_array, plist_new_data((char*)nor_data, (uint64_t)nor_size));
		}

		free(nor_data);
		nor_data = NULL;
		nor_size = 0;
		filename = strtok(NULL, "\r\n");
	}
	plist_dict_set_item(dict, "NorImageData", norimage_array);

	unsigned char* personalized_data = NULL;
	unsigned int personalized_size = 0;

	if (!build_identity_has_component(build_identity, "RestoreSEP") && build_identity_get_component_path(build_identity, "RestoreSEP", &restore_sep_path) == 0) {
		component = "RestoreSEP";
		if (extract_component(client->ipsw, restore_sep_path, &component_data, &component_size) < 0) {
			error("ERROR: Unable to extract component: %s\n", component);
			free(restore_sep_path);
			return -1;
		}

		if (personalize_component(component, component_data, component_size, client->tss, &personalized_data, &personalized_size) < 0) {
			error("ERROR: Unable to get personalized component: %s\n", component);
			free(component_data);
			free(restore_sep_path);
			return -1;
		}
		free(component_data);
		component_data = NULL;
		component_size = 0;

		plist_dict_set_item(dict, "RestoreSEPImageData", plist_new_data((char*)personalized_data, (uint64_t) personalized_size));
		free(personalized_data);
		personalized_data = NULL;
		personalized_size = 0;
	}

	if (!build_identity_has_component(build_identity, "SEP") && build_identity_get_component_path(build_identity, "SEP", &sep_path) == 0) {
		component = "SEP";
		if (extract_component(client->ipsw, sep_path, &component_data, &component_size) < 0) {
			error("ERROR: Unable to extract component: %s\n", component);
			free(sep_path);
			return -1;
		}

		if (personalize_component(component, component_data, component_size, client->tss, &personalized_data, &personalized_size) < 0) {
			error("ERROR: Unable to get personalized component: %s\n", component);
			free(component_data);
			free(sep_path);
			return -1;
		}
		free(component_data);
		component_data = NULL;
		component_size = 0;

		plist_dict_set_item(dict, "SEPImageData", plist_new_data((char*)personalized_data, (uint64_t) personalized_size));
		free(personalized_data);
		personalized_data = NULL;
		personalized_size = 0;
	}

	if (idevicerestore_debug)
		debug_plist(dict);

	info("Sending NORData now...\n");
	ret = restored_send(restore, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send NORImageData data\n");
		plist_free(dict);
		return -1;
	}

	info("Done sending NORData\n");
	plist_free(dict);
	return 0;
}

static const char* restore_get_bbfw_fn_for_element(const char* elem)
{
	struct bbfw_fn_elem_t {
		const char* element;
		const char* fn;
	};

	struct bbfw_fn_elem_t bbfw_fn_elem[] = {
		// ICE3 firmware files
		{ "RamPSI", "psi_ram.fls" },
		{ "FlashPSI", "psi_flash.fls" },
		// Trek firmware files
		{ "eDBL", "dbl.mbn" },
		{ "RestoreDBL", "restoredbl.mbn" },
		// Phoenix/Mav4 firmware files
		{ "DBL", "dbl.mbn" },
		{ "ENANDPRG", "ENPRG.mbn" },	
		// Mav5 firmware files
		{ "RestoreSBL1", "restoresbl1.mbn" },
		{ "SBL1", "sbl1.mbn" },
		{ NULL, NULL }
	};

	int i;
	for (i = 0; bbfw_fn_elem[i].element != NULL; i++) {
		if (strcmp(bbfw_fn_elem[i].element, elem) == 0) {
			return bbfw_fn_elem[i].fn;
		}
	}
	return NULL;
}

static int restore_sign_bbfw(const char* bbfwtmp, plist_t bbtss, const unsigned char* bb_nonce)
{
	int res = -1;

	// check for BBTicket in result
	plist_t bbticket = plist_dict_get_item(bbtss, "BBTicket");
	if (!bbticket || plist_get_node_type(bbticket) != PLIST_DATA) {
		error("ERROR: Could not find BBTicket in Baseband TSS response\n");
		return -1;
	}

	plist_t bbfw_dict = plist_dict_get_item(bbtss, "BasebandFirmware");
	if (!bbfw_dict || plist_get_node_type(bbfw_dict) != PLIST_DICT) {
		error("ERROR: Could not find BasebandFirmware Dictionary node in Baseband TSS response\n");
		return -1;
	}

	unsigned char* buffer = NULL;
	unsigned char* blob = NULL;
	unsigned char* fdata = NULL;
	off_t fsize = 0;
	uint64_t blob_size = 0;
	int zerr = 0;
	int zindex = -1;
	int size = 0;
	struct zip_stat zstat;
	struct zip_file* zfile = NULL;
	struct zip* za = NULL;
	struct zip_source* zs = NULL;
	mbn_file* mbn = NULL;
	fls_file* fls = NULL;

	za = zip_open(bbfwtmp, 0, &zerr);
	if (!za) {
		error("ERROR: Could not open ZIP archive '%s': %d\n", bbfwtmp, zerr);
		goto leave;
	}

	plist_dict_iter iter = NULL;
	plist_dict_new_iter(bbfw_dict, &iter);
	if (!iter) {
		error("ERROR: Could not create dict iter for BasebandFirmware Dictionary\n");
		return -1;
	}

	int is_fls = 0;
	int signed_file_idxs[16];
	int signed_file_count = 0;
	char* key = NULL;
	plist_t node = NULL;
	while (1) {
		plist_dict_next_item(bbfw_dict, iter, &key, &node);
		if (key == NULL)
			break;
		if (node && (strcmp(key + (strlen(key) - 5), "-Blob") == 0) && (plist_get_node_type(node) == PLIST_DATA)) {
			key[strlen(key)-5] = 0;
			const char* signfn = restore_get_bbfw_fn_for_element(key);
			char* ext = strrchr(signfn, '.');
			if (strcmp(ext, ".fls") == 0) {
				is_fls = 1;
			}

			zindex = zip_name_locate(za, signfn, 0);
			if (zindex < 0) {
				error("ERROR: can't locate '%s' in '%s'\n", signfn, bbfwtmp);
				goto leave;
			}

			zip_stat_init(&zstat);
			if (zip_stat_index(za, zindex, 0, &zstat) != 0) {
				error("ERROR: zip_stat_index failed for index %d\n", zindex);
				goto leave;
			}

			zfile = zip_fopen_index(za, zindex, 0);
			if (zfile == NULL) {
				error("ERROR: zip_fopen_index failed for index %d\n", zindex);
				goto leave;
			}

			size = zstat.size;
			buffer = (unsigned char*) malloc(size+1);
			if (buffer == NULL) {
				error("ERROR: Out of memory\n");
				goto leave;
			}

			if (zip_fread(zfile, buffer, size) != size) {
				error("ERROR: zip_fread: failed\n");
				goto leave;
			}
			buffer[size] = '\0';

			zip_fclose(zfile);
			zfile = NULL;

			if (is_fls) {
				fls = fls_parse(buffer, size);
				if (!fls) {
					error("ERROR: could not parse fls file\n");
					goto leave;
				}
			} else {
				mbn = mbn_parse(buffer, size);
				if (!mbn) {
					error("ERROR: could not parse mbn file\n");
					goto leave;
				}
			}
			free(buffer);
			buffer = NULL;

			blob = NULL;
			blob_size = 0;
			plist_get_data_val(node, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get %s-Blob data\n", key);
				goto leave;
			}

			if (is_fls) {
				if (fls_update_sig_blob(fls, blob, (unsigned int)blob_size) != 0) {
					error("ERROR: could not sign psi_ram.fls\n");
					goto leave;
				}
			} else {
				if (mbn_update_sig_blob(mbn, blob, (unsigned int)blob_size) != 0) {
					error("ERROR: could not sign dbl.mbn\n");
					goto leave;
				}
			}
			free(blob);
			blob = NULL;

			if (is_fls) {
				fsize = fls->size;
				fdata = (unsigned char*)malloc(fsize);
				memcpy(fdata, fls->data, fsize);
				fls_free(fls);
				fls = NULL;
			} else {
				fsize = mbn->size;
				fdata = (unsigned char*)malloc(fsize);
				memcpy(fdata, mbn->data, fsize);
				mbn_free(mbn);
				mbn = NULL;
			}

			zs = zip_source_buffer(za, fdata, fsize, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				goto leave;
			}

			if (zip_replace(za, zindex, zs) == -1) {
				error("ERROR: could not update signed '%s' in archive\n", signfn);
				goto leave;
			}

			if (is_fls && !bb_nonce) {
				if (strcmp(key, "RamPSI") == 0) {
					signed_file_idxs[signed_file_count++] = zindex;
				}
			} else {
				signed_file_idxs[signed_file_count++] = zindex;
			}
		}
		free(key);
	}
	free(iter);

	// remove everything but required files
	int i;
	int j;
	int skip = 0;
	int numf = zip_get_num_files(za);
	for (i = 0; i < numf; i++) {
		skip = 0;
		// check for signed file index
		for (j = 0; j < signed_file_count; j++) {
			if (i == signed_file_idxs[j]) {
				skip = 1;
				break;
			}
		}
		// check for anything but .mbn and .fls if bb_nonce is set
		if (bb_nonce && !skip) {
			const char* fn = zip_get_name(za, i, 0);
			if (fn) {
				char* ext = strrchr(fn, '.');
				if (strcmp(ext, ".fls") == 0 || strcmp(ext, ".mbn") == 0) {
					skip = 1;
				}
			}
		}
		if (skip) {
			continue;
		}
		zip_delete(za, i);
	}

	if (bb_nonce) {
		if (is_fls) {
			// add BBTicket to file ebl.fls
			zindex = zip_name_locate(za, "ebl.fls", 0);
			if (zindex < 0) {
				error("ERROR: can't locate 'ebl.fls' in '%s'\n", bbfwtmp);
				goto leave;
			}

			zip_stat_init(&zstat);
			if (zip_stat_index(za, zindex, 0, &zstat) != 0) {
				error("ERROR: zip_stat_index failed for index %d\n", zindex);
				goto leave;
			}

			zfile = zip_fopen_index(za, zindex, 0);
			if (zfile == NULL) {
				error("ERROR: zip_fopen_index failed for index %d\n", zindex);
				goto leave;
			}

			size = zstat.size;
			buffer = (unsigned char*) malloc(size+1);
			if (buffer == NULL) {
				error("ERROR: Out of memory\n");
				goto leave;
			}

			if (zip_fread(zfile, buffer, size) != size) {
				error("ERROR: zip_fread: failed\n");
				goto leave;
			}
			buffer[size] = '\0';

			zip_fclose(zfile);
			zfile = NULL;

			fls = fls_parse(buffer, size);
			free(buffer);
			buffer = NULL;
			if (!fls) {
				error("ERROR: could not parse fls file\n");
				goto leave;
			}

			blob = NULL;
			blob_size = 0;
			plist_get_data_val(bbticket, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get BBTicket data\n");
				goto leave;
			}

			if (fls_insert_ticket(fls, blob, (unsigned int)blob_size) != 0) {
				error("ERROR: could not insert BBTicket to ebl.fls\n");
				goto leave;
			}
			free(blob);
			blob = NULL;

			fsize = fls->size;
			fdata = (unsigned char*)malloc(fsize);
			memcpy(fdata, fls->data, fsize);
			fls_free(fls);
			fls = NULL;

			zs = zip_source_buffer(za, fdata, fsize, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				goto leave;
			}

			if (zip_replace(za, zindex, zs) == -1) {
				error("ERROR: could not update archive with ticketed ebl.fls\n");
				goto leave;
			}
		} else {
			// add BBTicket as bbticket.der
			blob = NULL;
			blob_size = 0;
			plist_get_data_val(bbticket, (char**)&blob, &blob_size);
			if (!blob) {
				error("ERROR: could not get BBTicket data\n");
				goto leave;
			}

			zs = zip_source_buffer(za, blob, blob_size, 1);
			if (!zs) {
				error("ERROR: out of memory\n");
				goto leave;
			}
			blob = NULL;

			if (zip_add(za, "bbticket.der", zs) == -1) {
				error("ERROR: could not add bbticket.der to archive\n");
				goto leave;
			}
		}
	}

	// this will write out the modified zip
	if (zip_close(za) == -1) {
		error("ERROR: could not close and write modified archive: %s\n", zip_strerror(za));
		res = -1;
	} else {
		res = 0;
	}
	za = NULL;
	zs = NULL;

leave:
	if (mbn) {
		mbn_free(mbn);
	}
	if (fls) {
		fls_free(fls);
	}
	if (zfile) {
		zip_fclose(zfile);
	}
	if (zs) {
		zip_source_free(zs);
	}
	if (za) {
		zip_unchange_all(za);
		zip_close(za);
	}
	if (buffer) {
		free(buffer);
	}
	if (blob) {
		free(blob);
	}

	return res;
}

int restore_send_baseband_data(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity, plist_t message)
{
	int res = -1;
	uint64_t bb_cert_id = 0;
	unsigned char* bb_snum = NULL;
	uint64_t bb_snum_size = 0;
	unsigned char* bb_nonce = NULL;
	uint64_t bb_nonce_size = 0;
	uint64_t bb_chip_id = 0;
	plist_t response = NULL;
	char* buffer = NULL;
	char* bbfwtmp = NULL;
	plist_t dict = NULL;

	info("About to send BasebandData...\n");

	// NOTE: this function is called 2 or 3 times!

	// setup request data
	plist_t arguments = plist_dict_get_item(message, "Arguments");
	if (arguments && plist_get_node_type(arguments) == PLIST_DICT) {
		plist_t bb_chip_id_node = plist_dict_get_item(arguments, "ChipID");
		if (bb_chip_id_node && plist_get_node_type(bb_chip_id_node) == PLIST_UINT) {
			plist_get_uint_val(bb_chip_id_node, &bb_chip_id);
		}
		plist_t bb_cert_id_node = plist_dict_get_item(arguments, "CertID");
		if (bb_cert_id_node && plist_get_node_type(bb_cert_id_node) == PLIST_UINT) {
			plist_get_uint_val(bb_cert_id_node, &bb_cert_id);
		}
		plist_t bb_snum_node = plist_dict_get_item(arguments, "ChipSerialNo");
		if (bb_snum_node && plist_get_node_type(bb_snum_node) == PLIST_DATA) {
			plist_get_data_val(bb_snum_node, (char**)&bb_snum, &bb_snum_size);
		}
		plist_t bb_nonce_node = plist_dict_get_item(arguments, "Nonce");
		if (bb_nonce_node && plist_get_node_type(bb_nonce_node) == PLIST_DATA) {
			plist_get_data_val(bb_nonce_node, (char**)&bb_nonce, &bb_nonce_size);
		}
	}

	if ((bb_nonce == NULL) || (client->restore->bbtss == NULL)) {
		/* populate parameters */
		plist_t parameters = plist_new_dict();
		plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
		if (bb_nonce) {
			plist_dict_set_item(parameters, "BbNonce", plist_new_data((const char*)bb_nonce, bb_nonce_size));
		}
		plist_dict_set_item(parameters, "BbChipID", plist_new_uint(bb_chip_id));
		plist_dict_set_item(parameters, "BbGoldCertId", plist_new_uint(bb_cert_id));
		plist_dict_set_item(parameters, "BbSNUM", plist_new_data((const char*)bb_snum, bb_snum_size));

		tss_parameters_add_from_manifest(parameters, build_identity);

		/* create baseband request */
		plist_t request = tss_request_new(NULL);
		if (request == NULL) {
			error("ERROR: Unable to create Baseband TSS request\n");
			plist_free(parameters);
			return -1;
		}

		/* add baseband parameters */
		tss_request_add_common_tags(request, parameters, NULL);
		tss_request_add_baseband_tags(request, parameters, NULL);

		if (idevicerestore_debug)
			debug_plist(request);

		info("Sending Baseband TSS request...\n");
		response = tss_request_send(request, client->tss_url);
		plist_free(request);
		plist_free(parameters);
		if (response == NULL) {
			error("ERROR: Unable to fetch Baseband TSS\n");
			return -1;
		}
		info("Received Baseband SHSH blobs\n");

		if (idevicerestore_debug)
			debug_plist(response);
	}

	// get baseband firmware file path from build identity
	plist_t bbfw_path = plist_access_path(build_identity, 4, "Manifest", "BasebandFirmware", "Info", "Path");
	if (!bbfw_path || plist_get_node_type(bbfw_path) != PLIST_STRING) {
		error("ERROR: Unable to get BasebandFirmware/Info/Path node\n");
		plist_free(response);
		return -1;
	}
	char* bbfwpath = NULL;
	plist_get_string_val(bbfw_path, &bbfwpath);	
	if (!bbfwpath) {
		error("ERROR: Unable to get baseband path\n");
		plist_free(response);
		return -1;
	}

	// extract baseband firmware to temp file
	bbfwtmp = tempnam(NULL, "bbfw_");
	if (!bbfwtmp) {
		error("WARNING: Could not generate temporary filename, using bbfw.tmp\n");
		bbfwtmp = strdup("bbfw.tmp");
	}
	if (ipsw_extract_to_file(client->ipsw, bbfwpath, bbfwtmp) != 0) {
		error("ERROR: Unable to extract baseband firmware from ipsw\n");
		plist_free(response);
		return -1;
	}

	if (bb_nonce && !client->restore->bbtss) {
		// keep the response for later requests
		client->restore->bbtss = response;
		response = NULL;
	}

	res = restore_sign_bbfw(bbfwtmp, (client->restore->bbtss) ? client->restore->bbtss : response, bb_nonce);
	if (res != 0) {
		goto leave;
	}

	res = -1;
	
	size_t sz = 0;
	if (read_file(bbfwtmp, (void**)&buffer, &sz) < 0) {
		error("ERROR: could not read updated bbfw archive\n");
		goto leave;
	}

	// send file
	dict = plist_new_dict();
	plist_dict_set_item(dict, "BasebandData", plist_new_data(buffer, (uint64_t)sz));
	free(buffer);
	buffer = NULL;

	info("Sending BasebandData now...\n");
	if (restored_send(restore, dict) != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send BasebandData data\n");
		goto leave;
	}

	info("Done sending BasebandData\n");
	plist_free(dict);
	dict = NULL;

	res = 0;

leave:
	if (dict) {
		plist_free(dict);
	}
	if (buffer) {
		free(buffer);
	}
	if (bbfwtmp) {
		remove(bbfwtmp);
		free(bbfwtmp);
	}
	if (response) {
		plist_free(response);
	}

	return res;
}

int restore_send_fdr_trust_data(restored_client_t restore, idevice_t device)
{
	restored_error_t restore_error;
	plist_t dict;

	info("About to send FDR Trust data...\n");

	// FIXME: What should we send here?
	/* Sending an empty dict makes it continue with FDR
	 * and this is what iTunes seems to be doing too */
	dict = plist_new_dict();

	info("Sending FDR Trust data now...\n");
	restore_error = restored_send(restore, dict);
	plist_free(dict);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: During sending FDR Trust data (%d)\n", restore_error);
		return -1;
	}

	info("Done sending FDR Trust Data\n");

	return 0;
}

int restore_handle_data_request_msg(struct idevicerestore_client_t* client, idevice_t device, restored_client_t restore, plist_t message, plist_t build_identity, const char* filesystem)
{
	char* type = NULL;
	plist_t node = NULL;

	// checks and see what kind of data restored is requests and pass
	// the request to its own handler
	node = plist_dict_get_item(message, "DataType");
	if (node && PLIST_STRING == plist_get_node_type(node)) {
		plist_get_string_val(node, &type);

		// this request is sent when restored is ready to receive the filesystem
		if (!strcmp(type, "SystemImageData")) {
			if(restore_send_filesystem(client, device, filesystem) < 0) {
				error("ERROR: Unable to send filesystem\n");
				return -2;
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
				if(restore_send_nor(restore, client, build_identity) < 0) {
					error("ERROR: Unable to send NOR data\n");
					return -1;
				}
			} else {
				info("Not sending NORData... Quitting...\n");
				client->flags |= FLAG_QUIT;
			}
		}

		else if (!strcmp(type, "BasebandData")) {
			if(restore_send_baseband_data(restore, client, build_identity, message) < 0) {
				error("ERROR: Unable to send baseband data\n");
				return -1;
			}
		}

		else if (!strcmp(type, "FDRTrustData")) {
			if(restore_send_fdr_trust_data(restore, device) < 0) {
				error("ERROR: Unable to send FDR Trust data\n");
				return -1;
			}
		}

		else {
			// Unknown DataType!!
			error("Unknown data request '%s' received\n", type);
			if (idevicerestore_debug)
				debug_plist(message);
		}
	}
	return 0;
}

int restore_device(struct idevicerestore_client_t* client, plist_t build_identity, const char* filesystem) {
	int err = 0;
	char* type = NULL;
	plist_t node = NULL;
	plist_t message = NULL;
	plist_t hwinfo = NULL;
	idevice_t device = NULL;
	restored_client_t restore = NULL;
	restored_error_t restore_error = RESTORE_E_SUCCESS;

	restore_finished = 0;

	// open our connection to the device and verify we're in restore mode
	err = restore_open_with_timeout(client);
	if (err < 0) {
		error("ERROR: Unable to open device in restore mode\n");
		return (err == -2) ? -1: -2;
	}
	info("Device has successfully entered restore mode\n");

	restore = client->restore->client;
	device = client->restore->device;

	restore_error = restored_query_value(restore, "HardwareInfo", &hwinfo);
	if (restore_error == RESTORE_E_SUCCESS) {
		uint64_t i = 0;
		uint8_t b = 0;
		info("Hardware Information:\n");

		node = plist_dict_get_item(hwinfo, "BoardID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("BoardID: %d\n", (int)i);
		}

		node = plist_dict_get_item(hwinfo, "ChipID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("ChipID: %d\n", (int)i);
		}

		node = plist_dict_get_item(hwinfo, "UniqueChipID");
		if (node && plist_get_node_type(node) == PLIST_UINT) {
			plist_get_uint_val(node, &i);
			info("UniqueChipID: " FMT_qu "\n", (long long unsigned int)i);
		}

		node = plist_dict_get_item(hwinfo, "ProductionMode");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			plist_get_bool_val(node, &b);
			info("ProductionMode: %s\n", (b==1) ? "true":"false");
		}
		plist_free(hwinfo);
	}

	restore_error = restored_query_value(restore, "SavedDebugInfo", &hwinfo);
	if (restore_error == RESTORE_E_SUCCESS) {
		char* sval = NULL;

		node = plist_dict_get_item(hwinfo, "PreviousExitStatus");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("Previous restore exit status: %s\n", sval);
			free(sval);
			sval = NULL;
		}

		node = plist_dict_get_item(hwinfo, "USBLog");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("USB log is available:\n%s\n", sval);
			free(sval);
			sval = NULL;
		}

		node = plist_dict_get_item(hwinfo, "PanicLog");
		if (node && plist_get_node_type(node) == PLIST_STRING) {
			plist_get_string_val(node, &sval);
			info("Panic log is available:\n%s\n", sval);
			free(sval);
			sval = NULL;
		}
		plist_free(hwinfo);
	}

	if (plist_dict_get_item(client->tss, "BBTicket")) {
		client->restore->bbtss = plist_copy(client->tss);
	}

	plist_t opts = plist_new_dict();
	// FIXME: required?
	//plist_dict_set_item(opts, "AuthInstallRestoreBehavior", plist_new_string("Erase"));
	plist_dict_set_item(opts, "AutoBootDelay", plist_new_uint(0));

	if (client->preflight_info) {
		plist_t node;
		plist_t bbus = plist_copy(client->preflight_info);	

		plist_dict_remove_item(bbus, "FusingStatus");
		plist_dict_remove_item(bbus, "PkHash");

		plist_dict_set_item(opts, "BBUpdaterState", bbus);

		node = plist_dict_get_item(client->preflight_info, "Nonce");
		if (node) {
			plist_dict_set_item(opts, "BasebandNonce", plist_copy(node));
		}
	}

	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "BootImageType", plist_new_string("UserOrInternal"));
	// FIXME: required?
	//plist_dict_set_item(opts, "BootImageFile", plist_new_string("018-7923-347.dmg"));
	plist_dict_set_item(opts, "CreateFilesystemPartitions", plist_new_bool(1));
	plist_dict_set_item(opts, "DFUFileType", plist_new_string("RELEASE"));
	plist_dict_set_item(opts, "DataImage", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "DeviceTreeFile", plist_new_string("DeviceTree.k48ap.img3"));
	plist_dict_set_item(opts, "FirmwareDirectory", plist_new_string("."));
	// FIXME: usable if false? (-x parameter)
	plist_dict_set_item(opts, "FlashNOR", plist_new_bool(1));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "KernelCacheFile", plist_new_string("kernelcache.release.k48"));
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "KernelCacheType", plist_new_string("Release"));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "NORImagePath", plist_new_string("."));
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "NORImageType", plist_new_string("production"));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "PersonalizedRestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	if (client->restore_boot_args) {
		plist_dict_set_item(opts, "RestoreBootArgs", plist_new_string(client->restore_boot_args));
	}
	plist_dict_set_item(opts, "RestoreBundlePath", plist_new_string("/tmp/Per2.tmp"));
	plist_dict_set_item(opts, "RootToInstall", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "SourceRestoreBundlePath", plist_new_string("/tmp"));
	plist_dict_set_item(opts, "SystemImage", plist_new_bool(1));
	plist_t spp = plist_new_dict();
	{
		plist_dict_set_item(spp, "128", plist_new_uint(1280));
		plist_dict_set_item(spp, "16", plist_new_uint(160));
		plist_dict_set_item(spp, "32", plist_new_uint(320));
		plist_dict_set_item(spp, "64", plist_new_uint(640));
		plist_dict_set_item(spp, "8", plist_new_uint(80));
	}
	// FIXME: new on iOS 5 ?
	plist_dict_set_item(opts, "SystemImageType", plist_new_string("User"));

	plist_dict_set_item(opts, "SystemPartitionPadding", spp);
	char* guid = generate_guid();
	if (guid) {
		plist_dict_set_item(opts, "UUID", plist_new_string(guid));
		free(guid);
	}
	// FIXME: does this have any effect actually?
	plist_dict_set_item(opts, "UpdateBaseband", plist_new_bool(0));
	// FIXME: not required for iOS 5?
	//plist_dict_set_item(opts, "UserLocale", plist_new_string("en_US"));

	/* this is mandatory on iOS 7+ to allow restore from normal mode */
	plist_dict_set_item(opts, "PersonalizedDuringPreflight", plist_new_bool(1));

	// start the restore process
	restore_error = restored_start_restore(restore, opts, client->restore->protocol_version);
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start the restore process\n");
		plist_free(opts);
		restore_client_free(client);
		return -1;
	}
	plist_free(opts);
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 1.0);

	// this is the restore process loop, it reads each message in from
	// restored and passes that data on to it's specific handler
	while ((client->flags & FLAG_QUIT) == 0) {
		// finally, if any of these message handlers returned -1 then we encountered
		// an unrecoverable error, so we need to bail.
		if (err < 0) {
			error("ERROR: Unable to successfully restore device\n");
			client->flags |= FLAG_QUIT;
		}

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
		// SystemImageData, RootTicket, KernelCache, NORData and BasebandData requests
		if (!strcmp(type, "DataRequestMsg")) {
			err = restore_handle_data_request_msg(client, device, restore, message, build_identity, filesystem);
		}

		// restore logs are available if a previous restore failed
		else if (!strcmp(type, "PreviousRestoreLogMsg")) {
			err = restore_handle_previous_restore_log_msg(restore, message);
		}

		// progress notification messages sent by the restored inform the client
		// of it's current operation and sometimes percent of progress is complete
		else if (!strcmp(type, "ProgressMsg")) {
			err = restore_handle_progress_msg(client, message);
		}

		// status messages usually indicate the current state of the restored
		// process or often to signal an error has been encountered
		else if (!strcmp(type, "StatusMsg")) {
			err = restore_handle_status_msg(restore, message);
			if (restore_finished) {
				client->flags |= FLAG_QUIT;
			}
		}

		// baseband update message
		else if (!strcmp(type, "BBUpdateStatusMsg")) {
			err = restore_handle_bb_update_status_msg(restore, message);
		}

		// there might be some other message types i'm not aware of, but I think
		// at least the "previous error logs" messages usually end up here
		else {
			debug("Unknown message type received\n");
			//if (idevicerestore_debug)
				debug_plist(message);
		}

		if (type)
			free(type);

		plist_free(message);
		message = NULL;
	}

	restore_client_free(client);
	return err;
}
