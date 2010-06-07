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

#include "tss.h"
#include "restore.h"
#include "idevicerestore.h"

#define ASR_PORT 12345

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
	if(restore_error != RESTORE_E_SUCCESS) {
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
		if(node) plist_free(node);
		return -1;
	}
	plist_get_string_val(node, &model);

	for(i = 0; idevicerestore_devices[i].model != NULL; i++) {
		if(!strcasecmp(model, idevicerestore_devices[i].model)) {
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
	}
}

int restore_open_with_timeout(const char* uuid, idevice_t* device, restored_client_t* restore) {
	int i = 0;
	int attempt = 10;
	char* type = NULL;
	uint64_t version = 0;
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

	for (i = 1; i <= attempt; i++) {
		if (restore_device_connected == 1) {
			break;
		}

		if (i == attempt) {
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

	restore_error = restored_query_type(client, &type, &version);
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
	//idevice_event_unsubscribe();
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
	uint64_t operation = 0;
	uint64_t uprogress = 0;
	uint64_t progress = 0;

	node = plist_dict_get_item(msg, "Operation");
	if (node && PLIST_UINT == plist_get_node_type(node)) {
		plist_get_uint_val(node, &operation);
	} else {
		debug("Failed to parse operation from ProgressMsg plist\n");
		return 0;
	}

	node = plist_dict_get_item(msg, "Progress");
	if (node && PLIST_UINT == plist_get_node_type(node)) {
		plist_get_uint_val(node, &uprogress);
		progress = uprogress;
	} else {
		debug("Failed to parse progress from ProgressMsg plist \n");
		return 0;
	}

	if ((progress > 0) && (progress < 100))
		info("%s - Progress: %llu%%\n", restore_progress_string(operation), progress);
	else
		info("%s\n", restore_progress_string(operation));

	return 0;
}

int restore_handle_status_msg(restored_client_t client, plist_t msg) {
	info("Got status message\n");
	return 0;
}

int restore_send_filesystem(idevice_t device, restored_client_t client, const char* filesystem) {
	int i = 0;
	char buffer[0x1000];
	uint32_t recv_bytes = 0;
	memset(buffer, '\0', 0x1000);
	idevice_connection_t connection = NULL;
	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;

	for (i = 0; i < 5; i++) {
		ret = idevice_connect(device, ASR_PORT, &connection);
		if (ret == IDEVICE_E_SUCCESS)
			break;

		else
			sleep(1);
	}

	if (ret != IDEVICE_E_SUCCESS)
		return ret;

	memset(buffer, '\0', 0x1000);
	ret = idevice_connection_receive(connection, buffer, 0x1000, &recv_bytes);
	if (ret != IDEVICE_E_SUCCESS) {
		idevice_disconnect(connection);
		return ret;
	}
	info("Received %d bytes\n", recv_bytes);
	info("%s", buffer);

	FILE* fd = fopen(filesystem, "rb");
	if (fd == NULL) {
		idevice_disconnect(connection);
		return ret;
	}

	fseek(fd, 0, SEEK_END);
	uint64_t len = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	info("Connected to ASR\n");
	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "FEC Slice Stride", plist_new_uint(40));
	plist_dict_insert_item(dict, "Packet Payload Size", plist_new_uint(1450));
	plist_dict_insert_item(dict, "Packets Per FEC", plist_new_uint(25));

	plist_t payload = plist_new_dict();
	plist_dict_insert_item(payload, "Port", plist_new_uint(1));
	plist_dict_insert_item(payload, "Size", plist_new_uint(len));
	plist_dict_insert_item(dict, "Payload", payload);

	plist_dict_insert_item(dict, "Stream ID", plist_new_uint(1));
	plist_dict_insert_item(dict, "Version", plist_new_uint(1));

	char* xml = NULL;
	unsigned int dict_size = 0;
	unsigned int sent_bytes = 0;
	plist_to_xml(dict, &xml, &dict_size);

	ret = idevice_connection_send(connection, xml, dict_size, &sent_bytes);
	if (ret != IDEVICE_E_SUCCESS) {
		idevice_disconnect(connection);
		return ret;
	}

	info("Sent %d bytes\n", sent_bytes);
	info("%s", xml);
	plist_free(dict);
	free(xml);

	char* command = NULL;
	do {
		memset(buffer, '\0', 0x1000);
		ret = idevice_connection_receive(connection, buffer, 0x1000, &recv_bytes);
		if (ret != IDEVICE_E_SUCCESS) {
			idevice_disconnect(connection);
			return ret;
		}
		info("Received %d bytes\n", recv_bytes);
		info("%s", buffer);

		plist_t request = NULL;
		plist_from_xml(buffer, recv_bytes, &request);
		plist_t command_node = plist_dict_get_item(request, "Command");
		if (command_node && PLIST_STRING == plist_get_node_type(command_node)) {
			plist_get_string_val(command_node, &command);
			if (!strcmp(command, "OOBData")) {
				plist_t oob_length_node = plist_dict_get_item(request, "OOB Length");
				if (!oob_length_node || PLIST_UINT != plist_get_node_type(oob_length_node)) {
					error("Error fetching OOB Length\n");
					idevice_disconnect(connection);
					return IDEVICE_E_UNKNOWN_ERROR;
				}
				uint64_t oob_length = 0;
				plist_get_uint_val(oob_length_node, &oob_length);

				plist_t oob_offset_node = plist_dict_get_item(request, "OOB Offset");
				if (!oob_offset_node || PLIST_UINT != plist_get_node_type(oob_offset_node)) {
					error("Error fetching OOB Offset\n");
					idevice_disconnect(connection);
					return IDEVICE_E_UNKNOWN_ERROR;
				}
				uint64_t oob_offset = 0;
				plist_get_uint_val(oob_offset_node, &oob_offset);

				char* oob_data = (char*) malloc(oob_length);
				if (oob_data == NULL) {
					error("Out of memory\n");
					idevice_disconnect(connection);
					return IDEVICE_E_UNKNOWN_ERROR;
				}

				fseek(fd, oob_offset, SEEK_SET);
				if (fread(oob_data, 1, oob_length, fd) != oob_length) {
					error("Unable to read filesystem offset\n");
					idevice_disconnect(connection);
					free(oob_data);
					return ret;
				}

				ret = idevice_connection_send(connection, oob_data, oob_length, &sent_bytes);
				if (sent_bytes != oob_length || ret != IDEVICE_E_SUCCESS) {
					error("Unable to send %d bytes to asr\n", sent_bytes);
					idevice_disconnect(connection);
					free(oob_data);
					return ret;
				}
				plist_free(request);
				free(oob_data);
			}
		}

	} while (strcmp(command, "Payload"));

	fseek(fd, 0, SEEK_SET);
	char data[1450];
	for (i = len; i > 0; i -= 1450) {
		int size = 1450;
		if (i < 1450) {
			size = i;
		}

		if (fread(data, 1, size, fd) != (unsigned int) size) {
			fclose(fd);
			idevice_disconnect(connection);
			error("Error reading filesystem\n");
			return IDEVICE_E_UNKNOWN_ERROR;
		}

		ret = idevice_connection_send(connection, data, size, &sent_bytes);
		if (ret != IDEVICE_E_SUCCESS) {
			fclose(fd);
		}

		if (i % (1450 * 1000) == 0) {
			info(".");
		}
	}

	info("Done sending filesystem\n");
	fclose(fd);
	ret = idevice_disconnect(connection);
	return ret;
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

	int sz = 0;
	char* xml = NULL;
	plist_to_xml(dict, &xml, &sz);
	debug("%s", xml);
	free(xml);

	restored_error_t ret = restored_send(client, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to send kernelcache data\n");
		plist_free(dict);
		return -1;
	}

	plist_free(dict);
	return 0;
}

int restore_device(const char* uuid, const char* ipsw, plist_t tss, const char* filesystem) {
	idevice_t device = NULL;
	idevice_error_t device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to open device\n");
		plist_free(tss);
		return -1;
	}

	restored_client_t restore = NULL;
	restored_error_t restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start restored client\n");
		plist_free(tss);
		idevice_free(device);
		return -1;
	}

	char* type = NULL;
	uint64_t version = 0;
	if (restored_query_type(restore, &type, &version) != RESTORE_E_SUCCESS) {
		error("ERROR: Device is not in restore mode. QueryType returned \"%s\"\n", type);
		plist_free(tss);
		restored_client_free(restore);
		idevice_free(device);
		return -1;
	}
	info("Device has successfully entered restore mode\n");

	/* start restore process */
	char* kernelcache = NULL;
	info("Restore protocol version is %llu.\n", version);
	restore_error = restored_start_restore(restore);
	if (restore_error == RESTORE_E_SUCCESS) {
		while (!idevicerestore_quit) {
			plist_t message = NULL;
			restore_error = restored_receive(restore, &message);
			plist_t msgtype_node = plist_dict_get_item(message, "MsgType");
			if (msgtype_node && PLIST_STRING == plist_get_node_type(msgtype_node)) {
				char *msgtype = NULL;
				plist_get_string_val(msgtype_node, &msgtype);
				if (!strcmp(msgtype, "ProgressMsg")) {
					restore_error = restore_handle_progress_msg(restore, message);

				} else if (!strcmp(msgtype, "DataRequestMsg")) {
					// device is requesting data to be sent
					plist_t datatype_node = plist_dict_get_item(message, "DataType");
					if (datatype_node && PLIST_STRING == plist_get_node_type(datatype_node)) {
						char *datatype = NULL;
						plist_get_string_val(datatype_node, &datatype);
						if (!strcmp(datatype, "SystemImageData")) {
							restore_send_filesystem(device, restore, filesystem);

						} else if (!strcmp(datatype, "KernelCache")) {
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

						} else if (!strcmp(datatype, "NORData")) {
							restore_send_nor(restore, ipsw, tss);

						} else {
							// Unknown DataType!!
							error("Unknown DataType\n");
							return -1;
						}
					}

				} else if (!strcmp(msgtype, "StatusMsg")) {
					restore_error = restore_handle_status_msg(restore, message);

				} else {
					info("Received unknown message type: %s\n", msgtype);
				}
			}

			if (RESTORE_E_SUCCESS != restore_error) {
				error("Invalid return status %d\n", restore_error);
				//idevicerestore_quit = 1;
			}

			plist_free(message);
		}
	} else {
		error("ERROR: Could not start restore. %d\n", restore_error);
	}

	restored_client_free(restore);
	idevice_free(device);
	return 0;
}
