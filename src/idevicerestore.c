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
#include <libimobiledevice/restore.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>

#include "tss.h"
#include "img3.h"
#include "ipsw.h"
#include "idevicerestore.h"

#define UNKNOWN_MODE   0
#define NORMAL_MODE    1
#define RECOVERY_MODE  2
#define RESTORE_MODE   3

#define ASR_PORT       12345

int idevicerestore_debug = 0;
static int idevicerestore_mode = 0;

void usage(int argc, char* argv[]);
int write_file(const char* filename, char* data, int size);
int send_ibec(char* ipsw, plist_t tss);
int send_applelogo(char* ipsw, plist_t tss);
int send_devicetree(char* ipsw, plist_t tss);
int send_ramdisk(char* ipsw, plist_t tss);
int send_kernelcache(char* ipsw, plist_t tss);
int get_tss_data(plist_t tss, const char* entry, char** path, char** blob);
void device_callback(const idevice_event_t* event, void *user_data);

int main(int argc, char* argv[]) {
	int opt = 0;
	char* ipsw = NULL;
	char* uuid = NULL;
	uint64_t ecid = 0;
	while ((opt = getopt(argc, argv, "vdhu:")) > 0) {
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

		case 'u':
			uuid = optarg;
			break;

		default:
			usage(argc, argv);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		ipsw = argv[0];

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
	device_error = 1;//idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		info("Checking for the device in recovery mode...\n");
		recovery_error = irecv_open(&recovery);
		if (recovery_error != IRECV_E_SUCCESS) {
			error("ERROR: Unable to find device, is it plugged in?\n");
			return -1;
		}
		info("Found device in recovery mode\n");
		idevicerestore_mode = RECOVERY_MODE;

	} else {
		info("Found device in normal mode\n");
		idevicerestore_mode = NORMAL_MODE;
	}

	if (idevicerestore_mode == NORMAL_MODE) {
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

	} else if (idevicerestore_mode == RECOVERY_MODE) {
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

	int  buildmanifest_size = 0;
	char* buildmanifest_data = NULL;
	info("Extracting BuildManifest.plist from IPSW\n");
	if (ipsw_extract_to_memory(ipsw, "BuildManifest.plist", &buildmanifest_data, &buildmanifest_size) < 0) {
		error("ERROR: Unable to extract BuildManifest.plist IPSW\n");
		return -1;
	}

	plist_t manifest = NULL;
	plist_from_xml(buildmanifest_data, buildmanifest_size, &manifest);

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
	info("Got TSS response\n");

	// Get name of filesystem DMG in IPSW
	char* filesystem = NULL;
	plist_t filesystem_node = plist_dict_get_item(tss_request, "OS");
	if (!filesystem_node || plist_get_node_type(filesystem_node) != PLIST_DICT) {
		error("ERROR: Unable to find OS filesystem\n");
		plist_free(tss_request);
		return -1;
	}

	plist_t filesystem_info_node = plist_dict_get_item(filesystem_node, "Info");
	if (!filesystem_info_node || plist_get_node_type(filesystem_info_node) != PLIST_DICT) {
		error("ERROR: Unable to find filesystem info node\n");
		plist_free(tss_request);
		return -1;
	}

	plist_t filesystem_info_path_node = plist_dict_get_item(filesystem_info_node, "Path");
	if (!filesystem_info_path_node || plist_get_node_type(filesystem_info_path_node) != PLIST_STRING) {
		error("ERROR: Unable to find filesystem info path node\n");
		plist_free(tss_request);
		return -1;
	}
	plist_get_string_val(filesystem_info_path_node, &filesystem);
	plist_free(tss_request);

	info("Extracting filesystem from IPSW\n");
	if(ipsw_extract_to_file(ipsw, filesystem, filesystem) < 0) {
		error("ERROR: Unable to extract filesystem\n");
		return -1;
	}

	if (idevicerestore_mode == NORMAL_MODE) {
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
		plist_free(tss_response);
		return -1;
	}
	sleep(1);

	if (send_applelogo(ipsw, tss_response) < 0) {
		error("ERROR: Unable to send AppleLogo\n");
		plist_free(tss_response);
		return -1;
	}

	if (send_devicetree(ipsw, tss_response) < 0) {
		error("ERROR: Unable to send DeviceTree\n");
		plist_free(tss_response);
		return -1;
	}

	if (send_ramdisk(ipsw, tss_response) < 0) {
		error("ERROR: Unable to send Ramdisk\n");
		plist_free(tss_response);
		return -1;
	}

	printf("Please unplug your device, then plug it back in\n");
	printf("Hit any key to continue...");
	getchar();

	if (send_kernelcache(ipsw, tss_response) < 0) {
		error("ERROR: Unable to send KernelCache\n");
		plist_free(tss_response);
		return -1;
	}

	//idevice_event_subscribe(&device_callback, NULL);
	info("Waiting for device to enter restore mode\n");
	while (idevicerestore_mode != RESTORE_MODE) {
		device_error = idevice_new(&device, uuid);
		if (device_error == IDEVICE_E_SUCCESS) {
			idevicerestore_mode = RESTORE_MODE;
			break;
		}
		sleep(2);
		info("Got response %d\n", device_error);
		info("Retrying connection...\n");
		//plist_free(tss_response);
		//return -1;
	}
	idevice_set_debug_level(5);
	restored_client_t restore = NULL;
	restored_error_t restore_error = restored_client_new(device, &restore, "idevicerestore");
	if (restore_error != RESTORE_E_SUCCESS) {
		error("ERROR: Unable to start restored client\n");
		plist_free(tss_response);
		idevice_free(device);
		return -1;
	}

	char* type = NULL;
	uint64_t version = 0;
	if (restored_query_type(restore, &type, &version) != RESTORE_E_SUCCESS) {
		printf("ERROR: Device is not in restore mode. QueryType returned \"%s\"\n", type);
		plist_free(tss_response);
		restored_client_free(restore);
		idevice_free(device);
		return -1;
	}
	info("Device has successfully entered restore mode\n");

	/* start restored service and retrieve port */
	int quit_flag = 0;
	char* kernelcache = NULL;
	printf("Restore protocol version is %llu.\n", version);
	restore_error = restored_start_restore(restore);
	if (restore_error == RESTORE_E_SUCCESS) {
		while (!quit_flag) {
			plist_t message = NULL;
			restore_error = restored_receive(restore, &message);
			plist_t msgtype_node = plist_dict_get_item(message, "MsgType");
			if (msgtype_node && PLIST_STRING == plist_get_node_type(msgtype_node)) {
				char *msgtype = NULL;
				plist_get_string_val(msgtype_node, &msgtype);
				if (!strcmp(msgtype, "ProgressMsg")) {
					restore_error = progress_msg(restore, message);

				} else if (!strcmp(msgtype, "DataRequestMsg")) {
					//restore_error = data_request_msg(device, restore, message, filesystem);
					plist_t datatype_node = plist_dict_get_item(message, "DataType");
					if (datatype_node && PLIST_STRING == plist_get_node_type(datatype_node)) {
						char *datatype = NULL;
						plist_get_string_val(datatype_node, &datatype);
						if (!strcmp(datatype, "SystemImageData")) {
							send_system_data(device, restore, filesystem);
						} else if (!strcmp(datatype, "KernelCache")) {
							send_kernel_data(device, restore, kernelcache);
						} else if (!strcmp(datatype, "NORData")) {
							send_nor_data(device, restore);
						} else {
							// Unknown DataType!!
							error("Unknown DataType\n");
							return -1;
						}
					}

				} else if (!strcmp(msgtype, "StatusMsg")) {
					restore_error = status_msg(restore, message);

				} else {
					printf("Received unknown message type: %s\n", msgtype);
				}
			}

			if (RESTORE_E_SUCCESS != restore_error) {
				printf("Invalid return status %d\n", restore_error);
			}

			plist_free(message);
		}
	} else {
		printf("ERROR: Could not start restore. %d\n", restore_error);
	}

	restored_client_free(restore);
	idevice_free(device);
	plist_free(tss_response);
	return 0;
}

void device_callback(const idevice_event_t* event, void *user_data) {
	if (event->event == IDEVICE_DEVICE_ADD) {
		idevicerestore_mode = RESTORE_MODE;
	}
}

void usage(int argc, char* argv[]) {
	char *name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] FILE\n", (name ? name + 1 : argv[0]));
	printf("Restore/upgrade IPSW firmware FILE to an iPhone/iPod Touch.\n");
	printf("  -d, \t\tenable communication debugging\n");
	printf("  -u, \t\ttarget specific device by its 40-digit device UUID\n");
	printf("  -h, \t\tprints usage information\n");
	printf("  -v, \t\tenable incremental levels of verboseness\n");
	printf("\n");
	exit(1);
}

int progress_msg(restored_client_t client, plist_t msg) {
	info("Got progress message\n");
	return 0;
}

int data_request_msg(idevice_t device, restored_client_t client, plist_t msg, const char *filesystem, const char *kernel) {
	plist_t datatype_node = plist_dict_get_item(msg, "DataType");
	if (datatype_node && PLIST_STRING == plist_get_node_type(datatype_node)) {
		char *datatype = NULL;
		plist_get_string_val(datatype_node, &datatype);
		if (!strcmp(datatype, "SystemImageData")) {
			send_system_data(device, client, filesystem);
		} else if (!strcmp(datatype, "KernelCache")) {
			send_kernel_data(device, client, kernel);
		} else if (!strcmp(datatype, "NORData")) {
			send_nor_data(device, client);
		} else {
			// Unknown DataType!!
			error("Unknown DataType\n");
			return -1;
		}
	}
	return 0;
}

int status_msg(restored_client_t client, plist_t msg) {
	info("Got status message\n");
	return 0;
}

int send_system_data(idevice_t device, restored_client_t client, const char *filesystem) {
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
	printf("Received %d bytes\n", recv_bytes);
	printf("%s", buffer);

	FILE* fd = fopen(filesystem, "rb");
	if (fd == NULL) {
		idevice_disconnect(connection);
		return ret;
	}

	fseek(fd, 0, SEEK_END);
	uint64_t len = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	printf("Connected to ASR\n");
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

	printf("Sent %d bytes\n", sent_bytes);
	printf("%s", xml);
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
					printf("Error fetching OOB Length\n");
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
					printf("Unable to send %d bytes to asr\n", sent_bytes);
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
			printf("Error reading filesystem\n");
			return IDEVICE_E_UNKNOWN_ERROR;
		}

		ret = idevice_connection_send(connection, data, size, &sent_bytes);
		if (ret != IDEVICE_E_SUCCESS) {
			fclose(fd);
		}

		if (i % (1450 * 1000) == 0) {
			printf(".");
		}
	}

	printf("Done sending filesystem\n");
	fclose(fd);
	ret = idevice_disconnect(connection);
	return ret;
}

int send_kernel_data(idevice_t device, restored_client_t client, const char *kernel) {
	printf("Sending kernelcache\n");
	FILE* fd = fopen(kernel, "rb");
	if (fd == NULL) {
		info("Unable to open kernelcache");
		return -1;
	}

	fseek(fd, 0, SEEK_END);
	uint64_t len = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	char* kernel_data = (char*) malloc(len);
	if (kernel_data == NULL) {
		error("Unable to allocate memory for kernel data");
		fclose(fd);
		return -1;
	}

	if (fread(kernel_data, 1, len, fd) != len) {
		error("Unable to read kernel data\n");
		free(kernel_data);
		fclose(fd);
		return -1;
	}
	fclose(fd);

	plist_t kernelcache_node = plist_new_data(kernel_data, len);

	plist_t dict = plist_new_dict();
	plist_dict_insert_item(dict, "KernelCacheFile", kernelcache_node);

	restored_error_t ret = restored_send(client, dict);
	if (ret != RESTORE_E_SUCCESS) {
		error("Unable to send kernelcache data\n");
		free(kernel_data);
		plist_free(dict);
		return -1;
	}

	info("Done sending kernelcache\n");
	free(kernel_data);
	plist_free(dict);
	return 0;
}

int send_nor_data(idevice_t device, restored_client_t client) {
	info("Not implemented\n");
	return 0;
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
		return -1;
	}
	plist_get_string_val(path_node, &path);

	char* blob = NULL;
	uint64_t blob_size = 0;
	plist_t blob_node = plist_dict_get_item(node, "Blob");
	if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find %s blob in entry\n", entry);
		free(path);
		return -1;
	}
	plist_get_data_val(blob_node, &blob, &blob_size);

	*ppath = path;
	*pblob = blob;
	return 0;
}

int send_ibec(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_error_t error = 0;
	irecv_client_t client = NULL;
	info("Sending iBEC...\n");
	for (i = 10; i > 0; i--) {
		error = irecv_open(&client);
		if (error == IRECV_E_SUCCESS) {
			irecv_send_command(client, "setenv auto-boot true");
			irecv_send_command(client, "saveenv");
			break;
		}

		if (i == 0) {
			error("Unable to connect to iBoot\n");
			return -1;
		}

		sleep(2);
		info("Retrying connection...\n");
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting data from TSS response\n");
	if (get_tss_data(tss, "iBEC", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	int ibec_size = 0;
	char* ibec_data = NULL;
	info("Extracting %s from %s\n", path, ipsw);
	if (ipsw_extract_to_memory(ipsw, path, &ibec_data, &ibec_size)) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(ibec_data, ibec_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		irecv_close(client);
		client = NULL;
		free(ibec_data);
		free(path);
		free(blob);
		return -1;
	}
	if (ibec_data) {
		free(ibec_data);
		ibec_data = NULL;
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

	if (idevicerestore_debug) {
		char* out = strrchr(path, '/');
		if (out != NULL) {
			out++;
		} else {
			out = path;
		}
		write_file(out, data, size);
	}

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

	if (client) {
		irecv_close(client);
		client = NULL;
	}
	return 0;
}

int send_applelogo(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_error_t error = 0;
	irecv_client_t client = NULL;
	info("Sending AppleLogo...\n");
	for (i = 10; i > 0; i--) {
		error = irecv_open(&client);
		if (error == IRECV_E_SUCCESS) {
			break;
		}

		if (i == 0) {
			error("Unable to connect to iBEC\n");
			return -1;
		}

		sleep(3);
		info("Retrying connection...\n");
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting data from TSS response\n");
	if (get_tss_data(tss, "RestoreLogo", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	int applelogo_size = 0;
	char* applelogo_data = NULL;
	info("Extracting %s from %s\n", path, ipsw);
	if (ipsw_extract_to_memory(ipsw, path, &applelogo_data, &applelogo_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(applelogo_data, applelogo_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		irecv_close(client);
		client = NULL;
		free(applelogo_data);
		free(path);
		free(blob);
		return -1;
	}
	if (applelogo_data) {
		free(applelogo_data);
		applelogo_data = NULL;
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

	if (idevicerestore_debug) {
		char* out = strrchr(path, '/');
		if (out != NULL) {
			out++;
		} else {
			out = path;
		}
		write_file(out, data, size);
	}

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

	error = irecv_send_command(client, "setpicture 1");
	error = irecv_send_command(client, "bgcolor 0 0 0");
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to set AppleLogo\n");
		irecv_close(client);
		client = NULL;
		free(data);
		return -1;
	}

	if (client) {
		irecv_close(client);
		client = NULL;
	}
	return 0;
}

int send_devicetree(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_error_t error = 0;
	irecv_client_t client = NULL;
	info("Sending DeviceTree...\n");
	for (i = 10; i > 0; i--) {
		error = irecv_open(&client);
		if (error == IRECV_E_SUCCESS) {
			break;
		}

		if (i == 0) {
			error("Unable to connect to iBEC\n");
			return -1;
		}

		sleep(3);
		info("Retrying connection...\n");
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting data from TSS response\n");
	if (get_tss_data(tss, "RestoreDeviceTree", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	int devicetree_size = 0;
	char* devicetree_data = NULL;
	info("Extracting %s from %s\n", path, ipsw);
	if (ipsw_extract_to_memory(ipsw, path, &devicetree_data, &devicetree_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(devicetree_data, devicetree_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		free(devicetree_data);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}
	if (devicetree_data) {
		free(devicetree_data);
		devicetree_data = NULL;
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

	if (idevicerestore_debug) {
		char* out = strrchr(path, '/');
		if (out != NULL) {
			out++;
		} else {
			out = path;
		}
		write_file(out, data, size);
	}

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

	error = irecv_send_command(client, "devicetree");
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute DeviceTree\n");
		irecv_close(client);
		client = NULL;
		free(data);
		return -1;
	}

	if (client) {
		irecv_close(client);
		client = NULL;
	}
	return 0;
}

int send_ramdisk(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_error_t error = 0;
	irecv_client_t client = NULL;
	info("Sending Ramdisk...\n");
	for (i = 10; i > 0; i--) {
		error = irecv_open(&client);
		if (error == IRECV_E_SUCCESS) {
			break;
		}

		if (i == 0) {
			error("Unable to connect to iBEC\n");
			return -1;
		}

		sleep(3);
		info("Retrying connection...\n");
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting data from TSS response\n");
	if (get_tss_data(tss, "RestoreRamDisk", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	int ramdisk_size = 0;
	char* ramdisk_data = NULL;
	info("Extracting %s from %s\n", path, ipsw);
	if (ipsw_extract_to_memory(ipsw, path, &ramdisk_data, &ramdisk_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(ramdisk_data, ramdisk_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		free(ramdisk_data);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}
	if (ramdisk_data) {
		free(ramdisk_data);
		ramdisk_data = NULL;
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

	if (idevicerestore_debug) {
		char* out = strrchr(path, '/');
		if (out != NULL) {
			out++;
		} else {
			out = path;
		}
		write_file(out, data, size);
	}

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

	error = irecv_send_command(client, "ramdisk");
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute Ramdisk\n");
		irecv_close(client);
		client = NULL;
		free(data);
		return -1;
	}

	if (client) {
		irecv_close(client);
		client = NULL;
	}
	return 0;
}

int send_kernelcache(char* ipsw, plist_t tss) {
	int i = 0;
	irecv_error_t error = 0;
	irecv_client_t client = NULL;
	info("Sending KernelCache...\n");
	for (i = 10; i > 0; i--) {
		error = irecv_open(&client);
		if (error == IRECV_E_SUCCESS) {
			break;
		}

		if (i == 0) {
			error("Unable to connect to iBEC\n");
			return -1;
		}

		sleep(3);
		info("Retrying connection...\n");
	}

	char* path = NULL;
	char* blob = NULL;
	info("Extracting data from TSS response\n");
	if (get_tss_data(tss, "RestoreKernelCache", &path, &blob) < 0) {
		error("ERROR: Unable to get data for TSS entry\n");
		irecv_close(client);
		client = NULL;
		return -1;
	}

	int kernelcache_size = 0;
	char* kernelcache_data = NULL;
	info("Extracting %s from %s\n", path, ipsw);
	if (ipsw_extract_to_memory(ipsw, path, &kernelcache_data, &kernelcache_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", path, ipsw);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}

	img3_file* img3 = img3_parse_file(kernelcache_data, kernelcache_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", path);
		free(kernelcache_data);
		irecv_close(client);
		client = NULL;
		free(path);
		free(blob);
		return -1;
	}
	if (kernelcache_data) {
		free(kernelcache_data);
		kernelcache_data = NULL;
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

	if (idevicerestore_debug) {
		char* out = strrchr(path, '/');
		if (out != NULL) {
			out++;
		} else {
			out = path;
		}
		write_file(out, data, size);
	}

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

	error = irecv_send_command(client, "bootx");
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute iBEC\n");
		irecv_close(client);
		client = NULL;
		free(data);
		return -1;
	}

	if (client) {
		irecv_set_configuration(client, 4);
		irecv_close(client);
		client = NULL;
	}
	return 0;
}
