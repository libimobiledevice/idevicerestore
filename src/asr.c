/*
 * asr.h
 * Functions for handling asr connections
 *
 * Copyright (c) 2010-2012 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen. All Rights Reserved.
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
#include <libimobiledevice/libimobiledevice.h>
#include <openssl/sha.h>

#include "asr.h"
#include "idevicerestore.h"
#include "common.h"

#define ASR_VERSION 1
#define ASR_STREAM_ID 1
#define ASR_PORT 12345
#define ASR_BUFFER_SIZE 65536
#define ASR_FEC_SLICE_STRIDE 40
#define ASR_PACKETS_PER_FEC 25
#define ASR_PAYLOAD_PACKET_SIZE 1450
#define ASR_CHECKSUM_CHUNK_SIZE 131072

int asr_open_with_timeout(idevice_t device, asr_client_t* asr) {
	int i = 0;
	int attempts = 10;
	idevice_connection_t connection = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;

	*asr = NULL;

	if (device == NULL) {
		return -1;
	}

	debug("Connecting to ASR\n");
	for (i = 1; i <= attempts; i++) {
		device_error = idevice_connect(device, ASR_PORT, &connection);
		if (device_error == IDEVICE_E_SUCCESS) {
			break;
		}

		if (i >= attempts) {
			error("ERROR: Unable to connect to ASR client\n");
			return -1;
		}

		sleep(2);
		debug("Retrying connection...\n");
	}

	asr_client_t asr_loc = (asr_client_t)malloc(sizeof(struct asr_client));
	memset(asr_loc, '\0', sizeof(struct asr_client));
	asr_loc->connection = connection;

	/* receive Initiate command message */
	plist_t data = NULL;
	asr_loc->checksum_chunks = 0;
	if (asr_receive(asr_loc, &data) < 0) {
		error("ERROR: Unable to receive data from ASR\n");
		asr_free(asr_loc);
		plist_free(data);
		return -1;
	}
	plist_t node;
	node = plist_dict_get_item(data, "Command");
	if (node && (plist_get_node_type(node) == PLIST_STRING)) {
		char* strval = NULL;
		plist_get_string_val(node, &strval);
		if (strval && (strcmp(strval, "Initiate") != 0)) {
			error("ERROR: unexpected ASR plist received:\n");
			debug_plist(data);
			plist_free(data);
			asr_free(asr_loc);
			return -1;
		}
	}

	node = plist_dict_get_item(data, "Checksum Chunks");
	if (node && (plist_get_node_type(node) == PLIST_BOOLEAN)) {
		plist_get_bool_val(node, &(asr_loc->checksum_chunks));
	}
	plist_free(data);

	*asr = asr_loc;

	return 0;
}

void asr_set_progress_callback(asr_client_t asr, asr_progress_cb_t cbfunc, void* userdata)
{
	if (!asr) {
		return;
	}
	asr->progress_cb = cbfunc;
	asr->progress_cb_data = userdata;
}

int asr_receive(asr_client_t asr, plist_t* data) {
	uint32_t size = 0;
	char* buffer = NULL;
	plist_t request = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;

	*data = NULL;

	buffer = (char*) malloc(ASR_BUFFER_SIZE);
	if (buffer == NULL) {
		error("ERROR: Unable to allocate memory for ASR receive buffer\n");
		return -1;
	}
	memset(buffer, '\0', ASR_BUFFER_SIZE);

	device_error = idevice_connection_receive(asr->connection, buffer, ASR_BUFFER_SIZE, &size);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to receive data from ASR\n");
		free(buffer);
		return -1;
	}
	plist_from_xml(buffer, size, &request);

	*data = request;

	debug("Received %d bytes:\n", size);
	if (idevicerestore_debug)
		debug_plist(request);
	free(buffer);
	return 0;
}

int asr_send(asr_client_t asr, plist_t data) {
	uint32_t size = 0;
	char* buffer = NULL;

	plist_to_xml(data, &buffer, &size);
	if (asr_send_buffer(asr, buffer, size) < 0) {
		error("ERROR: Unable to send plist to ASR\n");
		free(buffer);
		return -1;
	}

	debug("Sent %d bytes:\n", size);

	if (buffer)
		free(buffer);
	return 0;
}

int asr_send_buffer(asr_client_t asr, const char* data, uint32_t size) {
	uint32_t bytes = 0;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;

	device_error = idevice_connection_send(asr->connection, data, size, &bytes);
	if (device_error != IDEVICE_E_SUCCESS || bytes != size) {
		error("ERROR: Unable to send data to ASR. Sent %u of %u bytes.\n", bytes, size);
		return -1;
	}

	debug("Sent %d bytes buffer\n", bytes);

	return 0;
}

void asr_free(asr_client_t asr) {
	if (asr != NULL) {
		if (asr->connection != NULL) {
			idevice_disconnect(asr->connection);
			asr->connection = NULL;
		}
		free(asr);
		asr = NULL;
	}
}

int asr_perform_validation(asr_client_t asr, const char* filesystem) {
	FILE* file = NULL;
	uint64_t length = 0;
	char* command = NULL;
	plist_t node = NULL;
	plist_t packet = NULL;
	plist_t packet_info = NULL;
	plist_t payload_info = NULL;
	int attempts = 0;

	file = fopen(filesystem, "rb");
	if (file == NULL) {
		return -1;
	}

	fseek(file, 0, SEEK_END);
	length = ftell(file);
	fseek(file, 0, SEEK_SET);

	payload_info = plist_new_dict();
	plist_dict_set_item(payload_info, "Port", plist_new_uint(1));
	plist_dict_set_item(payload_info, "Size", plist_new_uint(length));

	packet_info = plist_new_dict();
	if (asr->checksum_chunks) {
		plist_dict_set_item(packet_info, "Checksum Chunk Size", plist_new_uint(ASR_CHECKSUM_CHUNK_SIZE));
	}
	plist_dict_set_item(packet_info, "FEC Slice Stride", plist_new_uint(ASR_FEC_SLICE_STRIDE));
	plist_dict_set_item(packet_info, "Packet Payload Size", plist_new_uint(ASR_PAYLOAD_PACKET_SIZE));
	plist_dict_set_item(packet_info, "Packets Per FEC", plist_new_uint(ASR_PACKETS_PER_FEC));
	plist_dict_set_item(packet_info, "Payload", payload_info);
	plist_dict_set_item(packet_info, "Stream ID", plist_new_uint(ASR_STREAM_ID));
	plist_dict_set_item(packet_info, "Version", plist_new_uint(ASR_VERSION));

	if (asr_send(asr, packet_info)) {
		error("ERROR: Unable to sent packet information to ASR\n");
		plist_free(packet_info);
		return -1;
	}
	plist_free(packet_info);

	while (1) {
		if (asr_receive(asr, &packet) < 0) {
			error("ERROR: Unable to receive validation packet\n");
			return -1;
		}

		if (packet == NULL) {
			if (attempts < 5) {
				info("Retrying to receive validation packet... %d\n", attempts);
				attempts++;
				sleep(1);
				continue;
			}
		}

		attempts = 0;

		node = plist_dict_get_item(packet, "Command");
		if (!node || plist_get_node_type(node) != PLIST_STRING) {
			error("ERROR: Unable to find command node in validation request\n");
			return -1;
		}
		plist_get_string_val(node, &command);

		if (!strcmp(command, "OOBData")) {
			asr_handle_oob_data_request(asr, packet, file);
			plist_free(packet);
		} else if(!strcmp(command, "Payload")) {
			plist_free(packet);
			break;

		} else {
			error("ERROR: Unknown command received from ASR\n");
			plist_free(packet);
			return -1;
		}
	}

	return 0;
}

int asr_handle_oob_data_request(asr_client_t asr, plist_t packet, FILE* file) {
	char* oob_data = NULL;
	uint64_t oob_offset = 0;
	uint64_t oob_length = 0;
	plist_t oob_length_node = NULL;
	plist_t oob_offset_node = NULL;

	oob_length_node = plist_dict_get_item(packet, "OOB Length");
	if (!oob_length_node || PLIST_UINT != plist_get_node_type(oob_length_node)) {
		error("ERROR: Unable to find OOB data length\n");
		return -1;
	}
	plist_get_uint_val(oob_length_node, &oob_length);

	oob_offset_node = plist_dict_get_item(packet, "OOB Offset");
	if (!oob_offset_node || PLIST_UINT != plist_get_node_type(oob_offset_node)) {
		error("ERROR: Unable to find OOB data offset\n");
		return -1;
	}
	plist_get_uint_val(oob_offset_node, &oob_offset);

	oob_data = (char*) malloc(oob_length);
	if (oob_data == NULL) {
		error("ERROR: Out of memory\n");
		plist_free(packet);
		return -1;
	}

	fseek(file, oob_offset, SEEK_SET);
	if (fread(oob_data, 1, oob_length, file) != oob_length) {
		error("ERROR: Unable to read OOB data from filesystem offset\n");
		plist_free(packet);
		free(oob_data);
		return -1;
	}

	if (asr_send_buffer(asr, oob_data, oob_length) < 0) {
		error("ERROR: Unable to send OOB data to ASR\n");
		plist_free(packet);
		free(oob_data);
		return -1;
	}
	free(oob_data);
	return 0;
}

int asr_send_payload(asr_client_t asr, const char* filesystem) {
	int i = 0;
	char data[ASR_PAYLOAD_PACKET_SIZE];
	FILE* file = NULL;
	uint32_t bytes = 0;
	uint32_t length = 0;
	double progress = 0;

	file = fopen(filesystem, "rb");
	if (file == NULL) {
		return -1;
	}

	fseek(file, 0, SEEK_END);
	length = ftell(file);
	fseek(file, 0, SEEK_SET);

	int chunk = 0;
	int add_checksum = 0;

	SHA_CTX sha1;

	if (asr->checksum_chunks) {
		SHA1_Init(&sha1);
	}

	int size = 0;
	for (i = length; i > 0; i -= size) {
		size = ASR_PAYLOAD_PACKET_SIZE;
		if (i < ASR_PAYLOAD_PACKET_SIZE) {
			size = i;
		}

		if (add_checksum) {
			add_checksum = 0;
		}

		if (asr->checksum_chunks && ((chunk + size) >= ASR_CHECKSUM_CHUNK_SIZE)) {
			// reduce packet size to match checksum chunk size
			size -= ((chunk + size) - ASR_CHECKSUM_CHUNK_SIZE);
			add_checksum = 1;
		}

		if (fread(data, 1, size, file) != (unsigned int) size) {
			error("Error reading filesystem\n");
			fclose(file);
			return -1;
		}

		if (asr_send_buffer(asr, data, size) < 0) {
			error("ERROR: Unable to send filesystem payload\n");
			fclose(file);
			return -1;
		}

		if (asr->checksum_chunks) {
			SHA1_Update(&sha1, data, size);
			chunk += size;

			if (add_checksum) {
				// get sha1 of last chunk
				SHA1_Final((unsigned char*)data, &sha1);

				// send checksum
				if (asr_send_buffer(asr, data, 20) < 0) {
					error("ERROR: Unable to send chunk checksum\n");
					fclose(file);
					return -1;
				}

				// reset SHA1 context
				SHA1_Init(&sha1);

				// reset chunk byte counter
				chunk = 0;
			}
		}

		bytes += size;
		progress = ((double) bytes/ (double) length);
		if (asr->progress_cb && ((int)(progress*100) > asr->lastprogress)) {
			asr->progress_cb(progress, asr->progress_cb_data);
			asr->lastprogress = (int)(progress*100);
		}
	}

	// if last chunk wasn't terminated with a checksum we do it here
	if (asr->checksum_chunks && !add_checksum) {
		// get sha1 of last chunk
		SHA1_Final((unsigned char*)data, &sha1);

		// send checksum
		if (asr_send_buffer(asr, data, 20) < 0) {
			error("ERROR: Unable to send chunk checksum\n");
			fclose(file);
			return -1;
		}
	}

	fclose(file);
	return 0;
}
