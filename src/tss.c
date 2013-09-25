/*
 * tss.c
 * Functions for communicating with Apple's TSS server
 *
 * Copyright (c) 2010-2013 Martin Szulecki. All Rights Reserved.
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
#include <curl/curl.h>
#include <plist/plist.h>

#include "tss.h"
#include "img3.h"
#include "common.h"
#include "idevicerestore.h"

#define ECID_STRSIZE 0x20

typedef struct {
	int length;
	char* content;
} tss_response;

plist_t tss_create_request(plist_t build_identity, uint64_t ecid, unsigned char* nonce, int nonce_size) {
	uint64_t unique_build_size = 0;
	char* unique_build_data = NULL;
	plist_t unique_build_node = plist_dict_get_item(build_identity, "UniqueBuildID");
	if (!unique_build_node || plist_get_node_type(unique_build_node) != PLIST_DATA) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return NULL;
	}
	plist_get_data_val(unique_build_node, &unique_build_data, &unique_build_size);

	int chip_id = 0;
	char* chip_id_string = NULL;
	plist_t chip_id_node = plist_dict_get_item(build_identity, "ApChipID");
	if (!chip_id_node || plist_get_node_type(chip_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApChipID node\n");
		return NULL;
	}
	plist_get_string_val(chip_id_node, &chip_id_string);
	sscanf(chip_id_string, "%x", &chip_id);

	int board_id = 0;
	char* board_id_string = NULL;
	plist_t board_id_node = plist_dict_get_item(build_identity, "ApBoardID");
	if (!board_id_node || plist_get_node_type(board_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApBoardID node\n");
		return NULL;
	}
	plist_get_string_val(board_id_node, &board_id_string);
	sscanf(board_id_string, "%x", &board_id);

	int security_domain = 0;
	char* security_domain_string = NULL;
	plist_t security_domain_node = plist_dict_get_item(build_identity, "ApSecurityDomain");
	if (!security_domain_node || plist_get_node_type(security_domain_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApSecurityDomain node\n");
		return NULL;
	}
	plist_get_string_val(security_domain_node, &security_domain_string);
	sscanf(security_domain_string, "%x", &security_domain);

	char ecid_string[ECID_STRSIZE];
	memset(ecid_string, '\0', ECID_STRSIZE);
	if (ecid == 0) {
		error("ERROR: Unable to get ECID\n");
		return NULL;
	}
	snprintf(ecid_string, ECID_STRSIZE, FMT_qu, (long long unsigned int)ecid);

	// Add build information to TSS request
	plist_t tss_request = plist_new_dict();
	plist_dict_insert_item(tss_request, "@APTicket", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "@BBTicket", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "@HostIpAddress", plist_new_string("192.168.0.1"));
	plist_dict_insert_item(tss_request, "@HostPlatformInfo",
#ifdef WIN32
		plist_new_string("windows")
#else
		plist_new_string("mac")
#endif
	);
	plist_dict_insert_item(tss_request, "@Locality", plist_new_string("en_US"));
	char* guid = generate_guid();
	if (guid) {
		plist_dict_insert_item(tss_request, "@UUID", plist_new_string(guid));
		free(guid);
	}
	plist_dict_insert_item(tss_request, "@VersionInfo", plist_new_string("libauthinstall-107.3"));
	plist_dict_insert_item(tss_request, "ApBoardID", plist_new_uint(board_id));
	plist_dict_insert_item(tss_request, "ApChipID", plist_new_uint(chip_id));
	plist_dict_insert_item(tss_request, "ApECID", plist_new_string(ecid_string));
	if (nonce && (nonce_size > 0)) {
		plist_dict_insert_item(tss_request, "ApNonce", plist_new_data((char*)nonce, nonce_size));
	}
	plist_dict_insert_item(tss_request, "ApProductionMode", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "ApSecurityDomain", plist_new_uint(security_domain));
	plist_dict_insert_item(tss_request, "UniqueBuildID", plist_new_data(unique_build_data, unique_build_size));
	free(unique_build_data);

	// Add all firmware files to TSS request
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find restore manifest\n");
		plist_free(tss_request);
		return NULL;
	}

	char* key = NULL;
	plist_t manifest_entry = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (1) {
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			plist_free(tss_request);
			return NULL;
		}

		if (strcmp(key, "BasebandFirmware") == 0) {
			free(key);
			continue;
		}

		plist_t tss_entry = plist_copy(manifest_entry);
		plist_dict_insert_item(tss_request, key, tss_entry);
		free(key);
	}

	if (idevicerestore_debug) {
		debug_plist(tss_request);
	}

	return tss_request;
}

plist_t tss_create_baseband_request(plist_t build_identity, uint64_t ecid, uint64_t bb_cert_id, unsigned char* bb_snum, uint64_t bb_snum_size, unsigned char* bb_nonce, int bb_nonce_size) {
	uint64_t unique_build_size = 0;
	char* unique_build_data = NULL;

	plist_t unique_build_node = plist_dict_get_item(build_identity, "UniqueBuildID");
	if (!unique_build_node || plist_get_node_type(unique_build_node) != PLIST_DATA) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return NULL;
	}
	plist_get_data_val(unique_build_node, &unique_build_data, &unique_build_size);

	int chip_id = 0;
	char* chip_id_string = NULL;
	plist_t chip_id_node = plist_dict_get_item(build_identity, "ApChipID");
	if (!chip_id_node || plist_get_node_type(chip_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApChipID node\n");
		return NULL;
	}
	plist_get_string_val(chip_id_node, &chip_id_string);
	sscanf(chip_id_string, "%x", &chip_id);

	int board_id = 0;
	char* board_id_string = NULL;
	plist_t board_id_node = plist_dict_get_item(build_identity, "ApBoardID");
	if (!board_id_node || plist_get_node_type(board_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApBoardID node\n");
		return NULL;
	}
	plist_get_string_val(board_id_node, &board_id_string);
	sscanf(board_id_string, "%x", &board_id);

	int security_domain = 0;
	char* security_domain_string = NULL;
	plist_t security_domain_node = plist_dict_get_item(build_identity, "ApSecurityDomain");
	if (!security_domain_node || plist_get_node_type(security_domain_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApSecurityDomain node\n");
		return NULL;
	}
	plist_get_string_val(security_domain_node, &security_domain_string);
	sscanf(security_domain_string, "%x", &security_domain);

	char ecid_string[ECID_STRSIZE];
	memset(ecid_string, '\0', ECID_STRSIZE);
	if (ecid == 0) {
		error("ERROR: Unable to get ECID\n");
		return NULL;
	}
	snprintf(ecid_string, ECID_STRSIZE, FMT_qu, (long long unsigned int)ecid);

	int bb_chip_id = 0;
	char* bb_chip_id_string = NULL;
	plist_t bb_chip_id_node = plist_dict_get_item(build_identity, "BbChipID");
	if (!bb_chip_id_node || plist_get_node_type(bb_chip_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find BbChipID node\n");
		return NULL;
	}
	plist_get_string_val(bb_chip_id_node, &bb_chip_id_string);
	sscanf(bb_chip_id_string, "%x", &bb_chip_id);

	plist_t bbfw_node = plist_access_path(build_identity, 2, "Manifest", "BasebandFirmware");
	if (!bbfw_node || plist_get_node_type(bbfw_node) != PLIST_DICT) {
		error("ERROR: Unable to get BasebandFirmware node\n");
		return NULL;
	}
	
	// Add build information to TSS request
	plist_t tss_request = plist_new_dict();
	plist_dict_insert_item(tss_request, "@BBTicket", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "@HostIpAddress", plist_new_string("192.168.0.1"));
	plist_dict_insert_item(tss_request, "@HostPlatformInfo",
#ifdef WIN32
		plist_new_string("windows")
#else
		plist_new_string("mac")
#endif
	);
	plist_dict_insert_item(tss_request, "@Locality", plist_new_string("en_US"));

	char* guid = generate_guid();
	if (guid) {
		plist_dict_insert_item(tss_request, "@UUID", plist_new_string(guid));
		free(guid);
	}
	plist_dict_insert_item(tss_request, "@VersionInfo", plist_new_string("libauthinstall-107.3"));
	plist_dict_insert_item(tss_request, "ApBoardID", plist_new_uint(board_id));
	plist_dict_insert_item(tss_request, "ApChipID", plist_new_uint(chip_id));
	plist_dict_insert_item(tss_request, "ApECID", plist_new_string(ecid_string));
	plist_dict_insert_item(tss_request, "ApProductionMode", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "ApSecurityDomain", plist_new_uint(security_domain));
	plist_dict_insert_item(tss_request, "BasebandFirmware", plist_copy(bbfw_node));

	/* Used by XMM 6180/GSM */
	plist_t bb_node = NULL;
	bb_node = plist_dict_get_item(build_identity, "BbSkeyId");
	if (bb_node && plist_get_node_type(bb_node) == PLIST_DATA) {
		plist_dict_insert_item(tss_request, "BbSkeyId", plist_copy(bb_node));
	} else {
		error("WARNING: Unable to find BbSkeyId node\n");
	}
	bb_node = NULL;

	/* Used by Qualcomm MDM6610 */
	bb_node = plist_dict_get_item(build_identity, "BbActivationManifestKeyHash");
	if (bb_node && plist_get_node_type(bb_node) == PLIST_DATA) {
		plist_dict_insert_item(tss_request, "BbActivationManifestKeyHash", plist_copy(bb_node));
	} else {
		error("WARNING: Unable to find BbActivationManifestKeyHash node\n");
	}
	bb_node = NULL;

	bb_node = plist_dict_get_item(build_identity, "BbCalibrationManifestKeyHash");
	if (bb_node && plist_get_node_type(bb_node) == PLIST_DATA) {
		plist_dict_insert_item(tss_request, "BbCalibrationManifestKeyHash", plist_copy(bb_node));
	} else {
		error("WARNING: Unable to find BbCalibrationManifestKeyHash node\n");
	}
	bb_node = NULL;

	plist_dict_insert_item(tss_request, "BbChipID", plist_new_uint(bb_chip_id));
	plist_dict_insert_item(tss_request, "BbGoldCertId", plist_new_uint(bb_cert_id));

	if (bb_nonce && (bb_nonce_size > 0)) {
		plist_dict_insert_item(tss_request, "BbNonce", plist_new_data((char*)bb_nonce, bb_nonce_size));
	}

	bb_node = plist_dict_get_item(build_identity, "BbProvisioningManifestKeyHash");
	if (bb_node && plist_get_node_type(bb_node) == PLIST_DATA) {
		plist_dict_insert_item(tss_request, "BbProvisioningManifestKeyHash", plist_copy(bb_node));
	} else {
		error("WARNING: Unable to find BbProvisioningManifestKeyHash node\n");
	}
	bb_node = NULL;

	if (bb_snum && bb_snum_size > 0) {
		plist_dict_insert_item(tss_request, "BbSNUM", plist_new_data((char*)bb_snum, bb_snum_size));
	}

	plist_dict_insert_item(tss_request, "UniqueBuildID", plist_new_data(unique_build_data, unique_build_size));
	free(unique_build_data);

	if (idevicerestore_debug) {
		debug_plist(tss_request);
	}

	return tss_request;
}

size_t tss_write_callback(char* data, size_t size, size_t nmemb, tss_response* response) {
	size_t total = size * nmemb;
	if (total != 0) {
		response->content = realloc(response->content, response->length + total + 1);
		memcpy(response->content + response->length, data, total);
		response->content[response->length + total] = '\0';
		response->length += total;
	}

	return total;
}

plist_t tss_send_request(plist_t tss_request, const char* server_url_string) {
	curl_global_init(CURL_GLOBAL_ALL);

	char* request = NULL;
	int status_code = -1;
	int retry = 0;
	int max_retries = 15;
	unsigned int size = 0;
	char curl_error_message[CURL_ERROR_SIZE];

	const char* urls[6] = {
		"https://gs.apple.com/TSS/controller?action=2",
		"https://17.171.36.30/TSS/controller?action=2",
		"https://17.151.36.30/TSS/controller?action=2",
		"http://gs.apple.com/TSS/controller?action=2",
		"http://17.171.36.30/TSS/controller?action=2",
		"http://17.151.36.30/TSS/controller?action=2"
	};

	plist_to_xml(tss_request, &request, &size);

	tss_response* response = NULL;
	memset(curl_error_message, '\0', CURL_ERROR_SIZE);

	while (retry++ < max_retries) {
		response = NULL;
		CURL* handle = curl_easy_init();
		if (handle == NULL) {
			break;
		}
		struct curl_slist* header = NULL;
		header = curl_slist_append(header, "Cache-Control: no-cache");
		header = curl_slist_append(header, "Content-type: text/xml; charset=\"utf-8\"");
		header = curl_slist_append(header, "Expect:");

		response = malloc(sizeof(tss_response));
		if (response == NULL) {
			fprintf(stderr, "Unable to allocate sufficent memory\n");
			return NULL;
		}

		response->length = 0;
		response->content = malloc(1);
		response->content[0] = '\0';

		/* disable SSL verification to allow download from untrusted https locations */
		curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);

		curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, curl_error_message);
		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, (curl_write_callback)&tss_write_callback);
		curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
		curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request);
		curl_easy_setopt(handle, CURLOPT_USERAGENT, "InetURL/1.0");
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(request));
		if (server_url_string) {
			curl_easy_setopt(handle, CURLOPT_URL, server_url_string);
		} else {
			int url_index = (retry - 1) % 6;
			curl_easy_setopt(handle, CURLOPT_URL, urls[url_index]);
			info("Request URL set to %s\n", urls[url_index]);
		}

		info("Sending TSS request attempt %d... ", retry);

		curl_easy_perform(handle);
		curl_slist_free_all(header);
		curl_easy_cleanup(handle);
	
		if (strstr(response->content, "MESSAGE=SUCCESS")) {
			status_code = 0;
			info("response successfully received\n");
			break;
		}

		if (response->length > 0) {
			error("TSS server returned: %s\n", response->content);
		}

		char* status = strstr(response->content, "STATUS=");
		if (status) {
			sscanf(status+7, "%d&%*s", &status_code);
		}
		if (status_code == -1) {
			error("%s\n", curl_error_message);
			// no status code in response. retry
			free(response->content);
			free(response);
			sleep(2);
			continue;
		} else if (status_code == 8) {
			// server error (invalid bb request?)
			break;
		} else if (status_code == 49) {
			// server error (invalid bb data, e.g. BbSNUM?)
			break;
		} else if (status_code == 94) {
			// This device isn't eligible for the requested build.
			break;
		} else if (status_code == 100) {
			// server error, most likely the request was malformed
			break;
		} else {
			error("ERROR: tss_send_request: Unhandled status code %d\n", status_code);
		}
	}

	if (status_code != 0) {
		if (strstr(response->content, "MESSAGE=") != NULL) {
			char* message = strstr(response->content, "MESSAGE=") + strlen("MESSAGE=");
			error("ERROR: TSS request failed (status=%d, message=%s)\n", status_code, message);
		} else {
			error("ERROR: TSS request failed: %s (status=%d)\n", curl_error_message, status_code);
		}
		free(request);
		free(response->content);
		free(response);
		return NULL;
	}

	char* tss_data = strstr(response->content, "<?xml");
	if (tss_data == NULL) {
		error("ERROR: Incorrectly formatted TSS response\n");
		free(request);
		free(response->content);
		free(response);
		return NULL;
	}

	uint32_t tss_size = 0;
	plist_t tss_response = NULL;
	tss_size = response->length - (tss_data - response->content);
	plist_from_xml(tss_data, tss_size, &tss_response);
	free(response->content);
	free(response);

	if (idevicerestore_debug) {
		debug_plist(tss_response);
	}

	free(request);
	curl_global_cleanup();

	return tss_response;
}

int tss_get_ticket(plist_t tss, unsigned char** ticket, unsigned int* tlen) {
	plist_t entry_node = plist_dict_get_item(tss, "APTicket");
	if (!entry_node || plist_get_node_type(entry_node) != PLIST_DATA) {
		error("ERROR: Unable to find APTicket entry in TSS response\n");
		return -1;
	}
	char *data = NULL;
	uint64_t len = 0;
	plist_get_data_val(entry_node, &data, &len);
	if (data) {
		*tlen = (unsigned int)len;
		*ticket = (unsigned char*)data;
		return 0;
	} else {
		error("ERROR: Unable to get APTicket data from TSS response\n");
		return -1;
	}
}

int tss_get_entry_path(plist_t tss, const char* entry, char** path) {
	char* path_string = NULL;
	plist_t path_node = NULL;
	plist_t entry_node = NULL;

	*path = NULL;

	entry_node = plist_dict_get_item(tss, entry);
	if (!entry_node || plist_get_node_type(entry_node) != PLIST_DICT) {
		error("ERROR: Unable to find %s entry in TSS response\n", entry);
		return -1;
	}

	path_node = plist_dict_get_item(entry_node, "Path");
	if (!path_node || plist_get_node_type(path_node) != PLIST_STRING) {
		debug("NOTE: Unable to find %s path in TSS entry\n", entry);
		return -1;
	}
	plist_get_string_val(path_node, &path_string);

	*path = path_string;
	return 0;
}

int tss_get_blob_by_path(plist_t tss, const char* path, unsigned char** blob) {
	int i = 0;
	uint32_t tss_size = 0;
	uint64_t blob_size = 0;
	char* entry_key = NULL;
	char* blob_data = NULL;
	char* entry_path = NULL;
	plist_t tss_entry = NULL;
	plist_t blob_node = NULL;
	plist_t path_node = NULL;
	plist_dict_iter iter = NULL;

	*blob = NULL;

	plist_dict_new_iter(tss, &iter);
	tss_size = plist_dict_get_size(tss);
	for (i = 0; i < tss_size; i++) {
		plist_dict_next_item(tss, iter, &entry_key, &tss_entry);
		if (entry_key == NULL)
			break;

		if (!tss_entry || plist_get_node_type(tss_entry) != PLIST_DICT) {
			continue;
		}

		path_node = plist_dict_get_item(tss_entry, "Path");
		if (!path_node || plist_get_node_type(path_node) != PLIST_STRING) {
			error("ERROR: Unable to find TSS path node in entry %s\n", entry_key);
			return -1;
		}

		plist_get_string_val(path_node, &entry_path);
		if (strcmp(path, entry_path) == 0) {
			blob_node = plist_dict_get_item(tss_entry, "Blob");
			if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
				error("ERROR: Unable to find TSS blob node in entry %s\n", entry_key);
				return -1;
			}
			plist_get_data_val(blob_node, &blob_data, &blob_size);
			break;
		}

		free(entry_key);
	}

	if (blob_data == NULL || blob_size <= 0) {
		return -1;
	}

	*blob = (unsigned char*)blob_data;
	return 0;
}

int tss_get_blob_by_name(plist_t tss, const char* entry, unsigned char** blob) {
	uint64_t blob_size = 0;
	char* blob_data = NULL;
	plist_t blob_node = NULL;
	plist_t tss_entry = NULL;

	*blob = NULL;

	tss_entry = plist_dict_get_item(tss, entry);
	if (!tss_entry || plist_get_node_type(tss_entry) != PLIST_DICT) {
		error("ERROR: Unable to find %s entry in TSS response\n", entry);
		return -1;
	}

	blob_node = plist_dict_get_item(tss_entry, "Blob");
	if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find blob in %s entry\n", entry);
		return -1;
	}
	plist_get_data_val(blob_node, &blob_data, &blob_size);

	*blob = (unsigned char*)blob_data;
	return 0;
}
