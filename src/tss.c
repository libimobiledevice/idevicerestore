/*
 * tss.c
 * Functions for communicating with Apple's TSS server
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
#include <curl/curl.h>
#include <plist/plist.h>

#include "tss.h"
#include "idevicerestore.h"

#define ECID_STRSIZE 0x20

plist_t tss_create_request(plist_t buildmanifest, uint64_t ecid) {
	// Fetch build information from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(buildmanifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find BuildIdentities array\n");
		return NULL;
	}

	plist_t restore_identity_dict = plist_array_get_item(build_identities_array, 0);
	if (!restore_identity_dict || plist_get_node_type(restore_identity_dict) != PLIST_DICT) {
		error("ERROR: Unable to find restore identity\n");
		return NULL;
	}

	uint64_t unique_build_size = 0;
	char* unique_build_data = NULL;
	plist_t unique_build_node = plist_dict_get_item(restore_identity_dict, "UniqueBuildID");
	if (!unique_build_node || plist_get_node_type(unique_build_node) != PLIST_DATA) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return NULL;
	}
	plist_get_data_val(unique_build_node, &unique_build_data, &unique_build_size);

	int chip_id = 0;
	char* chip_id_string = NULL;
	plist_t chip_id_node = plist_dict_get_item(restore_identity_dict, "ApChipID");
	if (!chip_id_node || plist_get_node_type(chip_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApChipID node\n");
		return NULL;
	}
	plist_get_string_val(chip_id_node, &chip_id_string);
	sscanf(chip_id_string, "%x", &chip_id);

	int board_id = 0;
	char* board_id_string = NULL;
	plist_t board_id_node = plist_dict_get_item(restore_identity_dict, "ApBoardID");
	if (!board_id_node || plist_get_node_type(board_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApBoardID node\n");
		return NULL;
	}
	plist_get_string_val(board_id_node, &board_id_string);
	sscanf(board_id_string, "%x", &board_id);

	int security_domain = 0;
	char* security_domain_string = NULL;
	plist_t security_domain_node = plist_dict_get_item(restore_identity_dict, "ApSecurityDomain");
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
	snprintf(ecid_string, ECID_STRSIZE, "%qu", ecid);

	// Add build information to TSS request
	plist_t tss_request = plist_new_dict();
	plist_dict_insert_item(tss_request, "@HostIpAddress", plist_new_string("192.168.0.1"));
	plist_dict_insert_item(tss_request, "@HostPlatformInfo", plist_new_string("darwin"));
	plist_dict_insert_item(tss_request, "@VersionInfo", plist_new_string("3.8"));
	plist_dict_insert_item(tss_request, "@Locality", plist_new_string("en_US"));
	plist_dict_insert_item(tss_request, "ApProductionMode", plist_new_bool(1));
	plist_dict_insert_item(tss_request, "ApECID", plist_new_string(ecid_string));
	plist_dict_insert_item(tss_request, "ApChipID", plist_new_uint(chip_id));
	plist_dict_insert_item(tss_request, "ApBoardID", plist_new_uint(board_id));
	plist_dict_insert_item(tss_request, "ApSecurityDomain", plist_new_uint(security_domain));
	plist_dict_insert_item(tss_request, "UniqueBuildID", plist_new_data(unique_build_data, unique_build_size));

	// Add all firmware files to TSS request
	plist_t manifest_node = plist_dict_get_item(restore_identity_dict, "Manifest");
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
		if (key == NULL) break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			free(tss_request);
			return NULL;
		}

		plist_t tss_entry = plist_copy(manifest_entry);
		plist_dict_insert_item(tss_request, key, tss_entry);
	}
	/*
		int sz = 0;
		char* xml = NULL;
		plist_to_xml(tss_request, &xml, &sz);
		printf("%s", xml);
	*/
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

plist_t tss_send_request(plist_t tss_request) {
	curl_global_init(CURL_GLOBAL_ALL);

	char* request = NULL;
	unsigned int size = 0;
	plist_to_xml(tss_request, &request, &size);
	tss_response* response = NULL;
	CURL* handle = curl_easy_init();
	if (handle != NULL) {
		struct curl_slist* header = NULL;
		header = curl_slist_append(header, "Content-type: text/xml");

		response = malloc(sizeof(tss_response));
		if (response == NULL) {
			fprintf(stderr, "Unable to allocate sufficent memory\n");
			return NULL;
		}

		response->length = 0;
		response->content = malloc(1);

		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &tss_write_callback);
		curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
		curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request);
		curl_easy_setopt(handle, CURLOPT_USERAGENT, "InetURL/1.0");
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(request));
		curl_easy_setopt(handle, CURLOPT_URL, "http://cydia.saurik.com/TSS/controller?action=2");
		//curl_easy_setopt(handle, CURLOPT_URL, "http://gs.apple.com/TSS/controller?action=2");

		curl_easy_perform(handle);
		curl_slist_free_all(header);
		curl_easy_cleanup(handle);
	}
	curl_global_cleanup();

	if(strstr(response->content, "MESSAGE=SUCCESS") == NULL) {
		error("ERROR: Unable to get signature from this firmware\n");
		free(response->content);
		free(response);
		return NULL;
	}

	char* tss_data = strstr(response->content, "<?xml");
	if(tss_data == NULL) {
		error("ERROR: Incorrectly formatted TSS response\n");
		free(response->content);
		free(response);
		return NULL;
	}

	uint32_t tss_size = 0;
	plist_t tss_response = NULL;
	tss_size = response->length - (tss_data - response->content);
	plist_from_xml(tss_data, tss_size, &tss_response);
/*
	int sz = 0;
	char* xml = NULL;
	plist_to_xml(tss_response, &xml, &sz);
	printf("%s", xml);
*/
	return tss_response;
}
