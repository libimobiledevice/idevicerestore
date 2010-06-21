/*
 * activate.c
 * Functions to fetch activation records from Apple's servers
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
#include <libimobiledevice/lockdown.h>

typedef struct {
	int length;
	char* content;
} activate_response;

size_t activate_write_callback(char* data, size_t size, size_t nmemb, activate_response* response) {
	size_t total = size * nmemb;
	if (total != 0) {
		response->content = realloc(response->content, response->length + total + 1);
		memcpy(response->content + response->length, data, total);
		response->content[response->length + total] = '\0';
		response->length += total;
	}
	//printf("%s", data);
	return total;
}

int activate_fetch_record(lockdownd_client_t client, plist_t* record) {
	int size = 0;
	char* request = NULL;
	struct curl_httppost* post = NULL;
	struct curl_httppost* last = NULL;
	activate_response* response = NULL;

	char* imei = NULL;
	char* imsi = NULL;
	char* iccid = NULL;
	char* serial_number = NULL;
	char* activation_info = NULL;

	plist_t imei_node = NULL;
	plist_t imsi_node = NULL;
	plist_t iccid_node = NULL;
	plist_t serial_number_node = NULL;
	plist_t activation_info_node = NULL;

	char* device_class = NULL;
	plist_t device_class_node = NULL;
	lockdownd_get_value(client, NULL, "DeviceClass", &device_class_node);
	if (!device_class_node || plist_get_node_type(device_class_node) != PLIST_STRING) {
		fprintf(stderr, "Unable to get DeviceClass from lockdownd\n");
		return -1;
	}
	plist_get_string_val(device_class_node, &device_class);
	plist_free(device_class_node);

	if (!strcmp(device_class, "iPhone")) {
		lockdownd_get_value(client, NULL, "IntegratedCircuitCardIdentity", &iccid_node);
		if (!iccid_node || plist_get_node_type(iccid_node) != PLIST_STRING) {
			fprintf(stderr, "Unable to get ICCID from lockdownd\n");
			return -1;
		}
		plist_get_string_val(iccid_node, &iccid);
		plist_free(iccid_node);

		lockdownd_get_value(client, NULL, "InternationalMobileEquipmentIdentity", &imei_node);
		if (!imei_node || plist_get_node_type(imei_node) != PLIST_STRING) {
			fprintf(stderr, "Unable to get IMEI from lockdownd\n");
			return -1;
		}
		plist_get_string_val(imei_node, &imei);
		plist_free(imei_node);

		lockdownd_get_value(client, NULL, "InternationalMobileSubscriberIdentity", &imsi_node);
		if (!imsi_node || plist_get_node_type(imsi_node) != PLIST_STRING) {
			fprintf(stderr, "Unable to get IMSI from lockdownd\n");
			return -1;
		}
		plist_get_string_val(imsi_node, &imsi);
		plist_free(imsi_node);
	}

	lockdownd_get_value(client, NULL, "SerialNumber", &serial_number_node);
	if (!serial_number_node || plist_get_node_type(serial_number_node) != PLIST_STRING) {
		fprintf(stderr, "Unable to get SerialNumber from lockdownd\n");
		return -1;
	}
	plist_get_string_val(serial_number_node, &serial_number);
	plist_free(serial_number_node);

	lockdownd_get_value(client, NULL, "ActivationInfo", &activation_info_node);
	int type = plist_get_node_type(activation_info_node);
	if (!activation_info_node || plist_get_node_type(activation_info_node) != PLIST_DICT) {
		fprintf(stderr, "Unable to get ActivationInfo from lockdownd\n");
		return -1;
	}
	//plist_get_string_val(activation_info_node, &activation_info);

	uint32_t activation_info_size = 0;
	char* activation_info_data = NULL;
	plist_to_xml(activation_info_node, &activation_info_data, &activation_info_size);
	plist_free(activation_info_node);
	//printf("%s\n\n", activation_info_data);

	char* activation_info_start = strstr(activation_info_data, "<dict>");
	if (activation_info_start == NULL) {
		fprintf(stderr, "Unable to locate beginning of ActivationInfo\n");
		return -1;
	}

	char* activation_info_stop = strstr(activation_info_data, "</dict>");
	if (activation_info_stop == NULL) {
		fprintf(stderr, "Unable to locate end of ActivationInfo\n");
		return -1;
	}

	activation_info_stop += strlen("</dict>");
	activation_info_size = activation_info_stop - activation_info_start;
	activation_info = malloc(activation_info_size + 1);
	memset(activation_info, '\0', activation_info_size + 1);
	memcpy(activation_info, activation_info_start, activation_info_size);
	free(activation_info_data);

	curl_global_init(CURL_GLOBAL_ALL);
	CURL* handle = curl_easy_init();
	if (handle == NULL) {
		fprintf(stderr, "Unable to initialize libcurl\n");
		curl_global_cleanup();
		return -1;
	}

	curl_formadd(&post, &last, CURLFORM_COPYNAME, "machineName", CURLFORM_COPYCONTENTS, "linux", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "InStoreActivation", CURLFORM_COPYCONTENTS, "false", CURLFORM_END);
	if (imei != NULL) {
		curl_formadd(&post, &last, CURLFORM_COPYNAME, "IMEI", CURLFORM_COPYCONTENTS, imei, CURLFORM_END);
		free(imei);
	}

	if (imsi != NULL) {
		curl_formadd(&post, &last, CURLFORM_COPYNAME, "IMSI", CURLFORM_COPYCONTENTS, imsi, CURLFORM_END);
		free(imsi);
	}

	if (iccid != NULL) {
		curl_formadd(&post, &last, CURLFORM_COPYNAME, "ICCID", CURLFORM_COPYCONTENTS, iccid, CURLFORM_END);
		free(iccid);
	}

	if (serial_number != NULL) {
		curl_formadd(&post, &last, CURLFORM_COPYNAME, "AppleSerialNumber", CURLFORM_COPYCONTENTS, serial_number, CURLFORM_END);
		free(serial_number);
	}

	if (activation_info != NULL) {
		curl_formadd(&post, &last, CURLFORM_COPYNAME, "activation-info", CURLFORM_COPYCONTENTS, activation_info, CURLFORM_END);
		free(activation_info);
	}

	struct curl_slist* header = NULL;
	header = curl_slist_append(header, "X-Apple-Tz: -14400");
	header = curl_slist_append(header, "X-Apple-Store-Front: 143441-1");

	response = malloc(sizeof(activate_response));
	if (response == NULL) {
		fprintf(stderr, "Unable to allocate sufficent memory\n");
		return -1;
	}

	response->length = 0;
	response->content = malloc(1);

	curl_easy_setopt(handle, CURLOPT_HTTPPOST, post);
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, &activate_write_callback);
	curl_easy_setopt(handle, CURLOPT_USERAGENT, "iTunes/9.1 (Macintosh; U; Intel Mac OS X 10.5.6)");
	curl_easy_setopt(handle, CURLOPT_URL, "https://albert.apple.com/WebObjects/ALUnbrick.woa/wa/deviceActivation");

	curl_easy_perform(handle);
	curl_slist_free_all(header);
	curl_easy_cleanup(handle);
	curl_global_cleanup();

	uint32_t ticket_size = response->length;
	char* ticket_data = response->content;

	char* ticket_start = strstr(ticket_data, "<plist");
	if (ticket_start == NULL) {
		fprintf(stderr, "Unable to locate beginning of ActivationInfo\n");
		return -1;
	}

	char* ticket_stop = strstr(ticket_data, "</plist>");
	if (ticket_stop == NULL) {
		fprintf(stderr, "Unable to locate end of ActivationInfo\n");
		return -1;
	}

	ticket_stop += strlen("</plist>");
	ticket_size = ticket_stop - ticket_start;
	char* ticket = malloc(ticket_size + 1);
	memset(ticket, '\0', ticket_size + 1);
	memcpy(ticket, ticket_start, ticket_size);
	//free(ticket_data);

	//printf("%s\n\n", ticket);

	plist_t ticket_dict = NULL;
	plist_from_xml(ticket, ticket_size, &ticket_dict);
	if (ticket_dict == NULL) {
		printf("Unable to convert activation ticket into plist\n");
		return -1;
	}

	plist_t iphone_activation_node = plist_dict_get_item(ticket_dict, "iphone-activation");
	if (!iphone_activation_node) {
		iphone_activation_node = plist_dict_get_item(ticket_dict, "device-activation");
		if (!iphone_activation_node) {
			printf("Unable to find device activation node\n");
			return -1;
		}
	}

	plist_t activation_record = plist_dict_get_item(iphone_activation_node, "activation-record");
	if (!activation_record) {
		printf("Unable to find activation record node");
		return -1;
	}

	*record = plist_copy(activation_record);

	//free(response->content);
	//free(response);
	//free(request);
	return 0;
}

int activate_check_status(const char* uuid) {
	return 1;
}

int activate_device(const char* uuid) {
	return 0;
}
