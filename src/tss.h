/*
 * tss.h
 * Definitions for communicating with Apple's TSS server.
 *
 * Copyright (c) 2013 Martin Szulecki. All Rights Reserved.
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

#ifndef IDEVICERESTORE_TSS_H
#define IDEVICERESTORE_TSS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <plist/plist.h>

/* parameters */
int tss_parameters_add_from_manifest(plist_t parameters, plist_t build_identity);

/* request */
plist_t tss_request_new(plist_t overrides);

int tss_request_add_common_tags(plist_t request, plist_t parameters, plist_t overrides);
int tss_request_add_ap_tags(plist_t request, plist_t parameters, plist_t overrides);
int tss_request_add_baseband_tags(plist_t request, plist_t parameters, plist_t overrides);

int tss_request_add_ap_img4_tags(plist_t request, plist_t parameters);
int tss_request_add_ap_img3_tags(plist_t request, plist_t parameters);

/* i/o */
plist_t tss_request_send(plist_t request, const char* server_url_string);

/* response */
int tss_response_get_ap_img4_ticket(plist_t response, unsigned char** ticket, unsigned int* length);
int tss_response_get_ap_ticket(plist_t response, unsigned char** ticket, unsigned int* length);
int tss_response_get_baseband_ticket(plist_t response, unsigned char** ticket, unsigned int* length);
int tss_response_get_path_by_entry(plist_t response, const char* entry, char** path);
int tss_response_get_blob_by_path(plist_t response, const char* path, unsigned char** blob);
int tss_response_get_blob_by_entry(plist_t response, const char* entry, unsigned char** blob);

/* helpers */
char* ecid_to_string(uint64_t ecid);

#ifdef __cplusplus
}
#endif

#endif
