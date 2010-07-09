/*
 * ipsw.c
 * Definitions for communicating with Apple's TSS server.
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

#ifndef IDEVICERESTORE_TSS_H
#define IDEVICERESTORE_TSS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <plist/plist.h>

plist_t tss_send_request(plist_t request);
plist_t tss_create_request(plist_t build_identity, uint64_t ecid);
int tss_get_entry_path(plist_t tss, const char* entry, char** path);
int tss_get_blob_by_path(plist_t tss, const char* path, char** blob);
int tss_get_blob_by_name(plist_t tss, const char* entry, char** blob);


#ifdef __cplusplus
}
#endif

#endif
