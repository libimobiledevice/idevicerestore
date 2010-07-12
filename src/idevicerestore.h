/*
 * idevicerestore.h
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

#ifndef IDEVICERESTORE_H
#define IDEVICERESTORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <plist/plist.h>

#include "common.h"

void usage(int argc, char* argv[]);
int check_mode(struct idevicerestore_client_t* client);
int check_device(struct idevicerestore_client_t* client);
int get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid);
int get_bdid(struct idevicerestore_client_t* client, uint32_t* bdid);
int get_cpid(struct idevicerestore_client_t* client, uint32_t* cpid);
int get_shsh_blobs(struct idevicerestore_client_t* client, uint64_t ecid, plist_t build_identity, plist_t* tss);
void build_manifest_print_information(plist_t build_manifest);
plist_t build_manifest_get_build_identity(plist_t build_manifest, uint32_t identity);
int build_manifest_get_build_count(plist_t build_manifest);
void build_identity_print_information(plist_t build_identity);
int build_identity_get_component_path(plist_t build_identity, const char* component, char** path);
int ipsw_extract_filesystem(const char* ipsw, plist_t build_identity, char** filesystem);
int ipsw_get_component_by_path(const char* ipsw, plist_t tss, const char* path, char** data, uint32_t* size);

#ifdef __cplusplus
}
#endif

#endif
