/*
 * restore.h
 * Functions for handling idevices in restore mode
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

#ifndef IDEVICERESTORE_RESTORE_H
#define IDEVICERESTORE_RESTORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <plist/plist.h>
#include <libimobiledevice/restore.h>
#include <libimobiledevice/libimobiledevice.h>

struct restore_client_t {
	plist_t tss;
	plist_t bbtss;
	idevice_t device;
	char* udid;
	unsigned int operation;
	const char* filesystem;
	uint64_t protocol_version;
	restored_client_t client;
};

int restore_check_mode(struct idevicerestore_client_t* client);
const char* restore_check_product_type(struct idevicerestore_client_t* client);
int restore_client_new(struct idevicerestore_client_t* client);
void restore_client_free(struct idevicerestore_client_t* client);
int restore_reboot(struct idevicerestore_client_t* client);
const char* restore_progress_string(unsigned int operation);
int restore_handle_status_msg(restored_client_t client, plist_t msg);
int restore_handle_progress_msg(struct idevicerestore_client_t* client, plist_t msg);
int restore_handle_data_request_msg(struct idevicerestore_client_t* client, idevice_t device, restored_client_t restore, plist_t message, plist_t build_identity, const char* filesystem);
int restore_send_nor(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity);
int restore_send_root_ticket(restored_client_t restore, struct idevicerestore_client_t* client);
int restore_send_kernelcache(restored_client_t restore, struct idevicerestore_client_t* client, plist_t build_identity);
int restore_device(struct idevicerestore_client_t* client, plist_t build_identity, const char* filesystem);
int restore_open_with_timeout(struct idevicerestore_client_t* client);
int restore_send_filesystem(struct idevicerestore_client_t* client, idevice_t device, const char* filesystem);
int restore_send_fdr_trust_data(restored_client_t restore, idevice_t device);

#ifdef __cplusplus
}
#endif

#endif
