/*
 * normal.h
 * Functions for handling idevices in normal mode
 *
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
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

#ifndef IDEVICERESTORE_NORMAL_H
#define IDEVICERESTORE_NORMAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>

struct normal_client_t {
	idevice_t device;
	lockdownd_client_t client;
	const char* ipsw;
	plist_t tss;
};


int normal_check_mode(struct idevicerestore_client_t* client);
const char* normal_check_product_type(struct idevicerestore_client_t* client);
int normal_client_new(struct idevicerestore_client_t* client);
void normal_client_free(struct idevicerestore_client_t* client);
int normal_open_with_timeout(struct idevicerestore_client_t* client);
int normal_enter_recovery(struct idevicerestore_client_t* client);
int normal_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid);
int normal_is_image4_supported(struct idevicerestore_client_t* client);
int normal_get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size);
int normal_get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size);
int normal_get_preflight_info(struct idevicerestore_client_t* client, plist_t *preflight_info);

#ifdef __cplusplus
}
#endif

#endif
