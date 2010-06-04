/*
 * normal.h
 * Functions for handling idevices in normal mode
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
#include <stdint.h>
#include <libirecovery.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>

#include "normal.h"
#include "recovery.h"
#include "idevicerestore.h"

int normal_check_mode(const char* uuid) {
	char* type = NULL;
	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		return -1;
	}

	lockdown_error = lockdownd_query_type(lockdown, &type);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;
	return 0;
}

int normal_get_device(const char* uuid) {
	idevice_t device = NULL;
	char* product_type = NULL;
	plist_t product_type_node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		return -1;
	}

	lockdown_error = lockdownd_get_value(lockdown, NULL, "ProductType", &product_type_node);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	if (!product_type_node || plist_get_node_type(product_type_node) != PLIST_STRING) {
		if(product_type_node) plist_free(product_type_node);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}
	plist_get_string_val(product_type_node, &product_type);
	plist_free(product_type_node);

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	int i = 0;
	for(i = 0; idevicerestore_products[i] != NULL; i++) {
		if(!strcmp(product_type, idevicerestore_products[i])) {
			idevicerestore_device = i;
			break;
		}
	}

	return idevicerestore_device;
}

int normal_enter_recovery(const char* uuid) {
	idevice_t device = NULL;
	irecv_client_t recovery = NULL;
	lockdownd_client_t lockdown = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to find device\n");
		return -1;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd service\n");
		idevice_free(device);
		return -1;
	}

	lockdown_error = lockdownd_enter_recovery(lockdown);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to place device in recovery mode\n");
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	if(recovery_open_with_timeout(&recovery) < 0) {
		error("ERROR: Unable to enter recovery mode\n");
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "setenv auto-boot true");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to reset auto-boot variable\n");
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "saveenv");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to save auto-boot variable\n");
		irecv_close(recovery);
		return -1;
	}

	idevicerestore_mode = RECOVERY_MODE;
	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int normal_get_cpid(const char* uuid, uint32_t* cpid) {
	return 0;
}

int normal_get_bdid(const char* uuid, uint32_t* bdid) {
	return 0;
}

int normal_get_ecid(const char* uuid, uint64_t* ecid) {
	idevice_t device = NULL;
	plist_t unique_chip_node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, uuid);
	if(device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd\n");
		idevice_free(device);
		return -1;
	}

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
	plist_get_uint_val(unique_chip_node, ecid);
	plist_free(unique_chip_node);

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;
	return 0;
}
