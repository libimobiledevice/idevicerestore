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
#include <stdlib.h>
#include <string.h>
#include <libirecovery.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>

#include "common.h"
#include "normal.h"
#include "recovery.h"

static int normal_device_connected = 0;

void normal_device_callback(const idevice_event_t* event, void* userdata) {
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) userdata;
	if (event->event == IDEVICE_DEVICE_ADD) {
		normal_device_connected = 1;

	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		normal_device_connected = 0;
		client->flags &= FLAG_QUIT;
	}
}

int normal_client_new(struct idevicerestore_client_t* client) {
	struct normal_client_t* normal = (struct normal_client_t*) malloc(sizeof(struct normal_client_t));
	if (normal == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}

	if (normal_open_with_timeout(client) < 0) {
		normal_client_free(client);
		return -1;
	}

	client->normal = normal;
	return 0;
}

void normal_client_free(struct idevicerestore_client_t* client) {
	struct normal_client_t* normal = NULL;
	if (client) {
		normal = client->normal;
		if(normal) {
			if(normal->client) {
				lockdownd_client_free(normal->client);
				normal->client = NULL;
			}
			if(normal->device) {
				idevice_free(normal->device);
				normal->device = NULL;
			}
		}
		free(normal);
		client->normal = NULL;
	}
}

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

int normal_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 10;
	idevice_t device = NULL;
	lockdownd_client_t lockdownd = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdownd_error = LOCKDOWN_E_SUCCESS;

	// no context exists so bail
	if(client == NULL) {
		return -1;
	}

	// create our normal client if it doesn't yet exist
	if(client->normal == NULL) {
		client->normal = (struct normal_client_t*) malloc(sizeof(struct normal_client_t));
		if(client->normal == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
	}

	device_error = idevice_event_subscribe(&normal_device_callback, NULL);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to subscribe to device events\n");
		return -1;
	}

	for (i = 1; i <= attempts; i++) {
		if (normal_device_connected == 1) {
			break;
		}

		if (i == attempts) {
			error("ERROR: Unable to connect to device in normal mode\n");
			return -1;
		}

		sleep(2);
	}

	device_error = idevice_new(&device, client->uuid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdownd_error = lockdownd_client_new(device, &lockdownd, "idevicerestore");
	if (lockdownd_error != LOCKDOWN_E_SUCCESS) {
		//idevice_event_unsubscribe();
		idevice_free(device);
		return -1;
	}

	char* type = NULL;
	lockdownd_error = lockdownd_query_type(lockdownd, &type);
	if (lockdownd_error != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdownd);
		//idevice_event_unsubscribe();
		idevice_free(device);
		return -1;
	}

	client->normal->device = device;
	client->normal->client = lockdownd;
	return 0;
}

int normal_check_device(const char* uuid) {
	int i = 0;
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

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	if (!product_type_node || plist_get_node_type(product_type_node) != PLIST_STRING) {
		if (product_type_node) plist_free(product_type_node);
		return -1;
	}
	plist_get_string_val(product_type_node, &product_type);
	plist_free(product_type_node);

	for (i = 0; idevicerestore_devices[i].product != NULL; i++) {
		if (!strcmp(product_type, idevicerestore_devices[i].product)) {
			break;
		}
	}

	return idevicerestore_devices[i].index;
}

int normal_enter_recovery(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;
	irecv_client_t recovery = NULL;
	lockdownd_client_t lockdown = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;

	device_error = idevice_new(&device, client->uuid);
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

	if (recovery_open_with_timeout(client) < 0) {
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

	//client->mode = &idevicerestore_modes[MODE_RECOVERY];
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
	if (device_error != IDEVICE_E_SUCCESS) {
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
