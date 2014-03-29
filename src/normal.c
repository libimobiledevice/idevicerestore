/*
 * normal.h
 * Functions for handling idevices in normal mode
 *
 * Copyright (c) 2012-2013 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
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

static int normal_idevice_new(struct idevicerestore_client_t* client, idevice_t* device)
{
	int num_devices = 0;
	char **devices = NULL;
	idevice_get_device_list(&devices, &num_devices);
	if (num_devices == 0) {
		return -1;
	}
	*device = NULL;
	idevice_t dev = NULL;
	idevice_error_t device_error;
	lockdownd_client_t lockdown = NULL;
	int j;
	for (j = 0; j < num_devices; j++) {
		if (lockdown != NULL) {
			lockdownd_client_free(lockdown);
			lockdown = NULL;
		}
		if (dev != NULL) {
			idevice_free(dev);
			dev = NULL;
		}
		device_error = idevice_new(&dev, devices[j]);
		if (device_error != IDEVICE_E_SUCCESS) {
			error("ERROR: %s: can't open device with UDID %s\n", __func__, devices[j]);
			continue;
		}

		if (lockdownd_client_new(dev, &lockdown, "idevicerestore") != LOCKDOWN_E_SUCCESS) {
			error("ERROR: %s: can't connect to lockdownd on device with UDID %s\n", __func__, devices[j]);
			continue;

		}
		char* type = NULL;
		if (lockdownd_query_type(lockdown, &type) != LOCKDOWN_E_SUCCESS) {
			continue;
		}
		if (strcmp(type, "com.apple.mobile.lockdown") != 0) {
			free(type);
			continue;
		}
		free(type);

		if (client->ecid != 0) {
			plist_t node = NULL;
			if ((lockdownd_get_value(lockdown, NULL, "UniqueChipID", &node) != LOCKDOWN_E_SUCCESS) || !node || (plist_get_node_type(node) != PLIST_UINT)){
				if (node) {
					plist_free(node);
				}
				continue;
			}
			lockdownd_client_free(lockdown);
			lockdown = NULL;

			uint64_t this_ecid = 0;
			plist_get_uint_val(node, &this_ecid);
			plist_free(node);

			if (this_ecid != client->ecid) {
				continue;
			}
		}
		if (lockdown) {
			lockdownd_client_free(lockdown);
			lockdown = NULL;
		}
		client->udid = strdup(devices[j]);
		*device = dev;
		break;
	}
	idevice_device_list_free(devices);

	return 0;
}

int normal_check_mode(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;

	normal_idevice_new(client, &device);
	if (!device) {
		return -1;
	}
	idevice_free(device);	

	return 0;
}

int normal_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 10;
	idevice_t device = NULL;

	// no context exists so bail
	if(client == NULL) {
		return -1;
	}

	normal_device_connected = 0;

	// create our normal client if it doesn't yet exist
	if(client->normal == NULL) {
		client->normal = (struct normal_client_t*) malloc(sizeof(struct normal_client_t));
		if(client->normal == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
	}

	for (i = 1; i <= attempts; i++) {
		normal_idevice_new(client, &device);
		if (device) {
			normal_device_connected = 1;
			break;
		}

		if (i == attempts) {
			error("ERROR: Unable to connect to device in normal mode\n");
			return -1;
		}
		sleep(2);
	}

	client->normal->device = device;

	return 0;
}

const char* normal_check_product_type(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;
	char* product_type = NULL;
	irecv_device_t irecv_device = NULL;
	plist_t product_type_node = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	normal_idevice_new(client, &device);
	if (!device) {
		return product_type;
	}

	lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	}
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		return product_type;
	}

	plist_t pval = NULL;
	lockdownd_get_value(lockdown, NULL, "HardwareModel", &pval);
	if (pval && (plist_get_node_type(pval) == PLIST_STRING)) {
		char* strval = NULL;
		plist_get_string_val(pval, &strval);
		if (strval) {
			irecv_devices_get_device_by_hardware_model(strval, &irecv_device);
			if (irecv_device) {
				product_type = strdup(irecv_device->product_type);
			}
			free(strval);
		}
	}
	if (pval) {
		plist_free(pval);
	}

	if (product_type == NULL) {
		lockdown_error = lockdownd_get_value(lockdown, NULL, "ProductType", &product_type_node);
		if (lockdown_error != LOCKDOWN_E_SUCCESS) {
			lockdownd_client_free(lockdown);
			idevice_free(device);
			return product_type;
		}
	}

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	if (irecv_device) {
		if (product_type)
			free(product_type);

		return irecv_device->product_type;
	}

	if (product_type_node != NULL) {
		if (!product_type_node || plist_get_node_type(product_type_node) != PLIST_STRING) {
			if (product_type_node)
				plist_free(product_type_node);
			return product_type;
		}
		plist_get_string_val(product_type_node, &product_type);
		plist_free(product_type_node);

		irecv_devices_get_device_by_product_type(product_type, &irecv_device);
		if (irecv_device && irecv_device->product_type) {
			free(product_type);
			return irecv_device->product_type;
		}
	}

	return product_type;
}

int normal_enter_recovery(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
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

	if (recovery_client_new(client) < 0) {
		error("ERROR: Unable to enter recovery mode\n");
		return -1;
	}

	client->mode = &idevicerestore_modes[MODE_RECOVERY];
	return 0;
}

static int normal_get_nonce_by_key(struct idevicerestore_client_t* client, const char* key, unsigned char** nonce, int* nonce_size) {
	idevice_t device = NULL;
	plist_t nonce_node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd\n");
		idevice_free(device);
		return -1;
	}

	lockdown_error = lockdownd_get_value(lockdown, NULL, key, &nonce_node);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("Unable to get %s from lockdownd\n", key);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	if (!nonce_node || plist_get_node_type(nonce_node) != PLIST_DATA) {
		error("Unable to get %s\n", key);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	uint64_t n_size = 0;
	plist_get_data_val(nonce_node, (char**)nonce, &n_size);
	*nonce_size = (int)n_size;
	plist_free(nonce_node);

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	return 0;
}

int normal_get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	return normal_get_nonce_by_key(client, "SEPNonce", nonce, nonce_size);
}

int normal_get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	return normal_get_nonce_by_key(client, "ApNonce", nonce, nonce_size);
}

int normal_is_image4_supported(struct idevicerestore_client_t* client)
{
	idevice_t device = NULL;
	plist_t node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return 0;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd\n");
		idevice_free(device);
		return 0;
	}

	lockdown_error = lockdownd_get_value(lockdown, NULL, "Image4Supported", &node);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return 0;
	}

	if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return 0;
	}

	uint8_t bval = 0;
	plist_get_bool_val(node, &bval);
	plist_free(node);

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	return bval;
}

int normal_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	idevice_t device = NULL;
	plist_t unique_chip_node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
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

int normal_get_preflight_info(struct idevicerestore_client_t* client, plist_t *preflight_info) {
	idevice_t device = NULL;
	plist_t node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = IDEVICE_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		return -1;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd\n");
		idevice_free(device);
		return -1;
	}

	lockdown_error = lockdownd_get_value(lockdown, NULL, "FirmwarePreflightInfo", &node);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		debug("ERROR: Unable to get FirmwarePreflightInfo from lockdownd\n");
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to get FirmwarePreflightInfo\n");
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}
	*preflight_info = node;

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;
	return 0;
}
