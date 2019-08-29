/*
 * normal.h
 * Functions for handling idevices in normal mode
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
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
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/preboard.h>

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
	idevice_t dev = NULL;
	idevice_error_t device_error;

	*device = NULL;

	if (client->udid) {
		device_error = idevice_new(&dev, client->udid);
		if (device_error != IDEVICE_E_SUCCESS) {
			error("ERROR: %s: can't open device with UDID %s\n", __func__, client->udid);
			return -1;
		}
		*device = dev;
		return 0;
	}

	idevice_get_device_list(&devices, &num_devices);
	if (num_devices == 0) {
		return -1;
	}
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

		if (client->ecid != 0) {
			if (this_ecid != client->ecid) {
				continue;
			}
		} else {
			client->ecid = this_ecid;
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

irecv_device_t normal_get_irecv_device(struct idevicerestore_client_t* client) {
	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;
	irecv_device_t irecv_device = NULL;

	normal_idevice_new(client, &device);
	if (!device) {
		return NULL;
	}

	lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (!(client->flags & FLAG_ERASE) && lockdown_error == LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING) {
		info("*** Device is not paired with this computer. Please trust this computer on the device to continue. ***\n");
		while (1) {
			lockdown_error = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
			if (lockdown_error != LOCKDOWN_E_PAIRING_DIALOG_RESPONSE_PENDING) {
				break;
			}
			sleep(1);
		}
	}
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	}
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		idevice_free(device);
		return NULL;
	}

	plist_t pval = NULL;
	lockdownd_get_value(lockdown, NULL, "HardwareModel", &pval);
	if (pval && (plist_get_node_type(pval) == PLIST_STRING)) {
		char *strval = NULL;
		plist_get_string_val(pval, &strval);
		if (strval) {
			irecv_devices_get_device_by_hardware_model(strval, &irecv_device);
			free(strval);
		}
	}
	plist_free(pval);

	lockdownd_client_free(lockdown);
	idevice_free(device);

	return irecv_device;
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

plist_t normal_get_lockdown_value(struct idevicerestore_client_t* client, const char* domain, const char* key)
{
	idevice_t device = NULL;
	plist_t node = NULL;
	lockdownd_client_t lockdown = NULL;
	idevice_error_t device_error = IDEVICE_E_SUCCESS;
	lockdownd_error_t lockdown_error = LOCKDOWN_E_SUCCESS;

	device_error = idevice_new(&device, client->udid);
	if (device_error != IDEVICE_E_SUCCESS) {
		error("ERROR: Unable to connect to device?!\n");
		return NULL;
	}

	lockdown_error = lockdownd_client_new(device, &lockdown, "idevicerestore");
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Unable to connect to lockdownd\n");
		idevice_free(device);
		return NULL;
	}

	lockdown_error = lockdownd_get_value(lockdown, domain, key, &node);
	if (lockdown_error != LOCKDOWN_E_SUCCESS) {
		debug("ERROR: Unable to get %s-%s from lockdownd\n", domain, key);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return NULL;
	}

	lockdownd_client_free(lockdown);
	idevice_free(device);
	lockdown = NULL;
	device = NULL;

	return node;
}

static int normal_get_nonce_by_key(struct idevicerestore_client_t* client, const char* key, unsigned char** nonce, int* nonce_size)
{
	plist_t nonce_node = normal_get_lockdown_value(client, NULL, key);

	if (!nonce_node || plist_get_node_type(nonce_node) != PLIST_DATA) {
		error("Unable to get %s\n", key);
		return -1;
	}

	uint64_t n_size = 0;
	plist_get_data_val(nonce_node, (char**)nonce, &n_size);
	*nonce_size = (int)n_size;
	plist_free(nonce_node);

	return 0;
}

int normal_get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size)
{
	return normal_get_nonce_by_key(client, "SEPNonce", nonce, nonce_size);
}

int normal_get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size)
{
	return normal_get_nonce_by_key(client, "ApNonce", nonce, nonce_size);
}

int normal_is_image4_supported(struct idevicerestore_client_t* client)
{
	plist_t node = normal_get_lockdown_value(client, NULL, "Image4Supported");

	if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
		return 0;
	}

	uint8_t bval = 0;
	plist_get_bool_val(node, &bval);
	plist_free(node);

	return bval;
}

int normal_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid)
{
	plist_t unique_chip_node = normal_get_lockdown_value(client, NULL, "UniqueChipID");
	if (!unique_chip_node || plist_get_node_type(unique_chip_node) != PLIST_UINT) {
		error("ERROR: Unable to get ECID\n");
		return -1;
	}
	plist_get_uint_val(unique_chip_node, ecid);
	plist_free(unique_chip_node);

	return 0;
}

int normal_get_preflight_info(struct idevicerestore_client_t* client, plist_t *preflight_info)
{
	plist_t node = normal_get_lockdown_value(client, NULL, "FirmwarePreflightInfo");
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to get FirmwarePreflightInfo\n");
		return -1;
	}
	*preflight_info = node;

	return 0;
}

int normal_handle_create_stashbag(struct idevicerestore_client_t* client, plist_t manifest)
{
	int result = -1;

	idevice_t device = NULL;
	idevice_error_t device_err;
	lockdownd_client_t lockdown;
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_error_t lerr;
	preboard_client_t preboard = NULL;
	preboard_error_t perr;

	device_err = idevice_new(&device, client->udid);
	if (device_err != IDEVICE_E_SUCCESS) {
		error("ERROR: Could not connect to device (%d)\n", device_err);
		return -1;
	}

	lerr = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (lerr != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Could not connect to lockdownd (%d)\n", lerr);
		idevice_free(device);
		return -1;
	}

	lerr = lockdownd_start_service(lockdown, PREBOARD_SERVICE_NAME, &service);
	if (lerr == LOCKDOWN_E_PASSWORD_PROTECTED) {
		info("*** Device is locked. Please unlock the device to continue. ***\n");
		while (1) {
			lerr = lockdownd_start_service(lockdown, PREBOARD_SERVICE_NAME, &service);
			if (lerr != LOCKDOWN_E_PASSWORD_PROTECTED) {
				break;
			}
			sleep(1);
		}
	}

	if (lerr != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Could not start preboard service (%d)\n", lerr);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	perr = preboard_client_new(device, service, &preboard);
	lockdownd_service_descriptor_free(service);
	lockdownd_client_free(lockdown);
	if (perr != PREBOARD_E_SUCCESS) {
		error("ERROR: Could not connect to preboard service (%d)\n", perr);
		idevice_free(device);
		return -1;
	}

	perr = preboard_create_stashbag(preboard, manifest, NULL, NULL);
	if (perr != PREBOARD_E_SUCCESS) {
		error("ERROR: Failed to trigger stashbag creation (%d)\n", perr);
		preboard_client_free(preboard);
		idevice_free(device);
		return -1;
	}

	int ticks = 0;
	while (ticks++ < 130) {
		plist_t pl = NULL;
		perr = preboard_receive_with_timeout(preboard, &pl, 1000);
		if (perr == PREBOARD_E_TIMEOUT) {
			continue;
		} else if (perr != PREBOARD_E_SUCCESS) {
			error("ERROR: could not receive from preboard service\n");
			break;
		} else {
			plist_t node;

			if (_plist_dict_get_bool(pl, "Skip")) {
				result = 0;
				info("Device does not require stashbag.\n");
				break;
			}

			if (_plist_dict_get_bool(pl, "ShowDialog")) {
				info("Device requires stashbag.\n");
				printf("******************************************************************************\n"
				       "* Please enter your passcode on the device.  The device will store a token   *\n"
				       "* that will be used after restore to access the user data partition.  This   *\n"
				       "* prevents an 'Attempting data recovery' process occurring after reboot that *\n"
				       "* may take a long time to complete and will _also_ require the passcode.     *\n"
				       "******************************************************************************\n");
				plist_free(pl);
				continue;
			}
			node = plist_dict_get_item(pl, "Error");
			if (node) {
				char *strval = NULL;
				node = plist_dict_get_item(pl, "ErrorString");
				if (node) {
					plist_get_string_val(node, &strval);
				}
				error("ERROR: Could not create stashbag: %s\n", (strval) ? strval : "(Unknown error)");
				free(strval);
				plist_free(pl);
				break;
			}
			if (_plist_dict_get_bool(pl, "Timeout")) {
				error("ERROR: Timeout while waiting for user to enter passcode.\n");
				result = -2;
				plist_free(pl);
				break;
			}
			if (_plist_dict_get_bool(pl, "HideDialog")) {
				plist_free(pl);
				/* hide dialog */
				result = 1;
				info("Stashbag created.\n");
				break;
			}
		}
		plist_free(pl);
	}
	preboard_client_free(preboard);
	idevice_free(device);

	return result;
}

int normal_handle_commit_stashbag(struct idevicerestore_client_t* client, plist_t manifest)
{
	int result = -1;

	idevice_t device = NULL;
	idevice_error_t device_err;
	lockdownd_client_t lockdown;
	lockdownd_service_descriptor_t service = NULL;
	lockdownd_error_t lerr;
	preboard_client_t preboard = NULL;
	preboard_error_t perr;
	plist_t pl = NULL;

	device_err = idevice_new(&device, client->udid);
	if (device_err != IDEVICE_E_SUCCESS) {
		error("ERROR: Could not connect to device (%d)\n", device_err);
		return -1;
	}

	lerr = lockdownd_client_new_with_handshake(device, &lockdown, "idevicerestore");
	if (lerr != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Could not connect to lockdownd (%d)\n", lerr);
		idevice_free(device);
		return -1;
	}

	lerr = lockdownd_start_service(lockdown, PREBOARD_SERVICE_NAME, &service);
	if (lerr == LOCKDOWN_E_PASSWORD_PROTECTED) {
		info("*** Device is locked. Please unlock the device to continue. ***\n");
		while (1) {
			lerr = lockdownd_start_service(lockdown, PREBOARD_SERVICE_NAME, &service);
			if (lerr != LOCKDOWN_E_PASSWORD_PROTECTED) {
				break;
			}
			sleep(1);
		}
	}

	if (lerr != LOCKDOWN_E_SUCCESS) {
		error("ERROR: Could not start preboard service (%d)\n", lerr);
		lockdownd_client_free(lockdown);
		idevice_free(device);
		return -1;
	}

	perr = preboard_client_new(device, service, &preboard);
	lockdownd_service_descriptor_free(service);
	lockdownd_client_free(lockdown);
	if (perr != PREBOARD_E_SUCCESS) {
		error("ERROR: Could not connect to preboard service (%d)\n", perr);
		idevice_free(device);
		return -1;
	}

	perr = preboard_commit_stashbag(preboard, manifest, NULL, NULL);
	if (perr != PREBOARD_E_SUCCESS) {
		error("ERROR: Failed to trigger stashbag creation (%d)\n", perr);
		preboard_client_free(preboard);
		idevice_free(device);
		return -1;
	}

	perr = preboard_receive_with_timeout(preboard, &pl, 30000);
	if (perr != PREBOARD_E_SUCCESS) {
		error("ERROR: could not receive from preboard service (%d)\n", perr);
	} else {
		int commit_complete = 0;
		plist_t node = plist_dict_get_item(pl, "Error");
		if (node) {
			char *strval = NULL;
			node = plist_dict_get_item(pl, "ErrorString");
			if (node) {
				plist_get_string_val(node, &strval);
			}
			error("ERROR: Could not commit stashbag: %s\n", (strval) ? strval : "(Unknown error)");
			free(strval);
		} else if (_plist_dict_get_bool(pl, "StashbagCommitComplete")) {
			info("Stashbag committed!\n");
			result = 0;
		} else {
			error("ERROR: Unexpected reply from preboard service\n");
			debug_plist(pl);
		}
		plist_free(pl);
	}
	preboard_client_free(preboard);
	idevice_free(device);

	return result;
}
