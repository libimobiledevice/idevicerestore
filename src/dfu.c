/*
 * dfu.c
 * Functions for handling idevices in DFU mode
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010-2013 Martin Szulecki. All Rights Reserved.
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

#include "dfu.h"
#include "tss.h"
#include "recovery.h"
#include "idevicerestore.h"
#include "common.h"

int dfu_progress_callback(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_PROGRESS) {
		print_progress_bar(event->progress);
	}
	return 0;
}

int dfu_client_new(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 10;
	irecv_client_t dfu = NULL;

	if (client->dfu == NULL) {
		client->dfu = (struct dfu_client_t*)malloc(sizeof(struct dfu_client_t));
		memset(client->dfu, 0, sizeof(struct dfu_client_t));
		if (client->dfu == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
	}

	for (i = 1; i <= attempts; i++) {
		if (irecv_open_with_ecid(&dfu, client->ecid) == IRECV_E_SUCCESS) {
			break;
		}

		if (i >= attempts) {
			error("ERROR: Unable to connect to device in DFU mode\n");
			return -1;
		}

		sleep(1);
		debug("Retrying connection...\n");
	}

	irecv_event_subscribe(dfu, IRECV_PROGRESS, &dfu_progress_callback, NULL);
	client->dfu->client = dfu;
	return 0;
}

void dfu_client_free(struct idevicerestore_client_t* client) {
	if(client != NULL) {
		if (client->dfu != NULL) {
			if(client->dfu->client != NULL) {
				irecv_close(client->dfu->client);
				client->dfu->client = NULL;
			}
			free(client->dfu);
		}
		client->dfu = NULL;
	}
}

int dfu_check_mode(struct idevicerestore_client_t* client, int* mode) {
	irecv_client_t dfu = NULL;
	int probe_mode = -1;

	if (client->udid && client->ecid == 0) {
		/* if we have a UDID but no ECID we can't make sure this is the correct device */
		return -1;
	}

	irecv_init();
	if (irecv_open_with_ecid(&dfu, client->ecid) != IRECV_E_SUCCESS) {
		return -1;
	}

	irecv_get_mode(dfu, &probe_mode);

	if ((probe_mode != IRECV_K_DFU_MODE) && (probe_mode != IRECV_K_WTF_MODE)) {
		irecv_close(dfu);
		return -1;
	}

	*mode = (probe_mode == IRECV_K_WTF_MODE) ? MODE_WTF : MODE_DFU;

	irecv_close(dfu);

	return 0;
}

irecv_device_t dfu_get_irecv_device(struct idevicerestore_client_t* client) {
	irecv_client_t dfu = NULL;
	irecv_error_t dfu_error = IRECV_E_SUCCESS;
	irecv_device_t device = NULL;

	irecv_init();
	if (irecv_open_with_ecid(&dfu, client->ecid) != IRECV_E_SUCCESS) {
		return NULL;
	}

	dfu_error = irecv_devices_get_device_by_client(dfu, &device);
	irecv_close(dfu);
	if (dfu_error != IRECV_E_SUCCESS) {
		return NULL;
	}

	return device;
}

int dfu_send_buffer(struct idevicerestore_client_t* client, unsigned char* buffer, unsigned int size)
{
	irecv_error_t err = 0;

	info("Sending data (%d bytes)...\n", size);

	err = irecv_send_buffer(client->dfu->client, buffer, size, 1);
	if (err != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send data: %s\n", irecv_strerror(err));
		return -1;
	}

	return 0;
}

int dfu_send_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component) {
	char* path = NULL;

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, component, &path) < 0) {
			debug("NOTE: No path for component %s in TSS, will fetch from build_identity\n", component);
		}
	}
	if (!path) {
		if (build_identity_get_component_path(build_identity, component, &path) < 0) {
			error("ERROR: Unable to get path for component '%s'\n", component);
			free(path);
			return -1;
		}
	}

	unsigned char* component_data = NULL;
	unsigned int component_size = 0;

	if (extract_component(client->ipsw, path, &component_data, &component_size) < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		free(path);
		return -1;
	}
	free(path);
	path = NULL;

	unsigned char* data = NULL;
	uint32_t size = 0;

	if (personalize_component(component, component_data, component_size, client->tss, &data, &size) < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		free(component_data);
		return -1;
	}
	free(component_data);
	component_data = NULL;

	if (!client->image4supported && client->build_major > 8 && !(client->flags & FLAG_CUSTOM) && !strcmp(component, "iBEC")) {
		unsigned char* ticket = NULL;
		unsigned int tsize = 0;
		if (tss_response_get_ap_ticket(client->tss, &ticket, &tsize) < 0) {
			error("ERROR: Unable to get ApTicket from TSS request\n");
			return -1;
		}
		uint32_t fillsize = 0;
		if (tsize % 64 != 0) {
			fillsize = ((tsize / 64) + 1) * 64;
		}
		debug("ticket size = %d\nfillsize = %d\n", tsize, fillsize);
		unsigned char* newdata = (unsigned char*)malloc(size + fillsize);
		memcpy(newdata, ticket, tsize);
		memset(newdata + tsize, '\xFF', fillsize - tsize);
		memcpy(newdata + fillsize, data, size);
		free(data);
		data = newdata;
		size += fillsize;
	}

	info("Sending %s (%d bytes)...\n", component, size);

	// FIXME: Did I do this right????
	irecv_error_t err = irecv_send_buffer(client->dfu->client, data, size, 1);
	if (err != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send %s component: %s\n", component, irecv_strerror(err));
		free(data);
		return -1;
	}

	free(data);
	return 0;
}

int dfu_get_cpid(struct idevicerestore_client_t* client, unsigned int* cpid) {
	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}

	*cpid = device_info->cpid;

	return 0;
}

int dfu_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}

	*ecid = device_info->ecid;

	return 0;
}

int dfu_is_image4_supported(struct idevicerestore_client_t* client)
{
	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return 0;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return 0;
	}

	return (device_info->ibfl & IBOOT_FLAG_IMAGE4_AWARE);
}

int dfu_get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}

	if (device_info->ap_nonce && device_info->ap_nonce_size > 0) {
		*nonce = (unsigned char*)malloc(device_info->ap_nonce_size);
		if (!*nonce) {
			return -1;
		}
		*nonce_size = device_info->ap_nonce_size;
		memcpy(*nonce, device_info->ap_nonce, *nonce_size);
	}

	return 0;
}

int dfu_get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->dfu->client);
	if (!device_info) {
		return -1;
	}

	if (device_info->sep_nonce && device_info->sep_nonce_size > 0) {
		*nonce = (unsigned char*)malloc(device_info->sep_nonce_size);
		if (!*nonce) {
			return -1;
		}
		*nonce_size = device_info->sep_nonce_size;
		memcpy(*nonce, device_info->sep_nonce, *nonce_size);
	}

	return 0;
}

int dfu_enter_recovery(struct idevicerestore_client_t* client, plist_t build_identity)
{
	int mode = 0;

	if (dfu_client_new(client) < 0) {
		error("ERROR: Unable to connect to DFU device\n");
		return -1;
	}

	irecv_get_mode(client->dfu->client, &mode);

	if (mode != IRECV_K_DFU_MODE) {
		info("NOTE: device is not in DFU mode, assuming recovery mode.\n");
		client->mode = &idevicerestore_modes[MODE_RECOVERY];
		return 0;
	}

	mutex_lock(&client->device_event_mutex);

	if (dfu_send_component(client, build_identity, "iBSS") < 0) {
		error("ERROR: Unable to send iBSS to device\n");
		irecv_close(client->dfu->client);
		client->dfu->client = NULL;
		return -1;
	}
	dfu_client_free(client);

	if (client->build_major > 8) {
		/* reconnect */
		debug("Waiting for device to disconnect...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
		if (client->mode != &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			if (!(client->flags & FLAG_QUIT)) {
				error("ERROR: Device did not disconnect. Possibly invalid iBSS. Reset device and try again.\n");
			}
			return -1;
		}
		debug("Waiting for device to reconnect...\n");
		cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
		if ((client->mode != &idevicerestore_modes[MODE_DFU] && client->mode != &idevicerestore_modes[MODE_RECOVERY]) || (client->flags & FLAG_QUIT)) {
			mutex_unlock(&client->device_event_mutex);
			if (!(client->flags & FLAG_QUIT)) {
				error("ERROR: Device did not reconnect in DFU or recovery mode. Possibly invalid iBSS. Reset device and try again.\n");
			}
			return -1;
		}
		mutex_unlock(&client->device_event_mutex);
		dfu_client_new(client);

		/* get nonce */
		unsigned char* nonce = NULL;
		int nonce_size = 0;
		int nonce_changed = 0;
		if (dfu_get_ap_nonce(client, &nonce, &nonce_size) < 0) {
			error("ERROR: Unable to get ApNonce from device!\n");
			return -1;
		}

		if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
			nonce_changed = 1;
			if (client->nonce) {
				free(client->nonce);
			}
			client->nonce = nonce;
			client->nonce_size = nonce_size;
		} else {
			free(nonce);
		}

		info("Nonce: ");
		int i;
		for (i = 0; i < client->nonce_size; i++) {
			info("%02x ", client->nonce[i]);
		}
		info("\n");

		if (nonce_changed && !(client->flags & FLAG_CUSTOM)) {
			// Welcome iOS5. We have to re-request the TSS with our nonce.
			plist_free(client->tss);
			if (get_tss_response(client, build_identity, &client->tss) < 0) {
				error("ERROR: Unable to get SHSH blobs for this device\n");
				return -1;
			}
			if (!client->tss) {
				error("ERROR: can't continue without TSS\n");
				return -1;
			}
			fixup_tss(client->tss);
		}

		if (irecv_usb_set_configuration(client->dfu->client, 1) < 0) {
			error("ERROR: set configuration failed\n");
		}

		mutex_lock(&client->device_event_mutex);

		/* send iBEC */
		if (dfu_send_component(client, build_identity, "iBEC") < 0) {
			mutex_unlock(&client->device_event_mutex);
			error("ERROR: Unable to send iBEC to device\n");
			irecv_close(client->dfu->client);
			client->dfu->client = NULL;
			return -1;
		}

		if (client->mode == &idevicerestore_modes[MODE_RECOVERY]) {
			if (irecv_send_command(client->dfu->client, "go") != IRECV_E_SUCCESS) {
				mutex_unlock(&client->device_event_mutex);
				error("ERROR: Unable to execute iBEC\n");
				return -1;
			}
			irecv_usb_control_transfer(client->dfu->client, 0x21, 1, 0, 0, 0, 0, 5000);
		}
		dfu_client_free(client);
	}

	debug("Waiting for device to disconnect...\n");
	cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
	if (client->mode != &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT)) {
		mutex_unlock(&client->device_event_mutex);
		if (!(client->flags & FLAG_QUIT)) {
			error("ERROR: Device did not disconnect. Possibly invalid %s. Reset device and try again.\n", (client->build_major > 8) ? "iBEC" : "iBSS");
		}
		return -1;
	}
	debug("Waiting for device to reconnect in recovery mode...\n");
	cond_wait_timeout(&client->device_event_cond, &client->device_event_mutex, 10000);
	if (client->mode != &idevicerestore_modes[MODE_RECOVERY] || (client->flags & FLAG_QUIT)) {
		mutex_unlock(&client->device_event_mutex);
		if (!(client->flags & FLAG_QUIT)) {
			error("ERROR: Device did not reconnect in recovery mode. Possibly invalid %s. Reset device and try again.\n", (client->build_major > 8) ? "iBEC" : "iBSS");
		}
		return -1;
	}
	mutex_unlock(&client->device_event_mutex);

	if (recovery_client_new(client) < 0) {
		error("ERROR: Unable to connect to recovery device\n");
		if (client->recovery->client) {
			irecv_close(client->recovery->client);
			client->recovery->client = NULL;
		}
		return -1;
	}

	return 0;
}

