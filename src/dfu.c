/*
 * dfu.c
 * Functions for handling idevices in DFU mode
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

#include "dfu.h"
#include "recovery.h"
#include "idevicerestore.h"

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
	irecv_error_t dfu_error = IRECV_E_UNKNOWN_ERROR;

	if (client->dfu == NULL) {
		client->dfu = (struct dfu_client_t*)malloc(sizeof(struct dfu_client_t));
		memset(client->dfu, 0, sizeof(struct dfu_client_t));
		if (client->dfu == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
	}

	for (i = 1; i <= attempts; i++) {
		dfu_error = irecv_open(&dfu);
		if (dfu_error == IRECV_E_SUCCESS) {
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

int dfu_check_mode() {
	irecv_client_t dfu = NULL;
	irecv_error_t dfu_error = IRECV_E_SUCCESS;

	irecv_init();
	dfu_error=irecv_open(&dfu);

	if (dfu_error != IRECV_E_SUCCESS) {
		return -1;
	}

	if (dfu->mode != kDfuMode) {
		irecv_close(dfu);
		return -1;
	}

	irecv_close(dfu);

	return 0;
}

int dfu_send_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component) {
	uint32_t size = 0;
	char* data = NULL;
	char* path = NULL;
	char* blob = NULL;
	irecv_error_t error = 0;

	if (client->tss) {
		if (tss_get_entry_path(client->tss, component, &path) < 0) {
			debug("NOTE: No path for component %s in TSS, will fetch from build_identity\n", component);
		}
	}
	if (!path) {
		if (build_identity_get_component_path(build_identity, component, &path) < 0) {
			error("ERROR: Unable to get path for component '%s'\n", component);
			if (path)
				free(path);
			return -1;
		}
	}

	if (client->tss)
		info("%s will be signed\n", component);

	if (ipsw_get_component_by_path(client->ipsw, client->tss, component, path, &data, &size) < 0) {
		error("ERROR: Unable to get component: %s\n", component);
		free(path);
		return -1;
	}

	if (!(client->flags & FLAG_CUSTOM) && (strcmp(component, "iBEC") == 0)) {
		char* ticket = NULL;
		uint32_t tsize = 0;
		if (tss_get_ticket(client->tss, &ticket, &tsize) < 0) {
			error("ERROR: Unable to get ApTicket from TSS request\n");
			return -1;
		}
		uint32_t fillsize = 0;
		if ((tsize % 0x100) != 0) {
			fillsize = ((tsize / 0x100) + 1) * 0x100;
		}
		debug("ticket size = %d\nfillsize = %d\n", tsize, fillsize);
		char* newdata = (char*)malloc(size + fillsize);
		memcpy(newdata, ticket, tsize);
		memset(newdata+tsize, '\xFF', fillsize - tsize);
		memcpy(newdata+fillsize, data, size);
		free(data);
		data = newdata;
		size += fillsize;
	}

	info("Sending %s (%d bytes)...\n", component, size);

	// FIXME: Did I do this right????
	error = irecv_send_buffer(client->dfu->client, data, size, 1);
	free(path);
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send %s component: %s\n", component, irecv_strerror(error));
		free(data);
		return -1;
	}

	free(data);
	return 0;
}

int dfu_get_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	irecv_error_t dfu_error = IRECV_E_SUCCESS;

	if(client->dfu == NULL) {
		if (dfu_client_new(client) < 0) {
			return -1;
		}
	}

	dfu_error = irecv_get_nonce(client->dfu->client, nonce, nonce_size);
	if (dfu_error != IRECV_E_SUCCESS) {
		return -1;
	}

	return 0;
}

int dfu_enter_recovery(struct idevicerestore_client_t* client, plist_t build_identity) {
	irecv_error_t dfu_error = IRECV_E_SUCCESS;

	if (dfu_client_new(client) < 0) {
		error("ERROR: Unable to connect to DFU device\n");
		return -1;
	}

	if (client->dfu->client->mode != kDfuMode) {
		info("NOTE: device is not in DFU mode, assuming recovery mode.\n");
		client->mode = &idevicerestore_modes[MODE_RECOVERY];
		return 0;
	}

	if (dfu_send_component(client, build_identity, "iBSS") < 0) {
		error("ERROR: Unable to send iBSS to device\n");
		irecv_close(client->dfu->client);
		return -1;
	}

	dfu_error = irecv_reset(client->dfu->client);
	if (dfu_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to reset device\n");
		irecv_close(client->dfu->client);
		return -1;
	}

	if (client->build[0] > '8') {
		/* reconnect */
		dfu_client_free(client);
		sleep(1);
		dfu_client_new(client);

		/* get nonce */
		unsigned char* nonce = NULL;
		int nonce_size = 0;
		int nonce_changed = 0;
		if (dfu_get_nonce(client, &nonce, &nonce_size) < 0) {
			error("ERROR: Unable to get nonce from device!\n");
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
			if (get_shsh_blobs(client, client->ecid, client->nonce, client->nonce_size, build_identity, &client->tss) < 0) {
				error("ERROR: Unable to get SHSH blobs for this device\n");
				return -1;
			}
			if (!client->tss) {
				error("ERROR: can't continue without TSS\n");
				return -1;
			}
			fixup_tss(client->tss);
		}

		if (irecv_set_configuration(client->dfu->client, 1) < 0) {
			error("ERROR: set configuration failed\n");
		}

		/* send iBEC */
		if (dfu_send_component(client, build_identity, "iBEC") < 0) {
			error("ERROR: Unable to send iBEC to device\n");
			irecv_close(client->dfu->client);
			return -1;
		}

		dfu_error = irecv_reset(client->dfu->client);
		if (dfu_error != IRECV_E_SUCCESS) {
			error("ERROR: Unable to reset device\n");
			irecv_close(client->dfu->client);
			return -1;
		}
	}

	dfu_client_free(client);

	sleep(7);

	// Reconnect to device, but this time make sure we're not still in DFU mode
	if (recovery_client_new(client) < 0 || client->recovery->client->mode == kDfuMode) {
		error("ERROR: Unable to connect to recovery device\n");
		if (client->recovery->client)
			irecv_close(client->recovery->client);
		return -1;
	}
	return 0;
}

