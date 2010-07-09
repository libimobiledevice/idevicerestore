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

int dfu_client_new(struct idevicerestore_client_t* client, uint32_t timeout) {
	struct dfu_client_t* dfu = NULL;
	if(client == NULL) {
		return -1;
	}

	if(client->dfu) {
		dfu_client_free(client);
	}

	dfu = (struct dfu_client_t*) malloc(sizeof(struct dfu_client_t));
	if (dfu == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}

	if (dfu_open_with_timeout(dfu, timeout) < 0) {
		dfu_client_free(client);
		return -1;
	}

	if(dfu->client->mode != kDfuMode) {
		dfu_client_free(client);
		return -1;
	}

	client->dfu = dfu;
	return 0;
}

void dfu_client_free(struct idevicerestore_client_t* client) {
	struct dfu_client_t* dfu = NULL;
	if(client != NULL) {
		dfu = client->dfu;
		if (dfu != NULL) {
			if(dfu->client != NULL) {
				irecv_close(dfu->client);
				dfu->client = NULL;
			}
			free(dfu);
		}
		client->dfu = NULL;
	}
}

int dfu_open_with_timeout(struct idevicerestore_client_t* client, uint32_t timeout) {
	int i = 0;
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_UNKNOWN_ERROR;

	for (i = 1; i <= timeout; i++) {
		recovery_error = irecv_open(&recovery);
		if (recovery_error == IRECV_E_SUCCESS) {
			break;
		}

		if (i == timeout) {
			error("ERROR: Unable to connect to device in DFU mode\n");
			return -1;
		}

		sleep(1);
		debug("Retrying connection...\n");
	}

	irecv_event_subscribe(recovery, IRECV_PROGRESS, &dfu_progress_callback, NULL);
	client->dfu->client = recovery;
	return 0;
}

int dfu_check_mode() {
	return -1;
}

int dfu_enter_recovery(struct idevicerestore_client_t* client, plist_t build_identity) {
	irecv_client_t dfu = NULL;
	const char* component = "iBSS";
	irecv_error_t dfu_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(client) < 0 || dfu->mode != kDfuMode) {
		error("ERROR: Unable to connect to DFU device\n");
		if (dfu)
			irecv_close(dfu);
		return -1;
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device\n", component);
		irecv_close(dfu);
		return -1;
	}

	dfu_error = irecv_reset(client->dfu->client);
	if (dfu_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to reset device\n");
		irecv_close(dfu);
		return -1;
	}
	irecv_close(client->dfu->client);
	client->dfu->client = NULL;

	// Reconnect to device, but this time make sure we're not still in DFU mode
	if (recovery_open_with_timeout(client) < 0 || client->mode->index != kDfuMode) {
		error("ERROR: Unable to connect to recovery device\n");
		if (client->dfu->client)
			irecv_close(client->dfu->client);
		return -1;
	}

	client->mode = &idevicerestore_modes[MODE_RECOVERY];
	irecv_close(client->dfu->client);
	client->dfu->client = NULL;
	return 0;
}

