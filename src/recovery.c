/*
 * recovery.c
 * Functions for handling idevices in recovery mode
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
#include <libimobiledevice/restore.h>
#include <libimobiledevice/libimobiledevice.h>

#include "tss.h"
#include "img3.h"
#include "common.h"
#include "restore.h"
#include "recovery.h"
#include "idevicerestore.h"

int recovery_progress_callback(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_PROGRESS) {
		print_progress_bar(event->progress);
	}
	return 0;
}

int recovery_client_new(struct idevicerestore_client_t* client) {
	struct recovery_client_t* recovery = (struct recovery_client_t*) malloc(sizeof(struct recovery_client_t));
	if (recovery == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}

	client->recovery = recovery;

	if (recovery_open_with_timeout(client) < 0) {
		recovery_client_free(client);
		return -1;
	}

	client->recovery = recovery;
	return 0;
}

void recovery_client_free(struct idevicerestore_client_t* client) {
	if(client) {
		if (client->recovery) {
			if(client->recovery->client) {
				irecv_close(client->recovery->client);
				client->recovery->client = NULL;
			}
			free(client->recovery);
			client->recovery = NULL;
		}
	}
}

int recovery_open_with_timeout(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 10;
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_UNKNOWN_ERROR;

	if(client->recovery == NULL) {
		if(recovery_client_new(client) < 0) {
			error("ERROR: Unable to open device in recovery mode\n");
			return -1;
		}
		return 0;
	}

	for (i = 1; i <= attempts; i++) {
		recovery_error = irecv_open(&recovery);
		if (recovery_error == IRECV_E_SUCCESS) {
			break;
		}

		if (i >= attempts) {
			error("ERROR: Unable to connect to device in recovery mode\n");
			return -1;
		}

		sleep(4);
		debug("Retrying connection...\n");
	}

	irecv_event_subscribe(recovery, IRECV_PROGRESS, &recovery_progress_callback, NULL);
	client->recovery->client = recovery;
	return 0;
}

int recovery_check_mode() {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	irecv_init();
	recovery_error=irecv_open(&recovery);

	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	if (recovery->mode == kDfuMode) {
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;

	return 0;
}

static int recovery_enable_autoboot(struct idevicerestore_client_t* client) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	//recovery_error = irecv_setenv(client->recovery->client, "auto-boot", "true");
	recovery_error = irecv_send_command(client->recovery->client, "setenv auto-boot true");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to set auto-boot environmental variable\n");
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "saveenv");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to save environmental variable\n");
		return -1;
	}

	return 0;
}

int recovery_enter_restore(struct idevicerestore_client_t* client, plist_t build_identity) {
	idevice_t device = NULL;
	restored_client_t restore = NULL;

	/* upload data to make device boot restore mode */

	if (recovery_enable_autoboot(client) < 0) {
		return -1;
	}

	/* send iBEC and run it */
	if (recovery_send_ibec(client, build_identity) < 0) {
		error("ERROR: Unable to send iBEC\n");
		return -1;
	}

	/* this must be long enough to allow the device to run the iBEC */
	/* FIXME: Probably better to detect if the device is back then */
	sleep(4);

	/* send logo and show it */
	if (recovery_send_applelogo(client, build_identity) < 0) {
		error("ERROR: Unable to send AppleLogo\n");
		return -1;
	}

	/* send devicetree and load it */
	if (recovery_send_devicetree(client, build_identity) < 0) {
		error("ERROR: Unable to send DeviceTree\n");
		return -1;
	}

	/* send ramdisk and run it */
	if (recovery_send_ramdisk(client, build_identity) < 0) {
		error("ERROR: Unable to send Ramdisk\n");
		return -1;
	}

	// for some reason iboot requires a hard reset after ramdisk
	//  or things start getting wacky
	printf("Please unplug your device, then plug it back in\n");
	printf("Hit any key to continue...");
	getchar();

	if (recovery_send_kernelcache(client, build_identity) < 0) {
		error("ERROR: Unable to send KernelCache\n");
		return -1;
	}

	info("Waiting for device to enter restore mode\n");
	if (restore_open_with_timeout(client) < 0) {
		error("ERROR: Unable to connect to device in restore mode\n");
		return -1;
	}

	restore_client_free(client);
	client->mode = &idevicerestore_modes[MODE_RESTORE];
	return 0;
}

int recovery_send_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component) {
	uint32_t size = 0;
	char* data = NULL;
	char* path = NULL;
	char* blob = NULL;
	irecv_error_t error = 0;

	if (client->tss) {
		if (tss_get_entry_path(client->tss, component, &path) < 0) {
			error("ERROR: Unable to get component path\n");
			return -1;
		}
	} else {
		if (build_identity_get_component_path(build_identity, component, &path) < 0) {
			error("ERROR: Unable to get component: %s\n", component);
			if (path)
				free(path);
			return -1;
		}
	}

	info("Resetting recovery mode connection...\n");
	irecv_reset(client->recovery->client);

	if (client->tss)
		info("%s will be signed\n", component);

	if (ipsw_get_component_by_path(client->ipsw, client->tss, path, &data, &size) < 0) {
		error("ERROR: Unable to get component: %s\n", component);
		free(path);
		return -1;
	}

	info("Sending %s (%d bytes)...\n", component, size);

	// FIXME: Did I do this right????
	error = irecv_send_buffer(client->recovery->client, data, size, 0);
	free(path);
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send %s component: %s\n", component, irecv_strerror(error));
		free(data);
		return -1;
	}

	free(data);
	return 0;
}

int recovery_send_ibec(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "iBEC";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "go");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_send_applelogo(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "AppleLogo";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	info("Sending %s...\n", component);
	if (recovery_open_with_timeout(client) < 0) {
		return -1;
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "setpicture 1");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to set %s\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "bgcolor 0 0 0");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to display %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_send_devicetree(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "RestoreDeviceTree";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if(client->recovery == NULL) {
		if (recovery_open_with_timeout(client) < 0) {
			return -1;
		}
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "devicetree");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_send_ramdisk(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char *component = "RestoreRamDisk";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if(client->recovery == NULL) {
		if (recovery_open_with_timeout(client) < 0) {
			return -1;
		}
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "ramdisk");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_send_kernelcache(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "RestoreKernelCache";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(client) < 0) {
		return -1;
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "bootx");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if(client->recovery == NULL) {
		if (recovery_open_with_timeout(client) < 0) {
			return -1;
		}
	}

	recovery_error = irecv_get_ecid(client->recovery->client, ecid);
	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	return 0;
}

int recovery_get_cpid(struct idevicerestore_client_t* client, uint32_t* cpid) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if(client->recovery == NULL) {
		if (recovery_open_with_timeout(client) < 0) {
			return -1;
		}
	}

	recovery_error = irecv_get_cpid(client->recovery->client, cpid);
	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	return 0;
}

int recovery_get_bdid(struct idevicerestore_client_t* client, uint32_t* bdid) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if(client->recovery == NULL) {
		if (recovery_open_with_timeout(client) < 0) {
			return -1;
		}
	}

	recovery_error = irecv_get_bdid(client->recovery->client, bdid);
	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	return 0;
}
