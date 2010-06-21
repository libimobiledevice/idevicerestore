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
#include <stdint.h>
#include <libirecovery.h>
#include <libimobiledevice/restore.h>
#include <libimobiledevice/libimobiledevice.h>

#include "tss.h"
#include "img3.h"
#include "common.h"
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

	if (recovery_open_with_timeout(recovery) < 0) {
		recovery_client_free(recovery);
		return -1;
	}

	if(recovery_check_mode(recovery) < 0) {
		recovery_client_free(recovery);
		return -1;
	}

	client->recovery = recovery;
	return 0;
}

void recovery_client_free(struct idevicerestore_client_t* client) {
	struct recovery_client_t* recovery = client->recovery;
	if (recovery) {
		if(recovery->client) {
			irecv_close(recovery);
			recovery = NULL;
		}
		free(recovery);
		client->recovery = NULL;

	}
}

int recovery_check_mode() {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	recovery_error = irecv_open(&recovery);
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

int recovery_enter_restore(const char* uuid, const char* ipsw, plist_t tss) {
	idevice_t device = NULL;
	restored_client_t restore = NULL;

	// upload data to make device boot restore mode
	if (recovery_send_ibec(ipsw, tss) < 0) {
		error("ERROR: Unable to send iBEC\n");
		return -1;
	}
	sleep(1);

	if (recovery_send_applelogo(ipsw, tss) < 0) {
		error("ERROR: Unable to send AppleLogo\n");
		return -1;
	}

	if (recovery_send_devicetree(ipsw, tss) < 0) {
		error("ERROR: Unable to send DeviceTree\n");
		return -1;
	}

	if (recovery_send_ramdisk(ipsw, tss) < 0) {
		error("ERROR: Unable to send Ramdisk\n");
		return -1;
	}

	// for some reason iboot requires a hard reset after ramdisk
	//  or things start getting wacky
	printf("Please unplug your device, then plug it back in\n");
	printf("Hit any key to continue...");
	getchar();

	if (recovery_send_kernelcache(ipsw, tss) < 0) {
		error("ERROR: Unable to send KernelCache\n");
		return -1;
	}

	info("Waiting for device to enter restore mode\n");
	if (restore_open_with_timeout(uuid, &device, &restore) < 0) {
		error("ERROR: Unable to connect to device in restore mode\n");
		return -1;
	}

	restore_close(device, restore);
	client->mode = &idevicerestore_modes[MODE_RESTORE];
	return 0;
}

int recovery_send_signed_component(struct idevicerestore_client_t client, const char* ipsw, plist_t tss, char* component) {
	int size = 0;
	char* data = NULL;
	char* path = NULL;
	char* blob = NULL;
	irecv_error_t error = 0;

	if (tss_get_entry_path(tss, component, &path) < 0) {
		error("ERROR: Unable to get component path\n");
		return -1;
	}

	if (get_signed_component(client, ipsw, tss, path, &data, &size) < 0) {
		error("ERROR: Unable to get signed component: %s\n", component);
		free(path);
		return -1;
	}
	free(path);

	info("Sending %s...\n", component);
	error = irecv_send_buffer(client, data, size);
	if (error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send component: %s\n", component);
		free(data);
		return -1;
	}

	free(data);
	return 0;
}

int recovery_open_with_timeout(irecv_client_t* client) {
	int i = 0;
	int attempts = 10;
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_UNKNOWN_ERROR;

	for (i = 1; i <= attempts; i++) {
		recovery_error = irecv_open(&recovery);
		if (recovery_error == IRECV_E_SUCCESS) {
			break;
		}

		if (i >= attempts) {
			error("ERROR: Unable to connect to device in recovery mode\n");
			return -1;
		}

		sleep(2);
		debug("Retrying connection...\n");
	}

	irecv_event_subscribe(recovery, IRECV_PROGRESS, &recovery_progress_callback, NULL);
	*client = recovery;
	return 0;
}

int recovery_send_ibec(const char* ipsw, plist_t tss) {
	irecv_client_t recovery = NULL;
	const char* component = "iBEC";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "setenv auto-boot true");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to set auto-boot environmental variable\n");
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "saveenv");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to save environmental variable\n");
		irecv_close(recovery);
		return -1;
	}

	if (recovery_send_signed_component(recovery, ipsw, tss, "iBEC") < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "go");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_send_applelogo(const char* ipsw, plist_t tss) {
	irecv_client_t recovery = NULL;
	const char* component = "applelogo";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	info("Sending %s...\n", component);
	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	if (recovery_send_signed_component(recovery, ipsw, tss, "AppleLogo") < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "setpicture 1");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to set %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "bgcolor 0 0 0");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to display %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_send_devicetree(const char* ipsw, plist_t tss) {
	irecv_client_t recovery = NULL;
	const char* component = "devicetree";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	if (recovery_send_signed_component(recovery, ipsw, tss, "RestoreDeviceTree") < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "devicetree");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_send_ramdisk(const char* ipsw, plist_t tss) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;
	irecv_client_t recovery = NULL;
	const char *component = "ramdisk";

	recovery_error = recovery_open_with_timeout(&recovery);
	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	if (recovery_send_signed_component(recovery, ipsw, tss, "RestoreRamDisk") < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "ramdisk");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_send_kernelcache(const char* ipsw, plist_t tss) {
	irecv_client_t recovery = NULL;
	const char* component = "kernelcache";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	if (recovery_send_signed_component(recovery, ipsw, tss, "RestoreKernelCache") < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		irecv_close(recovery);
		return -1;
	}

	recovery_error = irecv_send_command(recovery, "bootx");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_get_ecid(uint64_t* ecid) {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	recovery_error = irecv_get_ecid(recovery, ecid);
	if (recovery_error != IRECV_E_SUCCESS) {
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_get_cpid(uint32_t* cpid) {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	recovery_error = irecv_get_cpid(recovery, cpid);
	if (recovery_error != IRECV_E_SUCCESS) {
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}

int recovery_get_bdid(uint32_t* bdid) {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (recovery_open_with_timeout(&recovery) < 0) {
		return -1;
	}

	recovery_error = irecv_get_bdid(recovery, bdid);
	if (recovery_error != IRECV_E_SUCCESS) {
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;
	return 0;
}
