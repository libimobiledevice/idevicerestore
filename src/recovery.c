/*
 * recovery.c
 * Functions for handling idevices in recovery mode
 *
 * Copyright (c) 2010-2012 Martin Szulecki. All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libirecovery.h>
#include <libimobiledevice/restore.h>
#include <libimobiledevice/libimobiledevice.h>

#include "idevicerestore.h"
#include "tss.h"
#include "img3.h"
#include "restore.h"
#include "recovery.h"

int recovery_progress_callback(irecv_client_t client, const irecv_event_t* event) {
	if (event->type == IRECV_PROGRESS) {
		//print_progress_bar(event->progress);
	}
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

int recovery_client_new(struct idevicerestore_client_t* client) {
	int i = 0;
	int attempts = 20;
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_UNKNOWN_ERROR;

	if(client->recovery == NULL) {
		client->recovery = (struct recovery_client_t*)malloc(sizeof(struct recovery_client_t));
		if (client->recovery == NULL) {
			error("ERROR: Out of memory\n");
			return -1;
		}
		memset(client->recovery, 0, sizeof(struct recovery_client_t));
	}

	for (i = 1; i <= attempts; i++) {
		recovery_error = irecv_open_with_ecid(&recovery, client->ecid);
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

	if (client->srnm == NULL) {
		const struct irecv_device_info *device_info = irecv_get_device_info(recovery);
		if (device_info && device_info->srnm) {
			client->srnm = strdup(device_info->srnm);
			info("INFO: device serial number is %s\n", client->srnm);
		}
	}

	irecv_event_subscribe(recovery, IRECV_PROGRESS, &recovery_progress_callback, NULL);
	client->recovery->client = recovery;
	return 0;
}

int recovery_check_mode(struct idevicerestore_client_t* client) {
	irecv_client_t recovery = NULL;
	irecv_error_t recovery_error = IRECV_E_SUCCESS;
	int mode = 0;

	irecv_init();
	recovery_error=irecv_open_with_ecid(&recovery, client->ecid);

	if (recovery_error != IRECV_E_SUCCESS) {
		return -1;
	}

	irecv_get_mode(recovery, &mode);

	if ((mode == IRECV_K_DFU_MODE) || (mode == IRECV_K_WTF_MODE)) {
		irecv_close(recovery);
		return -1;
	}

	irecv_close(recovery);
	recovery = NULL;

	return 0;
}

int recovery_set_autoboot(struct idevicerestore_client_t* client, int enable) {
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	recovery_error = irecv_send_command(client->recovery->client, (enable) ? "setenv auto-boot true" : "setenv auto-boot false");
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
	if (client->build_major >= 8) {
		client->restore_boot_args = strdup("rd=md0 nand-enable-reformat=1 -progress");
	}

	/* upload data to make device boot restore mode */

	if(client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	if ((client->build_major > 8) && !(client->flags & FLAG_CUSTOM)) {
		if (!client->image4supported) {
			/* send ApTicket */
			if (recovery_send_ticket(client) < 0) {
				error("ERROR: Unable to send APTicket\n");
				return -1;
			}
		}
	}

	if (recovery_set_autoboot(client, 0) < 0) {
		return -1;
	}

	info("Recovery Mode Environment:\n");
	char* value = NULL;
	irecv_getenv(client->recovery->client, "build-version", &value);
	info("iBoot build-version=%s\n", (value) ? value : "(unknown)");
	if (value) {
		free(value);
		value = NULL;
	}
	irecv_getenv(client->recovery->client, "build-style", &value);
	info("iBoot build-style=%s\n", (value) ? value : "(unknown)");
	if (value) {
		free(value);
		value = NULL;
	}
	unsigned long radio_error = 0;
	irecv_getenv(client->recovery->client, "radio-error", &value);
	if (value) {
		radio_error = strtoul(value, NULL, 0);
	}
	if (radio_error > 0) {
		info("radio-error=%s\n", value);
		free(value);
		value = NULL;
		irecv_getenv(client->recovery->client, "radio-error-string", &value);
		if (value) {
			info("radio-error-string=%s\n", value);
			free(value);
			value = NULL;
		}
	}

	/* send logo and show it */
	if (recovery_send_applelogo(client, build_identity) < 0) {
		error("ERROR: Unable to send AppleLogo\n");
		return -1;
	}

	/* send ramdisk and run it */
	if (recovery_send_ramdisk(client, build_identity) < 0) {
		error("ERROR: Unable to send Ramdisk\n");
		return -1;
	}

	/* send devicetree and load it */
	if (recovery_send_devicetree(client, build_identity) < 0) {
		error("ERROR: Unable to send DeviceTree\n");
		return -1;
	}

	if (recovery_send_kernelcache(client, build_identity) < 0) {
		error("ERROR: Unable to send KernelCache\n");
		return -1;
	}

	client->mode = &idevicerestore_modes[MODE_RESTORE];
	return 0;
}

int recovery_send_ticket(struct idevicerestore_client_t* client)
{
	if (!client->tss) {
		error("ERROR: ApTicket requested but no TSS present\n");
		return -1;		
	}

	unsigned char* data = NULL;
	uint32_t size = 0;
	if (tss_response_get_ap_ticket(client->tss, &data, &size) < 0) {
		error("ERROR: Unable to get ApTicket from TSS request\n");
		return -1;
	}

	info("Sending APTicket (%d bytes)\n", size);
	irecv_error_t err = irecv_send_buffer(client->recovery->client, data, size, 0);
	if (err != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send APTicket: %s\n", irecv_strerror(err));
		free(data);
		return -1;
	}
	free(data);

	err = irecv_send_command(client->recovery->client, "ticket");
	if (err != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send ticket command\n");
		return -1;
	}

	return 0;
}

int recovery_send_component(struct idevicerestore_client_t* client, plist_t build_identity, const char* component) {
	unsigned int size = 0;
	unsigned char* data = NULL;
	char* path = NULL;
	irecv_error_t err = 0;

	if (client->tss) {
		if (tss_response_get_path_by_entry(client->tss, component, &path) < 0) {
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

	unsigned char* component_data = NULL;
	unsigned int component_size = 0;

	if (extract_component(client->ipsw, path, &component_data, &component_size) < 0) {
		error("ERROR: Unable to extract component: %s\n", component);
		free(path);
		return -1;
	}

	if (personalize_component(component, component_data, component_size, client->tss, &data, &size) < 0) {
		error("ERROR: Unable to get personalized component: %s\n", component);
		free(component_data);
		free(path);
		return -1;
	}
	free(component_data);
	component_data = NULL;	

	info("Sending %s (%d bytes)...\n", component, size);

	// FIXME: Did I do this right????
	err = irecv_send_buffer(client->recovery->client, data, size, 0);
	free(path);
	if (err != IRECV_E_SUCCESS) {
		error("ERROR: Unable to send %s component: %s\n", component, irecv_strerror(err));
		free(data);
		return -1;
	}

	free(data);
	return 0;
}

int recovery_send_ibec(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "iBEC";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "go");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}
	irecv_usb_control_transfer(client->recovery->client, 0x21, 1, 0, 0, 0, 0, 5000);

	return 0;
}

int recovery_send_applelogo(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "AppleLogo";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	info("Sending %s...\n", component);
	if (client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	recovery_error = irecv_send_command(client->recovery->client, "setpicture 2");
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
		if (recovery_client_new(client) < 0) {
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
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	irecv_send_command(client->recovery->client, "getenv ramdisk-size");
	irecv_receive(client->recovery->client);

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	irecv_send_command(client->recovery->client, "getenv ramdisk-delay");

	recovery_error = irecv_send_command(client->recovery->client, "ramdisk");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	sleep(2);

	return 0;
}

int recovery_send_kernelcache(struct idevicerestore_client_t* client, plist_t build_identity) {
	const char* component = "RestoreKernelCache";
	irecv_error_t recovery_error = IRECV_E_SUCCESS;

	if (client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	if (recovery_send_component(client, build_identity, component) < 0) {
		error("ERROR: Unable to send %s to device.\n", component);
		return -1;
	}

	irecv_usb_control_transfer(client->recovery->client, 0x21, 1, 0, 0, 0, 0, 5000);

	if (client->restore_boot_args) {
		char setba[256];
		strcpy(setba, "setenv boot-args ");
		strcat(setba, client->restore_boot_args);
		recovery_error = irecv_send_command(client->recovery->client, setba);
	}

	recovery_error = irecv_send_command(client->recovery->client, "bootx");
	if (recovery_error != IRECV_E_SUCCESS) {
		error("ERROR: Unable to execute %s\n", component);
		return -1;
	}

	return 0;
}

int recovery_get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	if(client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->recovery->client);
	if (!device_info) {
		return -1;
	}

	*ecid = device_info->ecid;

	return 0;
}

int recovery_is_image4_supported(struct idevicerestore_client_t* client)
{
	if(client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return 0;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->recovery->client);
	if (!device_info) {
		return 0;
	}

	return (device_info->ibfl & IBOOT_FLAG_IMAGE4_AWARE);
}

int recovery_get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	if(client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->recovery->client);
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

int recovery_get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	if(client->recovery == NULL) {
		if (recovery_client_new(client) < 0) {
			return -1;
		}
	}

	const struct irecv_device_info *device_info = irecv_get_device_info(client->recovery->client);
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

int recovery_send_reset(struct idevicerestore_client_t* client)
{
	irecv_send_command(client->recovery->client, "reset");
	return 0;
}

