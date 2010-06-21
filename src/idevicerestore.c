/*
 * idevicerestore.c
 * Restore device firmware and filesystem
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
#include <unistd.h>
#include <getopt.h>
#include <plist/plist.h>

#include "dfu.h"
#include "tss.h"
#include "img3.h"
#include "ipsw.h"
#include "common.h"
#include "normal.h"
#include "restore.h"
#include "recovery.h"
#include "idevicerestore.h"

static struct option longopts[] = {
	{ "uuid",    required_argument, NULL, 'u' },
	{ "debug",   no_argument,       NULL, 'd' },
	{ "help",    no_argument,       NULL, 'h' },
	{ "erase",   no_argument,       NULL, 'e' },
	{ "custom",  no_argument,       NULL, 'c' },
	{ "exclude", no_argument,       NULL, 'x' },
	{ NULL, 0, NULL, 0 }
};

void usage(int argc, char* argv[]) {
	char *name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] FILE\n", (name ? name + 1 : argv[0]));
	printf("Restore/upgrade IPSW firmware FILE to an iPhone/iPod Touch.\n");
	printf("  -u, --uuid UUID\ttarget specific device by its 40-digit device UUID\n");
	printf("  -d, --debug\t\tenable communication debugging\n");
	printf("  -h, --help\t\tprints usage information\n");
	printf("  -e, --erase\t\tperform a full restore, erasing all data\n");
	printf("  -c, --custom\t\trestore with a custom firmware\n");
	printf("  -x, --exclude\t\texclude nor/baseband upgrade\n");
	printf("\n");
}

int main(int argc, char* argv[]) {
	int opt = 0;
	int optindex = 0;
	char* ipsw = NULL;
	char* uuid = NULL;
	uint64_t ecid = 0;

	// create an instance of our context
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) malloc(sizeof(struct idevicerestore_client_t));
	if (client == NULL) {
		error("ERROR: Out of memory\n");
		return -1;
	}
	memset(client, '\0', sizeof(struct idevicerestore_client_t));

	while ((opt = getopt_long(argc, argv, "dhcexu:", longopts, &optindex)) > 0) {
		switch (opt) {
		case 'h':
			usage(argc, argv);
			break;

		case 'd':
			client->flags &= FLAG_DEBUG;
			break;

		case 'e':
			client->flags &= FLAG_ERASE;
			break;

		case 'c':
			client->flags &= FLAG_CUSTOM;
			break;

		case 'x':
			client->flags &= FLAG_EXCLUDE;
			break;

		case 'u':
			uuid = optarg;
			break;

		default:
			usage(argc, argv);
			return -1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1) {
		ipsw = argv[0];
	} else {
		usage(argc, argv);
		return -1;
	}

	if (client->flags & FLAG_DEBUG) {
		idevice_set_debug_level(1);
		irecv_set_debug_level(1);
	}

	client->uuid = uuid;
	client->ipsw = ipsw;

	// check which mode the device is currently in so we know where to start
	if (check_mode(client) < 0 || client->mode->index == MODE_UNKNOWN) {
		error("ERROR: Unable to discover current device state\n");
		return -1;
	}
	info("Found device in %s mode\n", client->mode->string);

	// discover the device type
	if (check_device(client) < 0 || client->device->index == DEVICE_UNKNOWN) {
		error("ERROR: Unable to discover device type\n");
		return -1;
	}
	info("Identified device as %s\n", client->device->product);

	if (client->mode->index == MODE_RESTORE) {
		if (restore_reboot(client) < 0) {
			error("ERROR: Unable to exit restore mode\n");
			return -1;
		}
	}

	// extract buildmanifest
	plist_t buildmanifest = NULL;
	info("Extracting BuildManifest from IPSW\n");
	if (extract_buildmanifest(client, ipsw, &buildmanifest) < 0) {
		error("ERROR: Unable to extract BuildManifest from %s\n", ipsw);
		return -1;
	}

	// devices are listed in order from oldest to newest
	// so we'll need their ECID
	if (client->device->index > DEVICE_IPOD2G) {
		debug("Creating TSS request\n");
		// fetch the device's ECID for the TSS request
		if (get_ecid(client, &client->ecid) < 0) {
			error("ERROR: Unable to find device ECID\n");
			return -1;
		}
		debug("Found ECID %llu\n", client->ecid);
	}

	// choose whether this is an upgrade or a restore (default to upgrade)
	plist_t tss = NULL;
	plist_t build_identity = NULL;
	if (client->flags & FLAG_ERASE) {
		build_identity = get_build_identity(client, buildmanifest, 0);
		if (build_identity == NULL) {
			error("ERROR: Unable to find build any identities\n");
			plist_free(buildmanifest);
			return -1;
		}

	} else {
		// loop through all build identities in the build manifest
		// and list the valid ones
		int i = 0;
		int valid_builds = 0;
		int build_count = get_build_count(buildmanifest);
		for (i = 0; i < build_count; i++) {
			if (client->device->index > DEVICE_IPOD2G) {
				build_identity = get_build_identity(client, buildmanifest, i);
				if (get_shsh_blobs(client, ecid, build_identity, &tss) < 0) {
					// if this fails then no SHSH blobs have been saved
					// for this build identity, so check the next one
					continue;
				}
				info("[%d] %s\n", i, get_build_name(buildmanifest, i));
				valid_builds++;
			}
		}
	}

	// Extract filesystem from IPSW and return its name
	char* filesystem = NULL;
	if (extract_filesystem(client, ipsw, build_identity, &filesystem) < 0) {
		error("ERROR: Unable to extract filesystem from IPSW\n");
		if (tss)
			plist_free(tss);
		plist_free(buildmanifest);
		return -1;
	}

	// if the device is in normal mode, place device into recovery mode
	if (client->mode->index == MODE_NORMAL) {
		info("Entering recovery mode...\n");
		if (normal_enter_recovery(client) < 0) {
			error("ERROR: Unable to place device into recovery mode\n");
			if (tss)
				plist_free(tss);
			plist_free(buildmanifest);
			return -1;
		}
	}

	// if the device is in DFU mode, place device into recovery mode
	if (client->mode->index == MODE_DFU) {
		if (dfu_enter_recovery(client) < 0) {
			error("ERROR: Unable to place device into recovery mode\n");
			plist_free(buildmanifest);
			if (tss)
				plist_free(tss);
			return -1;
		}
	}

	// if the device is in recovery mode, place device into restore mode
	if (client->mode->index == MODE_RECOVERY) {
		if (recovery_enter_restore(uuid, ipsw, tss) < 0) {
			error("ERROR: Unable to place device into restore mode\n");
			plist_free(buildmanifest);
			if (tss)
				plist_free(tss);
			return -1;
		}
	}

	// device is finally in restore mode, let's do this
	if (client->mode->index == MODE_RESTORE) {
		info("Restoring device... \n");
		if (restore_device(client, uuid, ipsw, tss, filesystem) < 0) {
			error("ERROR: Unable to restore device\n");
			return -1;
		}
	}

	// device has finished restoring, lets see if we need to activate
	if (client->mode->index == MODE_NORMAL) {
		info("Checking activation status\n");
		int activation = activate_check_status(uuid);
		if (activation < 0) {
			error("ERROR: Unable to check activation status\n");
			return -1;
		}

		if (activation == 0) {
			info("Activating device... \n");
			if (activate_device(uuid) < 0) {
				error("ERROR: Unable to activate device\n");
				return -1;
			}
		}
	}

	info("Cleaning up...\n");
	if (filesystem)
		unlink(filesystem);

	info("DONE\n");
	return 0;
}

int check_mode(struct idevicerestore_client_t* client) {
	int mode = MODE_UNKNOWN;

	if (recovery_check_mode() == 0) {
		info("Found device in recovery mode\n");
		mode = MODE_RECOVERY;
	}

	else if (dfu_check_mode() == 0) {
		info("Found device in DFU mode\n");
		mode = MODE_DFU;
	}

	else if (normal_check_mode(client->uuid) == 0) {
		info("Found device in normal mode\n");
		mode = MODE_NORMAL;
	}

	else if (restore_check_mode(client->uuid) == 0) {
		info("Found device in restore mode\n");
		mode = MODE_RESTORE;
	}

	client->mode = &idevicerestore_modes[mode];
	return mode;
}

int check_device(struct idevicerestore_client_t* client) {
	int device = DEVICE_UNKNOWN;
	uint32_t bdid = 0;
	uint32_t cpid = 0;

	switch (client->mode->index) {
	case MODE_RESTORE:
		device = restore_check_device(client->uuid);
		if (device < 0) {
			device = DEVICE_UNKNOWN;
		}
		break;

	case MODE_NORMAL:
		device = normal_check_device(client->uuid);
		if (device < 0) {
			device = DEVICE_UNKNOWN;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (get_cpid(client, &cpid) < 0) {
			error("ERROR: Unable to get device CPID\n");
			break;
		}

		switch (cpid) {
		case CPID_IPHONE2G:
			// iPhone1,1 iPhone1,2 and iPod1,1 all share the same ChipID
			//   so we need to check the BoardID
			if (get_bdid(client, &bdid) < 0) {
				error("ERROR: Unable to get device BDID\n");
				break;
			}

			switch (bdid) {
			case BDID_IPHONE2G:
				device = DEVICE_IPHONE2G;
				break;

			case BDID_IPHONE3G:
				device = DEVICE_IPHONE3G;
				break;

			case BDID_IPOD1G:
				device = DEVICE_IPOD1G;
				break;

			default:
				device = DEVICE_UNKNOWN;
				break;
			}
			break;

		case CPID_IPHONE3GS:
			device = DEVICE_IPHONE3GS;
			break;

		case CPID_IPOD2G:
			device = DEVICE_IPOD2G;
			break;

		case CPID_IPOD3G:
			device = DEVICE_IPOD3G;
			break;

		case CPID_IPAD1G:
			device = DEVICE_IPAD1G;
			break;

		default:
			device = DEVICE_UNKNOWN;
			break;
		}
		break;

	default:
		device = DEVICE_UNKNOWN;
		break;

	}

	client->device = &idevicerestore_devices[device];
	return device;
}

int get_bdid(struct idevicerestore_client_t* client, uint32_t* bdid) {
	switch (client->mode->index) {
	case MODE_NORMAL:
		if (normal_get_bdid(client->uuid, &client->device->board_id) < 0) {
			client->device->board_id = -1;
			return -1;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (recovery_get_bdid(client, &client->device->board_id) < 0) {
			client->device->board_id = -1;
			return -1;
		}
		break;

	default:
		error("ERROR: Device is in an invalid state\n");
		return -1;
	}

	return 0;
}

int get_cpid(struct idevicerestore_client_t* client, uint32_t* cpid) {
	switch (client->mode->index) {
	case MODE_NORMAL:
		if (normal_get_cpid(client->uuid, &client->device->chip_id) < 0) {
			client->device->chip_id = -1;
			return -1;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (recovery_get_cpid(client, &client->device->chip_id) < 0) {
			client->device->chip_id = -1;
			return -1;
		}
		break;

	default:
		error("ERROR: Device is in an invalid state\n");
		return -1;
	}

	return 0;
}

int get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	if(client->device->index <= DEVICE_IPOD2G) {
		*ecid = 0;
		return 0;
	}

	switch (client->mode->index) {
	case MODE_NORMAL:
		if (normal_get_ecid(client->uuid, ecid) < 0) {
			*ecid = 0;
			return -1;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (recovery_get_ecid(client, ecid) < 0) {
			*ecid = 0;
			return -1;
		}
		break;

	default:
		error("ERROR: Device is in an invalid state\n");
		return -1;
	}

	return 0;
}

int extract_buildmanifest(struct idevicerestore_client_t* client, const char* ipsw, plist_t* buildmanifest) {
	int size = 0;
	char* data = NULL;
	int device = client->device->index;
	if (device >= DEVICE_IPHONE2G && device <= DEVICE_IPOD2G) {
		// Older devices that don't require personalized firmwares use BuildManifesto.plist
		if (ipsw_extract_to_memory(ipsw, "BuildManifesto.plist", &data, &size) < 0) {
			return -1;
		}

	} else if (device >= DEVICE_IPHONE3GS && device <= DEVICE_IPAD1G) {
		// Whereas newer devices that do require personalized firmwares use BuildManifest.plist
		if (ipsw_extract_to_memory(ipsw, "BuildManifest.plist", &data, &size) < 0) {
			return -1;
		}

	} else {
		return -1;
	}

	plist_from_xml(data, size, buildmanifest);
	return 0;
}

plist_t get_build_identity(struct idevicerestore_client_t* client, plist_t buildmanifest, uint32_t identity) {
	// fetch build identities array from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(buildmanifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find build identities node\n");
		return NULL;
	}

	// check and make sure this identity exists in buildmanifest
	if (identity >= plist_array_get_size(build_identities_array)) {
		return NULL;
	}

	plist_t build_identity = plist_array_get_item(build_identities_array, identity);
	if (!build_identity || plist_get_node_type(build_identity) != PLIST_DICT) {
		error("ERROR: Unable to find build identities node\n");
		return NULL;
	}

	return plist_copy(build_identity);
}

int get_shsh_blobs(struct idevicerestore_client_t* client, uint64_t ecid, plist_t build_identity, plist_t* tss) {
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

	request = tss_create_request(build_identity, ecid);
	if (request == NULL) {
		error("ERROR: Unable to create TSS request\n");
		return -1;
	}

	info("Sending TSS request\n");
	response = tss_send_request(request);
	if (response == NULL) {
		plist_free(request);
		return -1;
	}

	plist_free(request);
	*tss = response;
	return 0;
}

int get_build_count(plist_t buildmanifest) {
	// fetch build identities array from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(buildmanifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find build identities node\n");
		return -1;
	}

	// check and make sure this identity exists in buildmanifest
	return plist_array_get_size(build_identities_array);
}

const char* get_build_name(plist_t build_identity, int identity) {
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find restore manifest\n");
		return NULL;
	}

	plist_t filesystem_info_node = plist_dict_get_item(manifest_node, "Info");
	if (!filesystem_info_node || plist_get_node_type(filesystem_info_node) != PLIST_DICT) {
		error("ERROR: Unable to find filesystem info node\n");
		return NULL;
	}
	return NULL;
}


int extract_filesystem(struct idevicerestore_client_t* client, const char* ipsw, plist_t build_identity, char** filesystem) {
	char* filename = NULL;

	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find manifest node\n");
		return -1;
	}

	plist_t filesystem_node = plist_dict_get_item(manifest_node, "OS");
	if (!filesystem_node || plist_get_node_type(filesystem_node) != PLIST_DICT) {
		error("ERROR: Unable to find filesystem node\n");
		return -1;
	}

	plist_t filesystem_info_node = plist_dict_get_item(filesystem_node, "Info");
	if (!filesystem_info_node || plist_get_node_type(filesystem_info_node) != PLIST_DICT) {
		error("ERROR: Unable to find filesystem info node\n");
		return -1;
	}

	plist_t filesystem_info_path_node = plist_dict_get_item(filesystem_info_node, "Path");
	if (!filesystem_info_path_node || plist_get_node_type(filesystem_info_path_node) != PLIST_STRING) {
		error("ERROR: Unable to find filesystem info path node\n");
		return -1;
	}
	plist_get_string_val(filesystem_info_path_node, &filename);

	info("Extracting filesystem from IPSW\n");
	if (ipsw_extract_to_file(ipsw, filename, filename) < 0) {
		error("ERROR: Unable to extract filesystem\n");
		return -1;
	}

	*filesystem = filename;
	return 0;
}

int get_signed_component(struct idevicerestore_client_t* client, const char* ipsw, plist_t tss, const char* path, char** data, uint32_t* size) {
	img3_file* img3 = NULL;
	uint32_t component_size = 0;
	char* component_data = NULL;
	char* component_blob = NULL;
	char* component_name = NULL;

	component_name = strrchr(path, '/');
	if (component_name != NULL)
		component_name++;
	else
		component_name = (char*) path;

	info("Extracting %s\n", component_name);
	if (ipsw_extract_to_memory(ipsw, path, &component_data, &component_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", component_name, ipsw);
		return -1;
	}

	img3 = img3_parse_file(component_data, component_size);
	if (img3 == NULL) {
		error("ERROR: Unable to parse IMG3: %s\n", component_name);
		free(component_data);
		return -1;
	}
	free(component_data);

	if (tss_get_blob_by_path(tss, path, &component_blob) < 0) {
		error("ERROR: Unable to get SHSH blob for TSS %s entry\n", component_name);
		img3_free(img3);
		return -1;
	}

	if (client->device->index > DEVICE_IPOD2G && (client->flags & FLAG_CUSTOM) == 0) {
		if (img3_replace_signature(img3, component_blob) < 0) {
			error("ERROR: Unable to replace IMG3 signature\n");
			free(component_blob);
			img3_free(img3);
			return -1;
		}
	}
	free(component_blob);

	if (img3_get_data(img3, &component_data, &component_size) < 0) {
		error("ERROR: Unable to reconstruct IMG3\n");
		img3_free(img3);
		return -1;
	}
	img3_free(img3);

	if (client->flags & FLAG_DEBUG) {
		write_file(component_name, component_data, component_size);
	}

	*data = component_data;
	*size = component_size;
	return 0;
}
