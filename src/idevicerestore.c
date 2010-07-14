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
	char* name = strrchr(argv[0], '/');
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
	int tss_enabled = 0;

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
			return 0;

		case 'd':
			client->flags |= FLAG_DEBUG;
			idevicerestore_debug = 1;
			break;

		case 'e':
			client->flags |= FLAG_ERASE;
			break;

		case 'c':
			client->flags |= FLAG_CUSTOM;
			break;

		case 'x':
			client->flags |= FLAG_EXCLUDE;
			break;

		case 'u':
			uuid = optarg;
			break;

		default:
			usage(argc, argv);
			return -1;
		}
	}

	if ((argc-optind) == 1) {
		argc -= optind;
		argv += optind;

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
		error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
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
	if (ipsw_extract_build_manifest(ipsw, &buildmanifest, &tss_enabled) < 0) {
		error("ERROR: Unable to extract BuildManifest from %s\n", ipsw);
		return -1;
	}

	/* print iOS information from the manifest */
	build_manifest_print_information(buildmanifest);

	if (client->flags & FLAG_CUSTOM) {
		/* prevent signing custom firmware */
		tss_enabled = 0;
		info("Custom firmware requested. Disabled TSS request.\n");
	}

	// choose whether this is an upgrade or a restore (default to upgrade)
	client->tss = NULL;
	plist_t build_identity = NULL;
	if (client->flags & FLAG_ERASE) {
		build_identity = build_manifest_get_build_identity(buildmanifest, 0);
		if (build_identity == NULL) {
			error("ERROR: Unable to find any build identities\n");
			plist_free(buildmanifest);
			return -1;
		}
	} else {
		// loop through all build identities in the build manifest
		// and list the valid ones
		int i = 0;
		int valid_builds = 0;
		int build_count = build_manifest_get_identity_count(buildmanifest);
		for (i = 0; i < build_count; i++) {
			build_identity = build_manifest_get_build_identity(buildmanifest, i);
			valid_builds++;
		}
	}

	/* print information about current build identity */
	build_identity_print_information(build_identity);

	/* retrieve shsh blobs if required */
	if (tss_enabled) {
		debug("Getting device's ECID for TSS request\n");
		/* fetch the device's ECID for the TSS request */
		if (get_ecid(client, &client->ecid) < 0) {
			error("ERROR: Unable to find device ECID\n");
			return -1;
		}
		info("Found ECID %llu\n", client->ecid);

		if (get_shsh_blobs(client, client->ecid, build_identity, &client->tss) < 0) {
			error("ERROR: Unable to get SHSH blobs for this device\n");
			return -1;
		}
	}

	/* verify if we have tss records if required */
	if ((tss_enabled) && (client->tss == NULL)) {
		error("ERROR: Unable to proceed without a TSS record.\n");
		plist_free(buildmanifest);
		return -1;
	}

	// Extract filesystem from IPSW and return its name
	char* filesystem = NULL;
	if (ipsw_extract_filesystem(client->ipsw, build_identity, &filesystem) < 0) {
		error("ERROR: Unable to extract filesystem from IPSW\n");
		if (client->tss)
			plist_free(client->tss);
		plist_free(buildmanifest);
		return -1;
	}

	// if the device is in normal mode, place device into recovery mode
	if (client->mode->index == MODE_NORMAL) {
		info("Entering recovery mode...\n");
		if (normal_enter_recovery(client) < 0) {
			error("ERROR: Unable to place device into recovery mode\n");
			if (client->tss)
				plist_free(client->tss);
			plist_free(buildmanifest);
			return -1;
		}
	}

	// if the device is in DFU mode, place device into recovery mode
	if (client->mode->index == MODE_DFU) {
		if (dfu_enter_recovery(client, build_identity) < 0) {
			error("ERROR: Unable to place device into recovery mode\n");
			plist_free(buildmanifest);
			if (client->tss)
				plist_free(client->tss);
			return -1;
		}
	}

	// if the device is in recovery mode, place device into restore mode
	if (client->mode->index == MODE_RECOVERY) {
		if (recovery_enter_restore(client, build_identity) < 0) {
			error("ERROR: Unable to place device into restore mode\n");
			plist_free(buildmanifest);
			if (client->tss)
				plist_free(client->tss);
			return -1;
		}
	}

	// device is finally in restore mode, let's do this
	if (client->mode->index == MODE_RESTORE) {
		info("Restoring device... \n");
		if (restore_device(client, build_identity, filesystem) < 0) {
			error("ERROR: Unable to restore device\n");
			return -1;
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
		mode = MODE_RECOVERY;
	}

	else if (dfu_check_mode() == 0) {
		mode = MODE_DFU;
	}

	else if (normal_check_mode(client->uuid) == 0) {
		mode = MODE_NORMAL;
	}

	else if (restore_check_mode(client->uuid) == 0) {
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
		if (normal_get_bdid(client->uuid, bdid) < 0) {
			*bdid = 0;
			return -1;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (recovery_get_bdid(client, bdid) < 0) {
			*bdid = 0;
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
		if (normal_get_cpid(client->uuid, cpid) < 0) {
			client->device->chip_id = -1;
			return -1;
		}
		break;

	case MODE_DFU:
	case MODE_RECOVERY:
		if (recovery_get_cpid(client, cpid) < 0) {
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

plist_t build_manifest_get_build_identity(plist_t build_manifest, uint32_t identity) {
	// fetch build identities array from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
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

	info("Sending TSS request... ");
	response = tss_send_request(request);
	if (response == NULL) {
		info("ERROR: Unable to send TSS request\n");
		plist_free(request);
		return -1;
	}

	info("received SHSH blobs\n");

	plist_free(request);
	*tss = response;
	return 0;
}

int build_manifest_get_identity_count(plist_t build_manifest) {
	// fetch build identities array from BuildManifest
	plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find build identities node\n");
		return -1;
	}

	// check and make sure this identity exists in buildmanifest
	return plist_array_get_size(build_identities_array);
}

int ipsw_extract_filesystem(const char* ipsw, plist_t build_identity, char** filesystem) {
	char* filename = NULL;

	if (build_identity_get_component_path(build_identity, "OS", &filename) < 0) {
		error("ERROR: Unable get path for filesystem component\n");
		return -1;
	}

	info("Extracting filesystem from IPSW\n");
	if (ipsw_extract_to_file(ipsw, filename, filename) < 0) {
		error("ERROR: Unable to extract filesystem\n");
		return -1;
	}

	*filesystem = filename;
	return 0;
}

int ipsw_get_component_by_path(const char* ipsw, plist_t tss, const char* path, char** data, uint32_t* size) {
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

	if (tss) {
		img3 = img3_parse_file(component_data, component_size);
		if (img3 == NULL) {
			error("ERROR: Unable to parse IMG3: %s\n", component_name);
			free(component_data);
			return -1;
		}
		free(component_data);

		/* sign the blob if required */
		if (tss_get_blob_by_path(tss, path, &component_blob) < 0) {
			error("ERROR: Unable to get SHSH blob for TSS %s entry\n", component_name);
			img3_free(img3);
			return -1;
		}

		info("Signing %s\n", component_name);
		if (img3_replace_signature(img3, component_blob) < 0) {
			error("ERROR: Unable to replace IMG3 signature\n");
			free(component_blob);
			img3_free(img3);
			return -1;
		}

		if (component_blob)
			free(component_blob);

		if (img3_get_data(img3, &component_data, &component_size) < 0) {
			error("ERROR: Unable to reconstruct IMG3\n");
			img3_free(img3);
			return -1;
		}
		img3_free(img3);
	}

	if (idevicerestore_debug) {
		write_file(component_name, component_data, component_size);
	}

	*data = component_data;
	*size = component_size;
	return 0;
}

void build_manifest_print_information(plist_t build_manifest) {
	char* value = NULL;
	plist_t node = NULL;

	node = plist_dict_get_item(build_manifest, "ProductVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ProductVersion node\n");
		return;
	}
	plist_get_string_val(node, &value);

	info("Product Version: %s\n", value);
	free(value);

	node = plist_dict_get_item(build_manifest, "ProductBuildVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ProductBuildVersion node\n");
		return;
	}
	plist_get_string_val(node, &value);

	info("Product Build: %s\n", value);
	free(value);

	node = NULL;
}

void build_identity_print_information(plist_t build_identity) {
	char* value = NULL;
	plist_t info_node = NULL;
	plist_t node = NULL;

	info_node = plist_dict_get_item(build_identity, "Info");
	if (!info_node || plist_get_node_type(info_node) != PLIST_DICT) {
		error("ERROR: Unable to find Info node\n");
		return;
	}

	node = plist_dict_get_item(info_node, "Variant");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find Variant node\n");
		return;
	}
	plist_get_string_val(node, &value);

	info("Variant: %s\n", value);
	free(value);

	node = plist_dict_get_item(info_node, "RestoreBehavior");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find RestoreBehavior node\n");
		return;
	}
	plist_get_string_val(node, &value);

	if (!strcmp(value, "Erase"))
		info("This restore will erase your device data.\n");

	if (!strcmp(value, "Update"))
		info("This restore will update your device without loosing data.\n");

	free(value);

	info_node = NULL;
	node = NULL;
}

int build_identity_get_component_path(plist_t build_identity, const char* component, char** path) {
	char* filename = NULL;

	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find manifest node\n");
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_node = plist_dict_get_item(manifest_node, component);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		error("ERROR: Unable to find component node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_info_node = plist_dict_get_item(component_node, "Info");
	if (!component_info_node || plist_get_node_type(component_info_node) != PLIST_DICT) {
		error("ERROR: Unable to find component info node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}

	plist_t component_info_path_node = plist_dict_get_item(component_info_node, "Path");
	if (!component_info_path_node || plist_get_node_type(component_info_path_node) != PLIST_STRING) {
		error("ERROR: Unable to find component info path node for %s\n", component);
		if (filename)
			free(filename);
		return -1;
	}
	plist_get_string_val(component_info_path_node, &filename);

	*path = filename;
	return 0;
}

