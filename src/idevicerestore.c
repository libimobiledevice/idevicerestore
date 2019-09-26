/*
 * idevicerestore.c
 * Restore device firmware and filesystem
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010-2015 Martin Szulecki. All Rights Reserved.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <plist/plist.h>
#include <zlib.h>
#include <libgen.h>
#include <signal.h>

#include <curl/curl.h>

#include "dfu.h"
#include "tss.h"
#include "img3.h"
#include "img4.h"
#include "ipsw.h"
#include "common.h"
#include "normal.h"
#include "restore.h"
#include "download.h"
#include "recovery.h"
#include "idevicerestore.h"

#include "limera1n.h"

#include "locking.h"

#define VERSION_XML "version.xml"

#ifndef IDEVICERESTORE_NOMAIN
static struct option longopts[] = {
	{ "ecid",    required_argument, NULL, 'i' },
	{ "udid",    required_argument, NULL, 'u' },
	{ "debug",   no_argument,       NULL, 'd' },
	{ "help",    no_argument,       NULL, 'h' },
	{ "erase",   no_argument,       NULL, 'e' },
	{ "custom",  no_argument,       NULL, 'c' },
	{ "latest",  no_argument,       NULL, 'l' },
	{ "cydia",   no_argument,       NULL, 's' },
	{ "exclude", no_argument,       NULL, 'x' },
	{ "shsh",    no_argument,       NULL, 't' },
	{ "keep-pers", no_argument,     NULL, 'k' },
	{ "pwn",     no_argument,       NULL, 'p' },
	{ "no-action", no_argument,     NULL, 'n' },
	{ "cache-path", required_argument, NULL, 'C' },
	{ "no-input", no_argument,      NULL, 'y' },
	{ NULL, 0, NULL, 0 }
};

static void usage(int argc, char* argv[], int err)
{
	char* name = strrchr(argv[0], '/');
	fprintf((err) ? stderr : stdout,
	"Usage: %s [OPTIONS] PATH\n" \
	"Restore IPSW firmware at PATH to an iOS device.\n" \
	"\n" \
	"PATH can be a compressed .ipsw file or a directory containing all files\n" \
	"extracted from an IPSW.\n" \
	"\n" \
	"Options:\n" \
	" -i, --ecid ECID  Target specific device by its ECID\n" \
	"                  e.g. 0xaabb123456 (hex) or 1234567890 (decimal)\n" \
	" -u, --udid UDID  Target specific device by its device UDID\n" \
	"                  NOTE: only works with devices in normal mode.\n" \
	" -l, --latest     Use latest available firmware (with download on demand).\n" \
	"                  Before performing any action it will interactively ask to\n" \
	"                  select one of the currently signed firmware versions,\n" \
	"                  unless -y has been given too.\n" \
	"                  The PATH argument is ignored when using this option.\n" \
	"                  DO NOT USE if you need to preserve the baseband (unlock)!\n" \
	"                  USE WITH CARE if you want to keep a jailbreakable firmware!\n" \
	" -e, --erase      Perform a full restore, erasing all data (defaults to update)\n" \
	"                  DO NOT USE if you want to preserve user data on the device!\n" \
	" -y, --no-input   Non-interactive mode, do not ask for any input.\n" \
	"                  WARNING: This will disable certain checks/prompts that are\n" \
	"                  supposed to prevent DATA LOSS. Use with caution.\n" \
	" -n, --no-action  Do not perform any restore action. If combined with -l option\n" \
	"                  the on-demand ipsw download is performed before exiting.\n" \
	" -h, --help       Prints this usage information\n" \
	" -C, --cache-path DIR  Use specified directory for caching extracted or other\n" \
	"                  reused files.\n" \
	" -d, --debug      Enable communication debugging\n" \
	"\n" \
	"Advanced/experimental options:\n"
	" -c, --custom     Restore with a custom firmware\n" \
	" -s, --cydia      Use Cydia's signature service instead of Apple's\n" \
	" -x, --exclude    Exclude nor/baseband upgrade\n" \
	" -t, --shsh       Fetch TSS record and save to .shsh file, then exit\n" \
	" -k, --keep-pers  Write personalized components to files for debugging\n" \
	" -p, --pwn        Put device in pwned DFU mode and exit (limera1n devices only)\n" \
	"\n" \
	"Homepage: <" PACKAGE_URL ">\n",
	(name ? name + 1 : argv[0]));
}
#endif

static int idevicerestore_keep_pers = 0;

static int load_version_data(struct idevicerestore_client_t* client)
{
	if (!client) {
		return -1;
	}

	struct stat fst;
	int cached = 0;

	char version_xml[1024];

	if (client->cache_dir) {
		if (stat(client->cache_dir, &fst) < 0) {
			mkdir_with_parents(client->cache_dir, 0755);
		}
		strcpy(version_xml, client->cache_dir);
		strcat(version_xml, "/");
		strcat(version_xml, VERSION_XML);
	} else {
		strcpy(version_xml, VERSION_XML);
	}

	if ((stat(version_xml, &fst) < 0) || ((time(NULL)-86400) > fst.st_mtime)) {
		char version_xml_tmp[1024];
		strcpy(version_xml_tmp, version_xml);
		strcat(version_xml_tmp, ".tmp");

		if (download_to_file("http://itunes.apple.com/check/version",  version_xml_tmp, 0) == 0) {
			remove(version_xml);
			if (rename(version_xml_tmp, version_xml) < 0) {
				error("ERROR: Could not update '%s'\n", version_xml);
			} else {
				info("NOTE: Updated version data.\n");
			}
		}
	} else {
		cached = 1;
	}

	char *verbuf = NULL;
	size_t verlen = 0;
	read_file(version_xml, (void**)&verbuf, &verlen);

	if (!verbuf) {
		error("ERROR: Could not load '%s'\n", version_xml);
		return -1;
	}

	client->version_data = NULL;
	plist_from_xml(verbuf, verlen, &client->version_data);
	free(verbuf);

	if (!client->version_data) {
		remove(version_xml);
		error("ERROR: Cannot parse plist data from '%s'.\n", version_xml);
		return -1;
	}

	if (cached) {
		info("NOTE: using cached version data\n");
	}

	return 0;
}

static int32_t get_version_num(const char *s_ver)
{
        int vers[3] = {0, 0, 0};
        if (sscanf(s_ver, "%d.%d.%d", &vers[0], &vers[1], &vers[2]) >= 2) {
                return ((vers[0] & 0xFF) << 16) | ((vers[1] & 0xFF) << 8) | (vers[2] & 0xFF);
        }
        return 0x00FFFFFF;
}

static int compare_versions(const char *s_ver1, const char *s_ver2)
{
	return (get_version_num(s_ver1) & 0xFFFF00) - (get_version_num(s_ver2) & 0xFFFF00);
}

static void idevice_event_cb(const idevice_event_t *event, void *userdata)
{
	struct idevicerestore_client_t *client = (struct idevicerestore_client_t*)userdata;
	if (event->event == IDEVICE_DEVICE_ADD) {
		if (normal_check_mode(client) == 0) {
			client->mode = &idevicerestore_modes[MODE_NORMAL];
			debug("%s: device %016llx (udid: %s) connected in normal mode\n", __func__, client->ecid, client->udid);
		} else if (client->ecid && restore_check_mode(client) == 0) {
			client->mode = &idevicerestore_modes[MODE_RESTORE];
			debug("%s: device %016llx (udid: %s) connected in restore mode\n", __func__, client->ecid, client->udid);
		}
	} else if (event->event == IDEVICE_DEVICE_REMOVE) {
		if (client->udid && !strcmp(event->udid, client->udid)) {
			client->mode = &idevicerestore_modes[MODE_UNKNOWN];
			debug("%s: device %016llx (udid: %s) disconnected\n", __func__, client->ecid, client->udid);
		}
	}
}

static void irecv_event_cb(const irecv_device_event_t* event, void *userdata)
{
	struct idevicerestore_client_t *client = (struct idevicerestore_client_t*)userdata;
	if (event->type == IRECV_DEVICE_ADD) {
		if (client->ecid && event->device_info->ecid == client->ecid) {
			switch (event->mode) {
				case IRECV_K_WTF_MODE:
					client->mode = &idevicerestore_modes[MODE_WTF];
					break;
				case IRECV_K_DFU_MODE:
					client->mode = &idevicerestore_modes[MODE_DFU];
					break;
				case IRECV_K_RECOVERY_MODE_1:
				case IRECV_K_RECOVERY_MODE_2:
				case IRECV_K_RECOVERY_MODE_3:
				case IRECV_K_RECOVERY_MODE_4:
					client->mode = &idevicerestore_modes[MODE_RECOVERY];
					break;
				default:
					client->mode = &idevicerestore_modes[MODE_UNKNOWN];
			}
			debug("%s: device %016llx (udid: %s) connected in %s mode\n", __func__, client->ecid, client->udid, client->mode->string);
		}
	} else if (event->type == IRECV_DEVICE_REMOVE) {
		if (client->ecid && event->device_info->ecid == client->ecid) {
			client->mode = &idevicerestore_modes[MODE_UNKNOWN];
			debug("%s: device %016llx (udid: %s) disconnected\n", __func__, client->ecid, client->udid);
		}
	}
}

int idevicerestore_start(struct idevicerestore_client_t* client)
{
	int tss_enabled = 0;
	int result = 0;

	if (!client) {
		return -1;
	}

	if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
		error("ERROR: FLAG_LATEST cannot be used with FLAG_CUSTOM.\n");
		return -1;
	}

	if (!client->ipsw && !(client->flags & FLAG_PWN) && !(client->flags & FLAG_LATEST)) {
		error("ERROR: no ipsw file given\n");
		return -1;
	}

	if (client->flags & FLAG_DEBUG) {
		idevice_set_debug_level(1);
		irecv_set_debug_level(1);
		idevicerestore_debug = 1;
	}

	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.0);

	irecv_device_event_subscribe(&client->irecv_e_ctx, irecv_event_cb, client);

	idevice_event_subscribe(idevice_event_cb, client);
	client->idevice_e_ctx = idevice_event_cb;

	// check which mode the device is currently in so we know where to start
	WAIT_FOR(client->mode != &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT), 10);
	if (client->mode == &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT)) {
		error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
		return -1;
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.1);
	info("Found device in %s mode\n", client->mode->string);

	if (client->mode->index == MODE_WTF) {
		unsigned int cpid = 0;

		if (dfu_client_new(client) != 0) {
			error("ERROR: Could not open device in WTF mode\n");
			return -1;
		}
		if ((dfu_get_cpid(client, &cpid) < 0) || (cpid == 0)) { 
			error("ERROR: Could not get CPID for WTF mode device\n");
			dfu_client_free(client);
			return -1;
		}

		char wtfname[256];
		sprintf(wtfname, "Firmware/dfu/WTF.s5l%04xxall.RELEASE.dfu", cpid);
		unsigned char* wtftmp = NULL;
		unsigned int wtfsize = 0;

		// Prefer to get WTF file from the restore IPSW
		ipsw_extract_to_memory(client->ipsw, wtfname, &wtftmp, &wtfsize);
		if (!wtftmp) {
			// update version data (from cache, or apple if too old)
			load_version_data(client);

			// Download WTF IPSW
			char* s_wtfurl = NULL;
			plist_t wtfurl = plist_access_path(client->version_data, 7, "MobileDeviceSoftwareVersionsByVersion", "5", "RecoverySoftwareVersions", "WTF", "304218112", "5", "FirmwareURL");
			if (wtfurl && (plist_get_node_type(wtfurl) == PLIST_STRING)) {
				plist_get_string_val(wtfurl, &s_wtfurl);
			}
			if (!s_wtfurl) {
				info("Using hardcoded x12220000_5_Recovery.ipsw URL\n");
				s_wtfurl = strdup("http://appldnld.apple.com.edgesuite.net/content.info.apple.com/iPhone/061-6618.20090617.Xse7Y/x12220000_5_Recovery.ipsw");
			}

			// make a local file name
			char* fnpart = strrchr(s_wtfurl, '/');
			if (!fnpart) {
				fnpart = (char*)"x12220000_5_Recovery.ipsw";
			} else {
				fnpart++;
			}
			struct stat fst;
			char wtfipsw[1024];
			if (client->cache_dir) {
				if (stat(client->cache_dir, &fst) < 0) {
					mkdir_with_parents(client->cache_dir, 0755);
				}
				strcpy(wtfipsw, client->cache_dir);
				strcat(wtfipsw, "/");
				strcat(wtfipsw, fnpart);
			} else {
				strcpy(wtfipsw, fnpart);
			}
			if (stat(wtfipsw, &fst) != 0) {
				download_to_file(s_wtfurl, wtfipsw, 0);
			}

			ipsw_extract_to_memory(wtfipsw, wtfname, &wtftmp, &wtfsize);
			if (!wtftmp) {
				error("ERROR: Could not extract WTF\n");
			}
		}

		if (wtftmp) {
			if (dfu_send_buffer(client, wtftmp, wtfsize) != 0) {
				error("ERROR: Could not send WTF...\n");
			}
		}
		dfu_client_free(client);

		free(wtftmp);

		WAIT_FOR(client->mode == &idevicerestore_modes[MODE_DFU] || (client->flags & FLAG_QUIT), 10); /* TODO: verify if it actually goes from 0x1222 -> 0x1227 */
	}

	// discover the device type
	client->device = get_irecv_device(client);
	if (client->device == NULL) {
		error("ERROR: Unable to discover device type\n");
		return -1;
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.2);
	info("Identified device as %s, %s\n", client->device->hardware_model, client->device->product_type);

	if ((client->flags & FLAG_PWN) && (client->mode->index != MODE_DFU)) {
		error("ERROR: you need to put your device into DFU mode to pwn it.\n");
		return -1;
	}

	if (client->flags & FLAG_PWN) {
		recovery_client_free(client);

		if (client->mode->index != MODE_DFU) {
			error("ERROR: Device needs to be in DFU mode for this option.\n");
			return -1;
		}

		info("connecting to DFU\n");
		if (dfu_client_new(client) < 0) {
			return -1;
		}
		info("exploiting with limera1n...\n");
		// TODO: check for non-limera1n device and fail
		if (limera1n_exploit(client->device, &client->dfu->client) != 0) {
			error("ERROR: limera1n exploit failed\n");
			dfu_client_free(client);
			return -1;
		}
		dfu_client_free(client);
		info("Device should be in pwned DFU state now.\n");

		return 0;
	}

	if (client->flags & FLAG_LATEST) {
		char *fwurl = NULL;
		unsigned char fwsha1[20];
		unsigned char *p_fwsha1 = NULL;
		plist_t signed_fws = NULL;
		int res = ipsw_get_signed_firmwares(client->device->product_type, &signed_fws);
		if (res < 0) {
			error("ERROR: Could not fetch list of signed firmwares.\n");
			return res;
		}
		uint32_t count = plist_array_get_size(signed_fws);
		if (count == 0) {
			plist_free(signed_fws);
			error("ERROR: No firmwares are currently being signed for %s (REALLY?!)\n", client->device->product_type);
			return -1;
		}
		plist_t selected_fw = NULL;
		if (client->flags & FLAG_INTERACTIVE) {
			uint32_t i = 0;
			info("The following firmwares are currently being signed for %s:\n", client->device->product_type);
			for (i = 0; i < count; i++) {
				plist_t fw = plist_array_get_item(signed_fws, i);
				plist_t p_version = plist_dict_get_item(fw, "version");
				plist_t p_build = plist_dict_get_item(fw, "buildid");
				char *s_version = NULL;
				char *s_build = NULL;
				plist_get_string_val(p_version, &s_version);
				plist_get_string_val(p_build, &s_build);
				info("  [%d] %s (build %s)\n", i+1, s_version, s_build);
				free(s_version);
				free(s_build);
			}
			while (1) {
				char input[64];
				printf("Select the firmware you want to restore: ");
				fflush(stdout);
				fflush(stdin);
				get_user_input(input, 63, 0);
				if (*input == '\0') {
					plist_free(signed_fws);
					return -1;
				}
				if (client->flags & FLAG_QUIT) {
					return -1;
				}
				unsigned long selected = strtoul(input, NULL, 10);
				if (selected == 0 || selected > count) {
					printf("Invalid input value. Must be in range: 1..%d\n", count);
					continue;
				}
				selected_fw = plist_array_get_item(signed_fws, (uint32_t)selected-1);
				break;
			}
		} else {
			info("NOTE: Running non-interactively, automatically selecting latest available version\n");
			selected_fw = plist_array_get_item(signed_fws, 0);
		}
		if (!selected_fw) {
			error("ERROR: failed to select latest firmware?!\n");
			plist_free(signed_fws);
			return -1;
		} else {
			plist_t p_version = plist_dict_get_item(selected_fw, "version");
			plist_t p_build = plist_dict_get_item(selected_fw, "buildid");
			char *s_version = NULL;
			char *s_build = NULL;
			plist_get_string_val(p_version, &s_version);
			plist_get_string_val(p_build, &s_build);
			info("Selected firmware %s (build %s)\n", s_version, s_build);
			free(s_version);
			free(s_build);
			plist_t p_url = plist_dict_get_item(selected_fw, "url");
			plist_t p_sha1 = plist_dict_get_item(selected_fw, "sha1sum");
			char *s_sha1 = NULL;
			plist_get_string_val(p_url, &fwurl);
			plist_get_string_val(p_sha1, &s_sha1);
			if (strlen(s_sha1) == 40) {
				int i;
				int v;
				for (i = 0; i < 40; i+=2) {
					v = 0;
					sscanf(s_sha1+i, "%02x", &v);
					fwsha1[i/2] = (unsigned char)v;
				}
				p_fwsha1 = &fwsha1[0];
			} else {
				error("ERROR: unexpected size of sha1sum\n");
			}
		}
		plist_free(signed_fws);

		if (!fwurl || !p_fwsha1) {
			error("ERROR: Missing firmware URL or SHA1\n");
			return -1;
		}

		char* ipsw = NULL;
		res = ipsw_download_fw(fwurl, p_fwsha1, client->cache_dir, &ipsw);
		if (res != 0) {
			if (ipsw) {
				free(ipsw);
			}
			return res;
		} else {
			client->ipsw = ipsw;
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.6);

	if (client->flags & FLAG_NOACTION) {
		return 0;
	}

	if (client->mode->index == MODE_RESTORE) {
		if (restore_reboot(client) < 0) {
			error("ERROR: Unable to exit restore mode\n");
			return -2;
		}

		// we need to refresh the current mode again
		WAIT_FOR(client->mode != &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT), 60);
		if (client->mode == &idevicerestore_modes[MODE_UNKNOWN] || (client->flags & FLAG_QUIT)) {
			error("ERROR: Unable to discover device mode. Please make sure a device is attached.\n");
			return -1;
		}
		info("Found device in %s mode\n", client->mode->string);
	}

	// verify if ipsw file exists
	if (access(client->ipsw, F_OK) < 0) {
		error("ERROR: Firmware file %s does not exist.\n", client->ipsw);
		return -1;
	}

	// extract buildmanifest
	plist_t buildmanifest = NULL;
	if (client->flags & FLAG_CUSTOM) {
		info("Extracting Restore.plist from IPSW\n");
		if (ipsw_extract_restore_plist(client->ipsw, &buildmanifest) < 0) {
			error("ERROR: Unable to extract Restore.plist from %s. Firmware file might be corrupt.\n", client->ipsw);
			return -1;
		}
	} else {
		info("Extracting BuildManifest from IPSW\n");
		if (ipsw_extract_build_manifest(client->ipsw, &buildmanifest, &tss_enabled) < 0) {
			error("ERROR: Unable to extract BuildManifest from %s. Firmware file might be corrupt.\n", client->ipsw);
			return -1;
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_DETECT, 0.8);

	/* check if device type is supported by the given build manifest */
	if (build_manifest_check_compatibility(buildmanifest, client->device->product_type) < 0) {
		error("ERROR: Could not make sure this firmware is suitable for the current device. Refusing to continue.\n");
		return -1;
	}

	/* print iOS information from the manifest */
	build_manifest_get_version_information(buildmanifest, client);

	info("Product Version: %s\n", client->version);
	info("Product Build: %s Major: %d\n", client->build, client->build_major);

	client->image4supported = is_image4_supported(client);
	info("Device supports Image4: %s\n", (client->image4supported) ? "true" : "false");

	if (client->flags & FLAG_CUSTOM) {
		/* prevent signing custom firmware */
		tss_enabled = 0;
		info("Custom firmware requested. Disabled TSS request.\n");
	}

	// choose whether this is an upgrade or a restore (default to upgrade)
	client->tss = NULL;
	plist_t build_identity = NULL;
	if (client->flags & FLAG_CUSTOM) {
		build_identity = plist_new_dict();
		{
			plist_t node;
			plist_t comp;
			plist_t inf;
			plist_t manifest;

			char tmpstr[256];
			char p_all_flash[128];
			char lcmodel[8];
			strcpy(lcmodel, client->device->hardware_model);
			int x = 0;
			while (lcmodel[x]) {
				lcmodel[x] = tolower(lcmodel[x]);
				x++;
			}

			sprintf(p_all_flash, "Firmware/all_flash/all_flash.%s.%s", lcmodel, "production");
			strcpy(tmpstr, p_all_flash);
			strcat(tmpstr, "/manifest");

			// get all_flash file manifest
			char *files[16];
			char *fmanifest = NULL;
			uint32_t msize = 0;
			if (ipsw_extract_to_memory(client->ipsw, tmpstr, (unsigned char**)&fmanifest, &msize) < 0) {
				error("ERROR: could not extract %s from IPSW\n", tmpstr);
				return -1;
			}

			char *tok = strtok(fmanifest, "\r\n");
			int fc = 0;
			while (tok) {
				files[fc++] = strdup(tok);
				if (fc >= 16) {
					break;
				}
				tok = strtok(NULL, "\r\n");
			}
			free(fmanifest);

			manifest = plist_new_dict();

			for (x = 0; x < fc; x++) {
				inf = plist_new_dict();
				strcpy(tmpstr, p_all_flash);
				strcat(tmpstr, "/");
				strcat(tmpstr, files[x]);
				plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
				comp = plist_new_dict();
				plist_dict_set_item(comp, "Info", inf);
				const char* compname = get_component_name(files[x]);
				if (compname) {
					plist_dict_set_item(manifest, compname, comp);
					if (!strncmp(files[x], "DeviceTree", 10)) {
						plist_dict_set_item(manifest, "RestoreDeviceTree", plist_copy(comp));
					}
				} else {
					error("WARNING: unhandled component %s\n", files[x]);
					plist_free(comp);
				}
				free(files[x]);
				files[x] = NULL;
			}

			// add iBSS
			sprintf(tmpstr, "Firmware/dfu/iBSS.%s.%s.dfu", lcmodel, "RELEASE");
			inf = plist_new_dict();
			plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
			comp = plist_new_dict();
			plist_dict_set_item(comp, "Info", inf);
			plist_dict_set_item(manifest, "iBSS", comp);

			// add iBEC
			sprintf(tmpstr, "Firmware/dfu/iBEC.%s.%s.dfu", lcmodel, "RELEASE");
			inf = plist_new_dict();
			plist_dict_set_item(inf, "Path", plist_new_string(tmpstr));
			comp = plist_new_dict();
			plist_dict_set_item(comp, "Info", inf);
			plist_dict_set_item(manifest, "iBEC", comp);

			// add kernel cache
			plist_t kdict = NULL;

			node = plist_dict_get_item(buildmanifest, "KernelCachesByTarget");
			if (node && (plist_get_node_type(node) == PLIST_DICT)) {
				char tt[4];
				strncpy(tt, lcmodel, 3);
				tt[3] = 0;
				kdict = plist_dict_get_item(node, tt);
			} else {
				// Populated in older iOS IPSWs
				kdict = plist_dict_get_item(buildmanifest, "RestoreKernelCaches");
			}
			if (kdict && (plist_get_node_type(kdict) == PLIST_DICT)) {
				plist_t kc = plist_dict_get_item(kdict, "Release");
				if (kc && (plist_get_node_type(kc) == PLIST_STRING)) {
					inf = plist_new_dict();
					plist_dict_set_item(inf, "Path", plist_copy(kc));
					comp = plist_new_dict();
					plist_dict_set_item(comp, "Info", inf);
					plist_dict_set_item(manifest, "KernelCache", comp);
					plist_dict_set_item(manifest, "RestoreKernelCache", plist_copy(comp));
				}
			}

			// add ramdisk
			node = plist_dict_get_item(buildmanifest, "RestoreRamDisks");
			if (node && (plist_get_node_type(node) == PLIST_DICT)) {
				plist_t rd = plist_dict_get_item(node, (client->flags & FLAG_ERASE) ? "User" : "Update");
				// if no "Update" ram disk entry is found try "User" ram disk instead
				if (!rd && !(client->flags & FLAG_ERASE)) {
					rd = plist_dict_get_item(node, "User");
					// also, set the ERASE flag since we actually change the restore variant
					client->flags |= FLAG_ERASE;
				}
				if (rd && (plist_get_node_type(rd) == PLIST_STRING)) {
					inf = plist_new_dict();
					plist_dict_set_item(inf, "Path", plist_copy(rd));
					comp = plist_new_dict();
					plist_dict_set_item(comp, "Info", inf);
					plist_dict_set_item(manifest, "RestoreRamDisk", comp);
				}
			}

			// add OS filesystem
			node = plist_dict_get_item(buildmanifest, "SystemRestoreImages");
			if (!node) {
				error("ERROR: missing SystemRestoreImages in Restore.plist\n");
			}
			plist_t os = plist_dict_get_item(node, "User");
			if (!os) {
				error("ERROR: missing filesystem in Restore.plist\n");
			} else {
				inf = plist_new_dict();
				plist_dict_set_item(inf, "Path", plist_copy(os));
				comp = plist_new_dict();
				plist_dict_set_item(comp, "Info", inf);
				plist_dict_set_item(manifest, "OS", comp);
			}

			// add info
			inf = plist_new_dict();
			plist_dict_set_item(inf, "RestoreBehavior", plist_new_string((client->flags & FLAG_ERASE) ? "Erase" : "Update"));
			plist_dict_set_item(inf, "Variant", plist_new_string((client->flags & FLAG_ERASE) ? "Customer Erase Install (IPSW)" : "Customer Upgrade Install (IPSW)"));
			plist_dict_set_item(build_identity, "Info", inf);

			// finally add manifest
			plist_dict_set_item(build_identity, "Manifest", manifest);
		}
	} else if (client->flags & FLAG_ERASE) {
		build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Erase");
		if (build_identity == NULL) {
			error("ERROR: Unable to find any build identities\n");
			plist_free(buildmanifest);
			return -1;
		}
	} else {
		build_identity = build_manifest_get_build_identity_for_model_with_restore_behavior(buildmanifest, client->device->hardware_model, "Update");
		if (!build_identity) {
			build_identity = build_manifest_get_build_identity_for_model(buildmanifest, client->device->hardware_model);
		}
	}

	/* print information about current build identity */
	build_identity_print_information(build_identity);

	if (client->mode->index == MODE_NORMAL && !(client->flags & FLAG_ERASE) && !(client->flags & FLAG_SHSHONLY)) {
		plist_t pver = normal_get_lockdown_value(client, NULL, "ProductVersion");
		char *device_version = NULL;
		if (pver) {
			plist_get_string_val(pver, &device_version);
			plist_free(pver);
		}
		if (device_version && (compare_versions(device_version, client->version) > 0)) {
			if (client->flags & FLAG_INTERACTIVE) {
				char input[64];
				char spaces[16];
				int num_spaces = 13 - strlen(client->version) - strlen(device_version);
				memset(spaces, ' ', num_spaces);
				spaces[num_spaces] = '\0';
				printf("################################ [ WARNING ] #################################\n"
				       "# You are trying to DOWNGRADE a %s device with an IPSW for %s while%s #\n"
				       "# trying to preserve the user data (Upgrade restore). This *might* work, but #\n"
				       "# there is a VERY HIGH chance it might FAIL BADLY with COMPLETE DATA LOSS.   #\n"
				       "# Hit CTRL+C now if you want to abort the restore.                           #\n"
				       "# If you want to take the risk (and have a backup of your important data!)   #\n"
				       "# type YES and press ENTER to continue. You have been warned.                #\n"
				       "##############################################################################\n",
				       device_version, client->version, spaces);
				while (1) {
					printf("> ");
					fflush(stdout);
					fflush(stdin);
					input[0] = '\0';
					get_user_input(input, 63, 0);
					if (client->flags & FLAG_QUIT) {
						return -1;
					}
					if (*input != '\0' && !strcmp(input, "YES")) {
						break;
					} else {
						printf("Invalid input. Please type YES or hit CTRL+C to abort.\n");
						continue;
					}
				}
			}
		}
		free(device_version);
	}

	if (client->flags & FLAG_ERASE && client->flags & FLAG_INTERACTIVE) {
		char input[64];
		printf("################################ [ WARNING ] #################################\n"
		       "# You are about to perform an *ERASE* restore. ALL DATA on the target device #\n"
		       "# will be IRREVERSIBLY DESTROYED. If you want to update your device without  #\n"
		       "# erasing the user data, hit CTRL+C now and restart without -e or --erase    #\n"
		       "# command line switch.                                                       #\n"
		       "# If you want to continue with the ERASE, please type YES and press ENTER.   #\n"
		       "##############################################################################\n");
		while (1) {
			printf("> ");
			fflush(stdout);
			fflush(stdin);
			input[0] = '\0';
			get_user_input(input, 63, 0);
			if (client->flags & FLAG_QUIT) {
				return -1;
			}
			if (*input != '\0' && !strcmp(input, "YES")) {
				break;
			} else {
				printf("Invalid input. Please type YES or hit CTRL+C to abort.\n");
				continue;
			}
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.0);

	/* check if all components we need are actually there */
	info("Checking IPSW for required components...\n");
	if (build_identity_check_components_in_ipsw(build_identity, client->ipsw) < 0) {
		error("ERROR: Could not find all required components in IPSW %s\n", client->ipsw);
		return -1;
	}
	info("All required components found in IPSW\n");

	// Get filesystem name from build identity
	char* fsname = NULL;
	if (build_identity_get_component_path(build_identity, "OS", &fsname) < 0) {
		error("ERROR: Unable get path for filesystem component\n");
		return -1;
	}

	// check if we already have an extracted filesystem
	int delete_fs = 0;
	char* filesystem = NULL;
	struct stat st;
	memset(&st, '\0', sizeof(struct stat));
	char tmpf[1024];
	if (client->cache_dir) {
		if (stat(client->cache_dir, &st) < 0) {
			mkdir_with_parents(client->cache_dir, 0755);
		}
		strcpy(tmpf, client->cache_dir);
		strcat(tmpf, "/");
		char *ipswtmp = strdup(client->ipsw);
		strcat(tmpf, basename(ipswtmp));
		free(ipswtmp);
	} else {
		strcpy(tmpf, client->ipsw);
	}

	if (!ipsw_is_directory(client->ipsw)) {
		// strip off file extension if given ipsw is not a directory
		char* s = tmpf + strlen(tmpf) - 1;
		char* p = s;
		while (*p != '\0' && *p != '.' && *p != '/' && *p != '\\') p--;
		if (s - p < 6) {
			if (*p == '.') {
				*p = '\0';
			}
		}
	}

	if (stat(tmpf, &st) < 0) {
		__mkdir(tmpf, 0755);
	}
	strcat(tmpf, "/");
	strcat(tmpf, fsname);

	memset(&st, '\0', sizeof(struct stat));
	if (stat(tmpf, &st) == 0) {
		uint64_t fssize = 0;
		ipsw_get_file_size(client->ipsw, fsname, &fssize);
		if ((fssize > 0) && ((uint64_t)st.st_size == fssize)) {
			info("Using cached filesystem from '%s'\n", tmpf);
			filesystem = strdup(tmpf);
		}
	}

	if (!filesystem && !(client->flags & FLAG_SHSHONLY)) {
		char extfn[1024];
		strcpy(extfn, tmpf);
		strcat(extfn, ".extract");
		char lockfn[1024];
		strcpy(lockfn, tmpf);
		strcat(lockfn, ".lock");
		lock_info_t li;

		lock_file(lockfn, &li);
		FILE* extf = NULL;
		if (access(extfn, F_OK) != 0) {
			extf = fopen(extfn, "wb");
		}
		unlock_file(&li);
		if (!extf) {
			// use temp filename
			filesystem = get_temp_filename("ipsw_");
			if (!filesystem) {
				error("WARNING: Could not get temporary filename, using '%s' in current directory\n", fsname);
				filesystem = strdup(fsname);
			}
			delete_fs = 1;
		} else {
			// use <fsname>.extract as filename
			filesystem = strdup(extfn);
			fclose(extf);
		}
		remove(lockfn);

		// Extract filesystem from IPSW
		info("Extracting filesystem from IPSW: %s\n", fsname);
		if (ipsw_extract_to_file_with_progress(client->ipsw, fsname, filesystem, 1) < 0) {
			error("ERROR: Unable to extract filesystem from IPSW\n");
			if (client->tss)
				plist_free(client->tss);
			plist_free(buildmanifest);
			info("Removing %s\n", filesystem);
			unlink(filesystem);
			return -1;
		}

		if (strstr(filesystem, ".extract")) {
			// rename <fsname>.extract to <fsname>
			remove(tmpf);
			rename(filesystem, tmpf);
			free(filesystem);
			filesystem = strdup(tmpf); 
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.2);

	/* retrieve shsh blobs if required */
	if (tss_enabled) {
		int stashbag_commit_required = 0;
		debug("Getting device's ECID for TSS request\n");
		/* fetch the device's ECID for the TSS request */
		if (get_ecid(client, &client->ecid) < 0) {
			error("ERROR: Unable to find device ECID\n");
			return -1;
		}
		info("Found ECID " FMT_qu "\n", (long long unsigned int)client->ecid);

		if (client->mode->index == MODE_NORMAL && !(client->flags & FLAG_ERASE) && !(client->flags & FLAG_SHSHONLY)) {
			plist_t node = normal_get_lockdown_value(client, NULL, "HasSiDP");
			uint8_t needs_preboard = 0;
			if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
				plist_get_bool_val(node, &needs_preboard);
			}
			if (needs_preboard) {
				info("Checking if device requires stashbag...\n");
				plist_t manifest;
				if (get_preboard_manifest(client, build_identity, &manifest) < 0) {
					error("ERROR: Unable to create preboard manifest.\n");
					return -1;
				}
				debug("DEBUG: creating stashbag...\n");
				int err = normal_handle_create_stashbag(client, manifest);
				if (err < 0) {
					if (err == -2) {
						error("ERROR: Could not create stashbag (timeout).\n");
					} else {
						error("ERROR: An error occurred while creating the stashbag.\n");
					}
					return -1;
				} else if (err == 1) {
					stashbag_commit_required = 1;
				}
				plist_free(manifest);
			}
		}

		if (client->build_major > 8) {
			unsigned char* nonce = NULL;
			int nonce_size = 0;
			if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
				/* the first nonce request with older firmware releases can fail and it's OK */
				info("NOTE: Unable to get nonce from device\n");
			}

			if (!client->nonce || (nonce_size != client->nonce_size) || (memcmp(nonce, client->nonce, nonce_size) != 0)) {
				if (client->nonce) {
					free(client->nonce);
				}
				client->nonce = nonce;
				client->nonce_size = nonce_size;
			} else {
				free(nonce);
			}
		}

		if (client->flags & FLAG_QUIT) {
			return -1;
		}
		if (get_tss_response(client, build_identity, &client->tss) < 0) {
			error("ERROR: Unable to get SHSH blobs for this device\n");
			return -1;
		}
		if (stashbag_commit_required) {
			plist_t ticket = plist_dict_get_item(client->tss, "ApImg4Ticket");
			if (!ticket || plist_get_node_type(ticket) != PLIST_DATA) {
				error("ERROR: Missing ApImg4Ticket in TSS response for stashbag commit\n");
				return -1;
			}
			info("Committing stashbag...\n");
			int err = normal_handle_commit_stashbag(client, ticket);
			if (err < 0) {
				error("ERROR: Could not commit stashbag (%d). Aborting.\n", err);
				return -1;
			}
		}
	}

	if (client->flags & FLAG_QUIT) {
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}
	if (client->flags & FLAG_SHSHONLY) {
		if (!tss_enabled) {
			info("This device does not require a TSS record\n");
			return 0;
		}
		if (!client->tss) {
			error("ERROR: could not fetch TSS record\n");
			plist_free(buildmanifest);
			return -1;
		} else {
			char *bin = NULL;
			uint32_t blen = 0;
			plist_to_bin(client->tss, &bin, &blen);
			if (bin) {
				char zfn[1024];
				if (client->cache_dir) {
					strcpy(zfn, client->cache_dir);
					strcat(zfn, "/shsh");
				} else {
					strcpy(zfn, "shsh");
				}
				mkdir_with_parents(zfn, 0755);
				sprintf(zfn+strlen(zfn), "/" FMT_qu "-%s-%s.shsh", (long long int)client->ecid, client->device->product_type, client->version);
				struct stat fst;
				if (stat(zfn, &fst) != 0) {
					gzFile zf = gzopen(zfn, "wb");
					gzwrite(zf, bin, blen);
					gzclose(zf);
					info("SHSH saved to '%s'\n", zfn);
				} else {
					info("SHSH '%s' already present.\n", zfn);
				}
				free(bin);
			} else {
				error("ERROR: could not get TSS record data\n");
			}
			plist_free(client->tss);
			plist_free(buildmanifest);
			return 0;
		}
	}

	/* verify if we have tss records if required */
	if ((tss_enabled) && (client->tss == NULL)) {
		error("ERROR: Unable to proceed without a TSS record.\n");
		plist_free(buildmanifest);
		return -1;
	}

	if ((tss_enabled) && client->tss) {
		/* fix empty dicts */
		fixup_tss(client->tss);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.25);
	if (client->flags & FLAG_QUIT) {
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}

	// if the device is in normal mode, place device into recovery mode
	if (client->mode->index == MODE_NORMAL) {
		info("Entering recovery mode...\n");
		if (normal_enter_recovery(client) < 0) {
			error("ERROR: Unable to place device into recovery mode from %s mode\n", client->mode->string);
			if (client->tss)
				plist_free(client->tss);
			plist_free(buildmanifest);
			return -5;
		}
	}

	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.3);
	if (client->flags & FLAG_QUIT) {
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}

	// if the device is in DFU mode, place device into recovery mode
	if (client->mode->index == MODE_DFU) {
		dfu_client_free(client);
		recovery_client_free(client);
		if ((client->flags & FLAG_CUSTOM) && limera1n_is_supported(client->device)) {
			info("connecting to DFU\n");
			if (dfu_client_new(client) < 0) {
				if (delete_fs && filesystem)
					unlink(filesystem);
				return -1;
			}
			info("exploiting with limera1n\n");
			// TODO: check for non-limera1n device and fail
			if (limera1n_exploit(client->device, &client->dfu->client) != 0) {
				error("ERROR: limera1n exploit failed\n");
				dfu_client_free(client);
				if (delete_fs && filesystem)
					unlink(filesystem);
				return -1;
			}
			dfu_client_free(client);
			info("exploited\n");
		}
		if (dfu_enter_recovery(client, build_identity) < 0) {
			error("ERROR: Unable to place device into recovery mode from %s mode\n", client->mode->string);
			plist_free(buildmanifest);
			if (client->tss)
				plist_free(client->tss);
			if (delete_fs && filesystem)
				unlink(filesystem);
			return -2;
		}
	}

	if (client->mode->index == MODE_DFU) {
		client->mode = &idevicerestore_modes[MODE_RECOVERY];
	} else {
		if ((client->build_major > 8) && !(client->flags & FLAG_CUSTOM)) {
			if (!client->image4supported) {
				/* send ApTicket */
				if (recovery_send_ticket(client) < 0) {
					error("WARNING: Unable to send APTicket\n");
				}
			}
		}

		/* now we load the iBEC */
		if (recovery_send_ibec(client, build_identity) < 0) {
			error("ERROR: Unable to send iBEC\n");
			if (delete_fs && filesystem)
				unlink(filesystem);
			return -2;
		}
		recovery_client_free(client);
	
		/* this must be long enough to allow the device to run the iBEC */
		/* FIXME: Probably better to detect if the device is back then */
		sleep(7);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.5);
	if (client->flags & FLAG_QUIT) {
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}

	if (!client->image4supported && (client->build_major > 8)) {
		// we need another tss request with nonce.
		unsigned char* nonce = NULL;
		int nonce_size = 0;
		int nonce_changed = 0;
		if (get_ap_nonce(client, &nonce, &nonce_size) < 0) {
			error("ERROR: Unable to get nonce from device!\n");
			recovery_send_reset(client);
			if (delete_fs && filesystem)
				unlink(filesystem);
			return -2;
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

		if (nonce_changed && !(client->flags & FLAG_CUSTOM)) {
			// Welcome iOS5. We have to re-request the TSS with our nonce.
			plist_free(client->tss);
			if (get_tss_response(client, build_identity, &client->tss) < 0) {
				error("ERROR: Unable to get SHSH blobs for this device\n");
				if (delete_fs && filesystem)
					unlink(filesystem);
				return -1;
			}
			if (!client->tss) {
				error("ERROR: can't continue without TSS\n");
				if (delete_fs && filesystem)
					unlink(filesystem);
				return -1;
			}
			fixup_tss(client->tss);
		}
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.7);
	if (client->flags & FLAG_QUIT) {
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}

	// now finally do the magic to put the device into restore mode
	if (client->mode->index == MODE_RECOVERY) {
		if (client->srnm == NULL) {
			error("ERROR: could not retrieve device serial number. Can't continue.\n");
			if (delete_fs && filesystem)
				unlink(filesystem);
			return -1;
		}
		if (recovery_enter_restore(client, build_identity) < 0) {
			error("ERROR: Unable to place device into restore mode\n");
			plist_free(buildmanifest);
			if (client->tss)
				plist_free(client->tss);
			if (delete_fs && filesystem)
				unlink(filesystem);
			return -2;
		}
		recovery_client_free(client);
	}
	idevicerestore_progress(client, RESTORE_STEP_PREPARE, 0.9);

	info("Waiting for device to enter restore mode...\n");
	WAIT_FOR(client->mode == &idevicerestore_modes[MODE_RESTORE] || (client->flags & FLAG_QUIT), 180);
	if (client->mode != &idevicerestore_modes[MODE_RESTORE] || (client->flags & FLAG_QUIT)) {
		error("ERROR: Device failed to enter restore mode.\n");
		if (delete_fs && filesystem)
			unlink(filesystem);
		return -1;
	}

	// device is finally in restore mode, let's do this
	if (client->mode->index == MODE_RESTORE) {
		info("About to restore device... \n");
		result = restore_device(client, build_identity, filesystem);
		if (result < 0) {
			error("ERROR: Unable to restore device\n");
			if (delete_fs && filesystem)
				unlink(filesystem);
			return result;
		}
	}

	info("Cleaning up...\n");
	if (delete_fs && filesystem)
		unlink(filesystem);

	/* special handling of older AppleTVs as they enter Recovery mode on boot when plugged in to USB */
	if ((strncmp(client->device->product_type, "AppleTV", 7) == 0) && (client->device->product_type[7] < '5')) {
		if (recovery_client_new(client) == 0) {
			if (recovery_set_autoboot(client, 1) == 0) {
				recovery_send_reset(client);
			} else {
				error("Setting auto-boot failed?!\n");
			}
		} else {
			error("Could not connect to device in recovery mode.\n");
		}
	}

	info("DONE\n");

	if (result == 0) {
		idevicerestore_progress(client, RESTORE_NUM_STEPS-1, 1.0);
	}

	if (buildmanifest)
		plist_free(buildmanifest);

	if (build_identity)
		plist_free(build_identity);

	return result;
}

struct idevicerestore_client_t* idevicerestore_client_new(void)
{
	struct idevicerestore_client_t* client = (struct idevicerestore_client_t*) malloc(sizeof(struct idevicerestore_client_t));
	if (client == NULL) {
		error("ERROR: Out of memory\n");
		return NULL;
	}
	memset(client, '\0', sizeof(struct idevicerestore_client_t));
	client->mode = &idevicerestore_modes[MODE_UNKNOWN];
	return client;
}

void idevicerestore_client_free(struct idevicerestore_client_t* client)
{
	if (!client) {
		return;
	}

	if (client->irecv_e_ctx) {
		irecv_device_event_unsubscribe(client->irecv_e_ctx);
	}
	if (client->idevice_e_ctx) {
		idevice_event_unsubscribe();
	}
	if (client->tss_url) {
		free(client->tss_url);
	}
	if (client->version_data) {
		plist_free(client->version_data);
	}
	if (client->nonce) {
		free(client->nonce);
	}
	if (client->udid) {
		free(client->udid);
	}
	if (client->srnm) {
		free(client->srnm);
	}
	if (client->ipsw) {
		free(client->ipsw);
	}
	if (client->version) {
		free(client->version);
	}
	if (client->build) {
		free(client->build);
	}
	if (client->restore_boot_args) {
		free(client->restore_boot_args);
	}
	if (client->cache_dir) {
		free(client->cache_dir);
	}
	free(client);
}

void idevicerestore_set_ecid(struct idevicerestore_client_t* client, unsigned long long ecid)
{
	if (!client)
		return;
	client->ecid = ecid;
}

void idevicerestore_set_udid(struct idevicerestore_client_t* client, const char* udid)
{
	if (!client)
		return;
	if (client->udid) {
		free(client->udid);
		client->udid = NULL;
	}
	if (udid) {
		client->udid = strdup(udid);
	}
}

void idevicerestore_set_flags(struct idevicerestore_client_t* client, int flags)
{
	if (!client)
		return;
	client->flags = flags;
}

void idevicerestore_set_ipsw(struct idevicerestore_client_t* client, const char* path)
{
	if (!client)
		return;
	if (client->ipsw) {
		free(client->ipsw);
		client->ipsw = NULL;
	}
	if (path) {
		client->ipsw = strdup(path);
	}
}

void idevicerestore_set_cache_path(struct idevicerestore_client_t* client, const char* path)
{
	if (!client)
		return;
	if (client->cache_dir) {
		free(client->cache_dir);
		client->cache_dir = NULL;
	}
	if (path) {
		client->cache_dir = strdup(path);
	}
}

void idevicerestore_set_progress_callback(struct idevicerestore_client_t* client, idevicerestore_progress_cb_t cbfunc, void* userdata)
{
	if (!client)
		return;
	client->progress_cb = cbfunc;
	client->progress_cb_data = userdata;
}

#ifndef IDEVICERESTORE_NOMAIN
static struct idevicerestore_client_t* idevicerestore_client = NULL;

static void handle_signal(int sig)
{
	if (idevicerestore_client) {
		idevicerestore_client->flags |= FLAG_QUIT;
		ipsw_cancel();
	}
}

int main(int argc, char* argv[]) {
	int opt = 0;
	int optindex = 0;
	char* ipsw = NULL;
	int result = 0;

	struct idevicerestore_client_t* client = idevicerestore_client_new();
	if (client == NULL) {
		error("ERROR: could not create idevicerestore client\n");
		return -1;
	}

	idevicerestore_client = client;

	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
#ifndef WIN32
	sigaction(SIGQUIT, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
#endif

	if (!isatty(fileno(stdin)) || !isatty(fileno(stdout))) {
		client->flags &= ~FLAG_INTERACTIVE;
	} else {
		client->flags |= FLAG_INTERACTIVE;
	}

	while ((opt = getopt_long(argc, argv, "dhcesxtpli:u:nC:ky", longopts, &optindex)) > 0) {
		switch (opt) {
		case 'h':
			usage(argc, argv, 0);
			return 0;

		case 'd':
			client->flags |= FLAG_DEBUG;
			break;

		case 'e':
			client->flags |= FLAG_ERASE;
			break;

		case 'c':
			client->flags |= FLAG_CUSTOM;
			break;

		case 's':
			client->tss_url = strdup("http://cydia.saurik.com/TSS/controller?action=2");
			break;

		case 'x':
			client->flags |= FLAG_EXCLUDE;
			break;

		case 'l':
			client->flags |= FLAG_LATEST;
			break;

		case 'i':
			if (optarg) {
				char* tail = NULL;
				client->ecid = strtoull(optarg, &tail, 0);
				if (tail && (tail[0] != '\0')) {
					client->ecid = 0;
				}
				if (client->ecid == 0) {
					error("ERROR: Could not parse ECID from '%s'\n", optarg);
					return -1;
				}
			}
			break;

		case 'u':
			if (!*optarg) {
				error("ERROR: UDID must not be empty!\n");
				usage(argc, argv, 1);
				return -1;
			}
			client->udid = strdup(optarg);
			break;

		case 't':
			client->flags |= FLAG_SHSHONLY;
			break;

		case 'k':
			idevicerestore_keep_pers = 1;
			break;

		case 'p':
			client->flags |= FLAG_PWN;
			break;

		case 'n':
			client->flags |= FLAG_NOACTION;
			break;

		case 'C':
			client->cache_dir = strdup(optarg);
			break;

		case 'y':
			client->flags &= ~FLAG_INTERACTIVE;
			break;

		default:
			usage(argc, argv, 1);
			return -1;
		}
	}

	if (((argc-optind) == 1) || (client->flags & FLAG_PWN) || (client->flags & FLAG_LATEST)) {
		argc -= optind;
		argv += optind;

		ipsw = argv[0];
	} else {
		usage(argc, argv, 1);
		return -1;
	}

	if ((client->flags & FLAG_LATEST) && (client->flags & FLAG_CUSTOM)) {
		error("ERROR: You can't use --custom and --latest options at the same time.\n");
		return -1;
	}

	if (ipsw) {
		client->ipsw = strdup(ipsw);
	}

	curl_global_init(CURL_GLOBAL_ALL);

	result = idevicerestore_start(client);

	idevicerestore_client_free(client);

	curl_global_cleanup();

	return result;
}
#endif

int check_mode(struct idevicerestore_client_t* client) {
	int mode = MODE_UNKNOWN;
	int dfumode = MODE_UNKNOWN;

	if (recovery_check_mode(client) == 0) {
		mode = MODE_RECOVERY;
	}

	else if (dfu_check_mode(client, &dfumode) == 0) {
		mode = dfumode;
	}

	else if (normal_check_mode(client) == 0) {
		mode = MODE_NORMAL;
	}

	else if (restore_check_mode(client) == 0) {
		mode = MODE_RESTORE;
	}

	if (mode == MODE_UNKNOWN) {
		client->mode = NULL;
	} else {
		client->mode = &idevicerestore_modes[mode];
	}
	return mode;
}

irecv_device_t get_irecv_device(struct idevicerestore_client_t *client) {
	int mode = MODE_UNKNOWN;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case MODE_RESTORE:
		return restore_get_irecv_device(client);

	case MODE_NORMAL:
		return normal_get_irecv_device(client);

	case MODE_DFU:
	case MODE_RECOVERY:
		return dfu_get_irecv_device(client);

	default:
		return NULL;
	}
}

int is_image4_supported(struct idevicerestore_client_t* client)
{
	int res = 0;
	int mode = MODE_UNKNOWN;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case MODE_NORMAL:
		res = normal_is_image4_supported(client);
		break;
	case MODE_DFU:
		res = dfu_is_image4_supported(client);
		break;
	case MODE_RECOVERY:
		res = recovery_is_image4_supported(client);
		break;
	default:
		error("ERROR: Device is in an invalid state\n");
		return 0;
	}
	return res;
}

int get_ecid(struct idevicerestore_client_t* client, uint64_t* ecid) {
	int mode = MODE_UNKNOWN;

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case MODE_NORMAL:
		if (normal_get_ecid(client, ecid) < 0) {
			*ecid = 0;
			return -1;
		}
		break;

	case MODE_DFU:
		if (dfu_get_ecid(client, ecid) < 0) {
			*ecid = 0;
			return -1;
		}
		break;

	case MODE_RECOVERY:
		if (recovery_get_ecid(client, ecid) < 0) {
			*ecid = 0;
			return -1;
		}
		break;

	default:
		error("ERROR: Device is in an invalid state\n");
		*ecid = 0;
		return -1;
	}

	return 0;
}

int get_ap_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	int mode = MODE_UNKNOWN;

	*nonce = NULL;
	*nonce_size = 0;

	info("Getting ApNonce ");

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case MODE_NORMAL:
		info("in normal mode... ");
		if (normal_get_ap_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;
	case MODE_DFU:
		info("in dfu mode... ");
		if (dfu_get_ap_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;
	case MODE_RECOVERY:
		info("in recovery mode... ");
		if (recovery_get_ap_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;

	default:
		info("failed\n");
		error("ERROR: Device is in an invalid state\n");
		return -1;
	}

	int i = 0;
	for (i = 0; i < *nonce_size; i++) {
		info("%02x ", (*nonce)[i]);
	}
	info("\n");

	return 0;
}

int get_sep_nonce(struct idevicerestore_client_t* client, unsigned char** nonce, int* nonce_size) {
	int mode = MODE_UNKNOWN;

	*nonce = NULL;
	*nonce_size = 0;

	info("Getting SepNonce ");

	if (client->mode) {
		mode = client->mode->index;
	}

	switch (mode) {
	case MODE_NORMAL:
		info("in normal mode... ");
		if (normal_get_sep_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;
	case MODE_DFU:
		info("in dfu mode... ");
		if (dfu_get_sep_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;
	case MODE_RECOVERY:
		info("in recovery mode... ");
		if (recovery_get_sep_nonce(client, nonce, nonce_size) < 0) {
			info("failed\n");
			return -1;
		}
		break;

	default:
		info("failed\n");
		error("ERROR: Device is in an invalid state\n");
		return -1;
	}

	int i = 0;
	for (i = 0; i < *nonce_size; i++) {
		info("%02x ", (*nonce)[i]);
	}
	info("\n");

	return 0;
}

plist_t build_manifest_get_build_identity_for_model_with_restore_behavior(plist_t build_manifest, const char *hardware_model, const char *behavior)
{
	plist_t build_identities_array = plist_dict_get_item(build_manifest, "BuildIdentities");
	if (!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find build identities node\n");
		return NULL;
	}

	uint32_t i;
	for (i = 0; i < plist_array_get_size(build_identities_array); i++) {
		plist_t ident = plist_array_get_item(build_identities_array, i);
		if (!ident || plist_get_node_type(ident) != PLIST_DICT) {
			continue;
		}
		plist_t info_dict = plist_dict_get_item(ident, "Info");
		if (!info_dict || plist_get_node_type(ident) != PLIST_DICT) {
			continue;
		}
		plist_t devclass = plist_dict_get_item(info_dict, "DeviceClass");
		if (!devclass || plist_get_node_type(devclass) != PLIST_STRING) {
			continue;
		}
		char *str = NULL;
		plist_get_string_val(devclass, &str);
		if (strcasecmp(str, hardware_model) != 0) {
			free(str);
			continue;
		}
		free(str);
		str = NULL;
		if (behavior) {
			plist_t rbehavior = plist_dict_get_item(info_dict, "RestoreBehavior");
			if (!rbehavior || plist_get_node_type(rbehavior) != PLIST_STRING) {
				continue;
			}
			plist_get_string_val(rbehavior, &str);
			if (strcasecmp(str, behavior) != 0) {
				free(str);
				continue;
			} else {
				free(str);
				return plist_copy(ident);
			}
			free(str);
		} else {
			return plist_copy(ident);
		}
	}

	return NULL;
}

plist_t build_manifest_get_build_identity_for_model(plist_t build_manifest, const char *hardware_model)
{
	return build_manifest_get_build_identity_for_model_with_restore_behavior(build_manifest, hardware_model, NULL);
}

int get_preboard_manifest(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* manifest)
{
	plist_t request = NULL;
	*manifest = NULL;

	if (!client->image4supported) {
		return -1;
	}

	/* populate parameters */
	plist_t parameters = plist_new_dict();

	plist_t overrides = plist_new_dict();
	plist_dict_set_item(overrides, "@APTicket", plist_new_bool(1));
	plist_dict_set_item(overrides, "ApProductionMode", plist_new_uint(0));
	plist_dict_set_item(overrides, "ApSecurityDomain", plist_new_uint(0));

	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(0));
	plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(0));
	plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));

	tss_parameters_add_from_manifest(parameters, build_identity);

	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		error("ERROR: Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	if (tss_request_add_common_tags(request, parameters, overrides) < 0) {
		error("ERROR: Unable to add common tags\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	plist_dict_set_item(parameters, "_OnlyFWComponents", plist_new_bool(1));

	/* add tags from manifest */
	if (tss_request_add_ap_tags(request, parameters, NULL) < 0) {
		error("ERROR: Unable to add ap tags\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	plist_t local_manifest = NULL;
	int res = img4_create_local_manifest(request, &local_manifest);

	*manifest = local_manifest;

	plist_free(request);
	plist_free(parameters);
	plist_free(overrides);

	return res;
}

int get_tss_response(struct idevicerestore_client_t* client, plist_t build_identity, plist_t* tss) {
	plist_t request = NULL;
	plist_t response = NULL;
	*tss = NULL;

	if ((client->build_major <= 8) || (client->flags & FLAG_CUSTOM)) {
		error("checking for local shsh\n");

		/* first check for local copy */
		char zfn[1024];
		if (client->version) {
			if (client->cache_dir) {
				sprintf(zfn, "%s/shsh/" FMT_qu "-%s-%s.shsh", client->cache_dir, (long long int)client->ecid, client->device->product_type, client->version);
			} else {
				sprintf(zfn, "shsh/" FMT_qu "-%s-%s.shsh", (long long int)client->ecid, client->device->product_type, client->version);
			}
			struct stat fst;
			if (stat(zfn, &fst) == 0) {
				gzFile zf = gzopen(zfn, "rb");
				if (zf) {
					int blen = 0;
					int readsize = 16384;
					int bufsize = readsize;
					char* bin = (char*)malloc(bufsize);
					char* p = bin;
					do {
						int bytes_read = gzread(zf, p, readsize);
						if (bytes_read < 0) {
							fprintf(stderr, "Error reading gz compressed data\n");
							exit(EXIT_FAILURE);
						}
						blen += bytes_read;
						if (bytes_read < readsize) {
							if (gzeof(zf)) {
								bufsize += bytes_read;
								break;
							}
						}
						bufsize += readsize;
						bin = realloc(bin, bufsize);
						p = bin + blen;
					} while (!gzeof(zf));
					gzclose(zf);
					if (blen > 0) {
						if (memcmp(bin, "bplist00", 8) == 0) {
							plist_from_bin(bin, blen, tss);
						} else {
							plist_from_xml(bin, blen, tss);
						}
					}
					free(bin);
				}
			} else {
				error("no local file %s\n", zfn);
			}
		} else {
			error("No version found?!\n");
		}
	}

	if (*tss) {
		info("Using cached SHSH\n");
		return 0;
	} else {
		info("Trying to fetch new SHSH blob\n");
	}

	/* populate parameters */
	plist_t parameters = plist_new_dict();
	plist_dict_set_item(parameters, "ApECID", plist_new_uint(client->ecid));
	if (client->nonce) {
		plist_dict_set_item(parameters, "ApNonce", plist_new_data((const char*)client->nonce, client->nonce_size));
	}
	unsigned char* sep_nonce = NULL;
	int sep_nonce_size = 0;
	get_sep_nonce(client, &sep_nonce, &sep_nonce_size);

	if (sep_nonce) {
		plist_dict_set_item(parameters, "ApSepNonce", plist_new_data((const char*)sep_nonce, sep_nonce_size));
		free(sep_nonce);
	}

	plist_dict_set_item(parameters, "ApProductionMode", plist_new_bool(1));
	if (client->image4supported) {
		plist_dict_set_item(parameters, "ApSecurityMode", plist_new_bool(1));
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(1));
	} else {
		plist_dict_set_item(parameters, "ApSupportsImg4", plist_new_bool(0));
	}

	tss_parameters_add_from_manifest(parameters, build_identity);

	/* create basic request */
	request = tss_request_new(NULL);
	if (request == NULL) {
		error("ERROR: Unable to create TSS request\n");
		plist_free(parameters);
		return -1;
	}

	/* add common tags from manifest */
	if (tss_request_add_common_tags(request, parameters, NULL) < 0) {
		error("ERROR: Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	/* add tags from manifest */
	if (tss_request_add_ap_tags(request, parameters, NULL) < 0) {
		error("ERROR: Unable to add common tags to TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	if (client->image4supported) {
		/* add personalized parameters */
		if (tss_request_add_ap_img4_tags(request, parameters) < 0) {
			error("ERROR: Unable to add img4 tags to TSS request\n");
			plist_free(request);
			plist_free(parameters);
			return -1;
		}
	} else {
		/* add personalized parameters */
		if (tss_request_add_ap_img3_tags(request, parameters) < 0) {
			error("ERROR: Unable to add img3 tags to TSS request\n");
			plist_free(request);
			plist_free(parameters);
			return -1;
		}
	}

	if (client->mode->index == MODE_NORMAL) {
		/* normal mode; request baseband ticket aswell */
		plist_t pinfo = NULL;
		normal_get_preflight_info(client, &pinfo);
		if (pinfo) {
			plist_t node;
			node = plist_dict_get_item(pinfo, "Nonce");
			if (node) {
				plist_dict_set_item(parameters, "BbNonce", plist_copy(node));
			}
			node = plist_dict_get_item(pinfo, "ChipID");
			if (node) {
				plist_dict_set_item(parameters, "BbChipID", plist_copy(node));
			}
			node = plist_dict_get_item(pinfo, "CertID");
			if (node) {
				plist_dict_set_item(parameters, "BbGoldCertId", plist_copy(node));
			}
			node = plist_dict_get_item(pinfo, "ChipSerialNo");
			if (node) {
				plist_dict_set_item(parameters, "BbSNUM", plist_copy(node));
			}
		
			/* add baseband parameters */
			tss_request_add_baseband_tags(request, parameters, NULL);

			node = plist_dict_get_item(pinfo, "EUICCChipID");
			uint64_t euiccchipid = 0;
			if (node && plist_get_node_type(node) == PLIST_UINT) {
				plist_get_uint_val(node, &euiccchipid);
				plist_dict_set_item(parameters, "eUICC,ChipID", plist_copy(node));
			}
			if (euiccchipid >= 5) {
				node = plist_dict_get_item(pinfo, "EUICCCSN");
				if (node) {
					plist_dict_set_item(parameters, "eUICC,EID", plist_copy(node));
				}
				node = plist_dict_get_item(pinfo, "EUICCCertIdentifier");
				if (node) {
					plist_dict_set_item(parameters, "eUICC,RootKeyIdentifier", plist_copy(node));
				}
				node = plist_dict_get_item(pinfo, "EUICCGoldNonce");
				if (node) {
					plist_dict_set_item(parameters, "EUICCGoldNonce", plist_copy(node));
				}
				node = plist_dict_get_item(pinfo, "EUICCMainNonce");
				if (node) {
					plist_dict_set_item(parameters, "EUICCMainNonce", plist_copy(node));
				}

				/* add vinyl parameters */
				tss_request_add_vinyl_tags(request, parameters, NULL);
			}
		}
		client->preflight_info = pinfo;
	}

	/* send request and grab response */
	response = tss_request_send(request, client->tss_url);
	if (response == NULL) {
		info("ERROR: Unable to send TSS request\n");
		plist_free(request);
		plist_free(parameters);
		return -1;
	}

	info("Received SHSH blobs\n");

	plist_free(request);
	plist_free(parameters);

	*tss = response;

	return 0;
}

void fixup_tss(plist_t tss)
{
	plist_t node;
	plist_t node2;
	node = plist_dict_get_item(tss, "RestoreLogo");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "AppleLogo");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreLogo");
			plist_dict_set_item(tss, "RestoreLogo", plist_copy(node2));
		}
	}
	node = plist_dict_get_item(tss, "RestoreDeviceTree");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "DeviceTree");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreDeviceTree");
			plist_dict_set_item(tss, "RestoreDeviceTree", plist_copy(node2));
		}
	}
	node = plist_dict_get_item(tss, "RestoreKernelCache");
	if (node && (plist_get_node_type(node) == PLIST_DICT) && (plist_dict_get_size(node) == 0)) {
		node2 = plist_dict_get_item(tss, "KernelCache");
		if (node2 && (plist_get_node_type(node2) == PLIST_DICT)) {
			plist_dict_remove_item(tss, "RestoreKernelCache");
			plist_dict_set_item(tss, "RestoreKernelCache", plist_copy(node2));
		}
	}
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

int extract_component(const char* ipsw, const char* path, unsigned char** component_data, unsigned int* component_size)
{
	char* component_name = NULL;
	if (!ipsw || !path || !component_data || !component_size) {
		return -1;
	}

	component_name = strrchr(path, '/');
	if (component_name != NULL)
		component_name++;
	else
		component_name = (char*) path;

	info("Extracting %s...\n", component_name);
	if (ipsw_extract_to_memory(ipsw, path, component_data, component_size) < 0) {
		error("ERROR: Unable to extract %s from %s\n", component_name, ipsw);
		return -1;
	}

	return 0;
}

int personalize_component(const char *component_name, const unsigned char* component_data, unsigned int component_size, plist_t tss_response, unsigned char** personalized_component, unsigned int* personalized_component_size) {
	unsigned char* component_blob = NULL;
	unsigned int component_blob_size = 0;
	unsigned char* stitched_component = NULL;
	unsigned int stitched_component_size = 0;

	if (tss_response && tss_response_get_ap_img4_ticket(tss_response, &component_blob, &component_blob_size) == 0) {
		/* stitch ApImg4Ticket into IMG4 file */
		img4_stitch_component(component_name, component_data, component_size, component_blob, component_blob_size, &stitched_component, &stitched_component_size);
	} else {
		/* try to get blob for current component from tss response */
		if (tss_response && tss_response_get_blob_by_entry(tss_response, component_name, &component_blob) < 0) {
			debug("NOTE: No SHSH blob found for component %s\n", component_name);
		}

		if (component_blob != NULL) {
			if (img3_stitch_component(component_name, component_data, component_size, component_blob, 64, &stitched_component, &stitched_component_size) < 0) {
				error("ERROR: Unable to replace %s IMG3 signature\n", component_name);
				free(component_blob);
				return -1;
			}
		} else {
			info("Not personalizing component %s...\n", component_name);
			stitched_component = (unsigned char*)malloc(component_size);
			if (stitched_component) {
				stitched_component_size = component_size;
				memcpy(stitched_component, component_data, component_size);
			}
		}
	}
	free(component_blob);

	if (idevicerestore_keep_pers) {
		write_file(component_name, stitched_component, stitched_component_size);
	}

	*personalized_component = stitched_component;
	*personalized_component_size = stitched_component_size;
	return 0;
}

int build_manifest_check_compatibility(plist_t build_manifest, const char* product) {
	int res = -1;
	plist_t node = plist_dict_get_item(build_manifest, "SupportedProductTypes");
	if (!node || (plist_get_node_type(node) != PLIST_ARRAY)) {
		debug("%s: ERROR: SupportedProductTypes key missing\n", __func__);
		debug("%s: WARNING: If attempting to install iPhoneOS 2.x, be advised that Restore.plist does not contain the", __func__);
		debug("%s: WARNING: key 'SupportedProductTypes'. Recommendation is to manually add it to the Restore.plist.", __func__);
		return -1;
	}
	uint32_t pc = plist_array_get_size(node);
	uint32_t i;
	for (i = 0; i < pc; i++) {
		plist_t prod = plist_array_get_item(node, i);
		if (plist_get_node_type(prod) == PLIST_STRING) {
			char *val = NULL;
			plist_get_string_val(prod, &val);
			if (val && (strcmp(val, product) == 0)) {
				res = 0;
				free(val);
				break;
			}
		}
	}
	return res;
}

void build_manifest_get_version_information(plist_t build_manifest, struct idevicerestore_client_t* client) {
	plist_t node = NULL;
	client->version = NULL;
	client->build = NULL;

	node = plist_dict_get_item(build_manifest, "ProductVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ProductVersion node\n");
		return;
	}
	plist_get_string_val(node, &client->version);

	node = plist_dict_get_item(build_manifest, "ProductBuildVersion");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ProductBuildVersion node\n");
		return;
	}
	plist_get_string_val(node, &client->build);

	client->build_major = strtoul(client->build, NULL, 10);
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
		info("This restore will update your device without erasing user data.\n");

	free(value);

	info_node = NULL;
	node = NULL;
}

int build_identity_check_components_in_ipsw(plist_t build_identity, const char *ipsw)
{
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		return -1;
	}
	int res = 0;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	plist_t node = NULL;
	char *key = NULL;
	do {
		node = NULL;
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &node);
		if (key && node) {
			plist_t path = plist_access_path(node, 2, "Info", "Path");
			if (path) {
				char *comp_path = NULL;
				plist_get_string_val(path, &comp_path);
				if (comp_path) {
					if (!ipsw_file_exists(ipsw, comp_path)) {
						error("ERROR: %s file %s not found in IPSW\n", key, comp_path);
						res = -1;
					}
					free(comp_path);
				}
			}
		}
		free(key);
	} while (node);
	return res;
}

int build_identity_has_component(plist_t build_identity, const char* component) {
	plist_t manifest_node = plist_dict_get_item(build_identity, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		return 0;
	}

	plist_t component_node = plist_dict_get_item(manifest_node, component);
	if (!component_node || plist_get_node_type(component_node) != PLIST_DICT) {
		return 0;
	}

	return 1;
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

const char* get_component_name(const char* filename) {
	if (!strncmp(filename, "LLB", 3)) {
		return "LLB";
	} else if (!strncmp(filename, "iBoot", 5)) {
		return "iBoot";
	} else if (!strncmp(filename, "DeviceTree", 10)) {
		return "DeviceTree";
	} else if (!strncmp(filename, "applelogo", 9)) {
		return "AppleLogo";
	} else if (!strncmp(filename, "liquiddetect", 12)) {
		return "Liquid";
	} else if (!strncmp(filename, "lowpowermode", 12)) {
		return "LowPowerWallet0";
	} else if (!strncmp(filename, "recoverymode", 12)) {
		return "RecoveryMode";
	} else if (!strncmp(filename, "batterylow0", 11)) {
		return "BatteryLow0";
	} else if (!strncmp(filename, "batterylow1", 11)) {
		return "BatteryLow1";
	} else if (!strncmp(filename, "glyphcharging", 13)) {
		return "BatteryCharging";
	} else if (!strncmp(filename, "glyphplugin", 11)) {
		return "BatteryPlugin";
	} else if (!strncmp(filename, "batterycharging0", 16)) {
		return "BatteryCharging0";
	} else if (!strncmp(filename, "batterycharging1", 16)) {
		return "BatteryCharging1";
	} else if (!strncmp(filename, "batteryfull", 11)) {
		return "BatteryFull";
	} else if (!strncmp(filename, "needservice", 11)) {
		return "NeedService";
	} else if (!strncmp(filename, "SCAB", 4)) {
		return "SCAB";
	} else if (!strncmp(filename, "sep-firmware", 12)) {
		return "RestoreSEP";
	} else {
		error("WARNING: Unhandled component '%s'", filename);
		return NULL;
	}
}
