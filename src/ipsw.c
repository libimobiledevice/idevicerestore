/*
 * ipsw.c
 * Utilities for extracting and manipulating IPSWs
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010-2012 Martin Szulecki. All Rights Reserved.
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
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <zip.h>
#ifdef HAVE_OPENSSL
#include <openssl/sha.h>
#else
#include "sha1.h"
#define SHA_CTX SHA1_CTX
#define SHA1_Init SHA1Init
#define SHA1_Update SHA1Update
#define SHA1_Final SHA1Final
#endif

#include <libimobiledevice-glue/termcolors.h>

#include "ipsw.h"
#include "locking.h"
#include "download.h"
#include "common.h"
#include "idevicerestore.h"
#include "json_plist.h"

#define BUFSIZE 0x100000

typedef struct {
	struct zip* zip;
	char *path;
} ipsw_archive;

static int cancel_flag = 0;

ipsw_archive* ipsw_open(const char* ipsw);
void ipsw_close(ipsw_archive* archive);

static char* build_path(const char* path, const char* file)
{
	size_t plen = strlen(path);
	size_t flen = strlen(file);
	char *fullpath = malloc(plen + flen + 2);
	if (!fullpath) {
		return NULL;
	}
	memcpy(fullpath, path, plen);
	fullpath[plen] = '/';
	memcpy(fullpath+plen+1, file, flen);
	fullpath[plen+1+flen] = '\0';
	return fullpath;
}

int ipsw_print_info(const char* path)
{
	struct stat fst;

	if (stat(path, &fst) != 0) {
		error("ERROR: '%s': %s\n", path, strerror(errno));
		return -1;
	}

	char thepath[PATH_MAX];

	if (S_ISDIR(fst.st_mode)) {
		sprintf(thepath, "%s/BuildManifest.plist", path);
		if (stat(thepath, &fst) != 0) {
			error("ERROR: '%s': %s\n", thepath, strerror(errno));
			return -1;
		}
	} else {
		sprintf(thepath, "%s", path);
	}

	FILE* f = fopen(thepath, "r");
	if (!f) {
		error("ERROR: Can't open '%s': %s\n", thepath, strerror(errno));
		return -1;
	}
	uint32_t magic;
	if (fread(&magic, 1, 4, f) != 4) {
		fclose(f);
		fprintf(stderr, "Failed to read from '%s'\n", path);
		return -1;
	}
	fclose(f);

	char* plist_buf = NULL;
	uint32_t plist_len = 0;

	if (memcmp(&magic, "PK\x03\x04", 4) == 0) {
		unsigned int rlen = 0;
		if (ipsw_extract_to_memory(thepath, "BuildManifest.plist", (unsigned char**)&plist_buf, &rlen) < 0) {
			error("ERROR: Failed to extract BuildManifest.plist from IPSW!\n");
			return -1;
		}
		plist_len = (uint32_t)rlen;
	} else {
		size_t rlen = 0;
		if (read_file(thepath, (void**)&plist_buf, &rlen) < 0) {
			error("ERROR: Failed to read BuildManifest.plist!\n");
			return -1;
		}
		plist_len = (uint32_t)rlen;
	}

	plist_t manifest = NULL;
	plist_from_memory(plist_buf, plist_len, &manifest);
	free(plist_buf);

	plist_t val;

	char* prod_ver = NULL;
	char* build_ver = NULL;

	val = plist_dict_get_item(manifest, "ProductVersion");
	if (val) {
		plist_get_string_val(val, &prod_ver);
	}

	val = plist_dict_get_item(manifest, "ProductBuildVersion");
	if (val) {
		plist_get_string_val(val, &build_ver);
	}

	cprintf(COLOR_WHITE "Product Version: " COLOR_BRIGHT_YELLOW "%s" COLOR_RESET COLOR_WHITE "   Build: " COLOR_BRIGHT_YELLOW "%s" COLOR_RESET "\n", prod_ver, build_ver);
	free(prod_ver);
	free(build_ver);
	cprintf(COLOR_WHITE "Supported Product Types:" COLOR_RESET);
	val = plist_dict_get_item(manifest, "SupportedProductTypes");
	if (val) {
		plist_array_iter iter = NULL;
		plist_array_new_iter(val, &iter);
		if (iter) {
			plist_t item = NULL;
			do {
				plist_array_next_item(val, iter, &item);
				if (item) {
					char* item_str = NULL;
					plist_get_string_val(item, &item_str);
					cprintf(" " COLOR_BRIGHT_CYAN "%s" COLOR_RESET, item_str);
					free(item_str);
				}
			} while (item);
			free(iter);
		}
	}
	cprintf("\n");

	cprintf(COLOR_WHITE "Build Identities:" COLOR_RESET "\n");

	plist_t build_ids_grouped = plist_new_dict();

	plist_t build_ids = plist_dict_get_item(manifest, "BuildIdentities");
	plist_array_iter build_id_iter = NULL;
	plist_array_new_iter(build_ids, &build_id_iter);
	if (build_id_iter) {
		plist_t build_identity = NULL;
		do {
			plist_array_next_item(build_ids, build_id_iter, &build_identity);
			if (!build_identity) {
				break;
			}
			plist_t node;
			char* variant_str = NULL;

			node = plist_access_path(build_identity, 2, "Info", "Variant");
			plist_get_string_val(node, &variant_str);

			plist_t entries = NULL;
			plist_t group = plist_dict_get_item(build_ids_grouped, variant_str);
			if (!group) {
				group = plist_new_dict();
				node = plist_access_path(build_identity, 2, "Info", "RestoreBehavior");
				plist_dict_set_item(group, "RestoreBehavior", plist_copy(node));
				entries = plist_new_array();
				plist_dict_set_item(group, "Entries", entries);
				plist_dict_set_item(build_ids_grouped, variant_str, group);
			} else {
				entries = plist_dict_get_item(group, "Entries");
			}
			free(variant_str);
			plist_array_append_item(entries, plist_copy(build_identity));
		} while (build_identity);
		free(build_id_iter);
	}

	plist_dict_iter build_ids_group_iter = NULL;
	plist_dict_new_iter(build_ids_grouped, &build_ids_group_iter);
	if (build_ids_group_iter) {
		plist_t group = NULL;
		int group_no = 0;
		do {
			group = NULL;
			char* key = NULL;
			plist_dict_next_item(build_ids_grouped, build_ids_group_iter, &key, &group);
			if (!key) {
				break;
			}
			plist_t node;
			char* rbehavior = NULL;

			group_no++;
			node = plist_dict_get_item(group, "RestoreBehavior");
			plist_get_string_val(node, &rbehavior);
			cprintf("  " COLOR_WHITE "[%d] Variant: " COLOR_BRIGHT_CYAN "%s" COLOR_WHITE "   Behavior: " COLOR_BRIGHT_CYAN "%s" COLOR_RESET "\n", group_no, key, rbehavior);
			free(key);
			free(rbehavior);

			build_ids = plist_dict_get_item(group, "Entries");
			if (!build_ids) {
				continue;
			}
			build_id_iter = NULL;
			plist_array_new_iter(build_ids, &build_id_iter);
			if (!build_id_iter) {
				continue;
			}
			plist_t build_id;
			do {
				build_id = NULL;
				plist_array_next_item(build_ids, build_id_iter, &build_id);
				if (!build_id) {
					break;
				}
				uint64_t chip_id = 0;
				uint64_t board_id = 0;
				char* hwmodel = NULL;

				node = plist_dict_get_item(build_id, "ApChipID");
				if (PLIST_IS_STRING(node)) {
					char* strval = NULL;
					plist_get_string_val(node, &strval);
					if (strval) {
						chip_id = strtoull(strval, NULL, 0);
						free(strval);
					}
				} else {
					plist_get_uint_val(node, &chip_id);
				}

				node = plist_dict_get_item(build_id, "ApBoardID");
				if (PLIST_IS_STRING(node)) {
					char* strval = NULL;
					plist_get_string_val(node, &strval);
					if (strval) {
						board_id = strtoull(strval, NULL, 0);
						free(strval);
					}
				} else {
					plist_get_uint_val(node, &board_id);
				}

				node = plist_access_path(build_id, 2, "Info", "DeviceClass");
				plist_get_string_val(node, &hwmodel);

				irecv_device_t irecvdev = NULL;
				if (irecv_devices_get_device_by_hardware_model(hwmodel, &irecvdev) == 0) {
					cprintf("    ChipID: " COLOR_GREEN "%04x" COLOR_RESET "   BoardID: " COLOR_GREEN "%02x" COLOR_RESET "   Model: " COLOR_YELLOW "%-8s" COLOR_RESET "  " COLOR_MAGENTA "%s" COLOR_RESET "\n", (int)chip_id, (int)board_id, hwmodel, irecvdev->display_name);
				} else {
					cprintf("    ChipID: " COLOR_GREEN "%04x" COLOR_RESET "   BoardID: " COLOR_GREEN "%02x" COLOR_RESET "   Model: " COLOR_YELLOW "%s" COLOR_RESET "\n", (int)chip_id, (int)board_id, hwmodel);
				}
				free(hwmodel);
			} while (build_id);
			free(build_id_iter);
		} while (group);
		free(build_ids_group_iter);
	}
	plist_free(build_ids_grouped);

	plist_free(manifest);

	return 0;
}

ipsw_archive* ipsw_open(const char* ipsw)
{
	int err = 0;
	ipsw_archive* archive = (ipsw_archive*) malloc(sizeof(ipsw_archive));
	if (archive == NULL) {
		error("ERROR: Out of memory\n");
		return NULL;
	}

	struct stat fst;
	if (stat(ipsw, &fst) != 0) {
		error("ERROR: ipsw_open %s: %s\n", ipsw, strerror(errno));
		return NULL;
	}
	archive->path = strdup(ipsw);
	if (S_ISDIR(fst.st_mode)) {
		archive->zip = NULL;
	} else {
		archive->zip = zip_open(ipsw, 0, &err);
		if (archive->zip == NULL) {
			error("ERROR: zip_open: %s: %d\n", ipsw, err);
			free(archive);
			return NULL;
		}
	}
	return archive;
}

int ipsw_is_directory(const char* ipsw)
{
	struct stat fst;
	memset(&fst, '\0', sizeof(fst));
	if (stat(ipsw, &fst) != 0) {
		return 0;
	}
	return S_ISDIR(fst.st_mode);
}

int ipsw_get_file_size(const char* ipsw, const char* infile, uint64_t* size)
{
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

	if (archive->zip) {
		int zindex = zip_name_locate(archive->zip, infile, 0);
		if (zindex < 0) {
			error("ERROR: zip_name_locate: %s\n", infile);
			ipsw_close(archive);
			return -1;
		}

		struct zip_stat zstat;
		zip_stat_init(&zstat);
		if (zip_stat_index(archive->zip, zindex, 0, &zstat) != 0) {
			error("ERROR: zip_stat_index: %s\n", infile);
			ipsw_close(archive);
			return -1;
		}

		*size = zstat.size;
	} else {
		char *filepath = build_path(archive->path, infile);
		struct stat fst;
		if (stat(filepath, &fst) != 0) {
			free(filepath);
			ipsw_close(archive);
			return -1;
		}
		free(filepath);

		*size = fst.st_size;
	}

	ipsw_close(archive);
	return 0;
}

int ipsw_extract_to_file_with_progress(const char* ipsw, const char* infile, const char* outfile, int print_progress)
{
	int ret = 0;
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

	cancel_flag = 0;

	if (archive->zip) {
		int zindex = zip_name_locate(archive->zip, infile, 0);
		if (zindex < 0) {
			error("ERROR: zip_name_locate: %s\n", infile);
			return -1;
		}

		struct zip_stat zstat;
		zip_stat_init(&zstat);
		if (zip_stat_index(archive->zip, zindex, 0, &zstat) != 0) {
			error("ERROR: zip_stat_index: %s\n", infile);
			return -1;
		}

		char* buffer = (char*) malloc(BUFSIZE);
		if (buffer == NULL) {
			error("ERROR: Unable to allocate memory\n");
			return -1;
		}

		struct zip_file* zfile = zip_fopen_index(archive->zip, zindex, 0);
		if (zfile == NULL) {
			error("ERROR: zip_fopen_index: %s\n", infile);
			return -1;
		}

		FILE* fd = fopen(outfile, "wb");
		if (fd == NULL) {
			error("ERROR: Unable to open output file: %s\n", outfile);
			zip_fclose(zfile);
			return -1;
		}

		uint64_t i, bytes = 0;
		int count, size = BUFSIZE;
		double progress;
		for(i = zstat.size; i > 0; i -= count) {
			if (cancel_flag) {
				break;
			}
			if (i < BUFSIZE)
				size = i;
			count = zip_fread(zfile, buffer, size);
			if (count < 0) {
				error("ERROR: zip_fread: %s\n", infile);
				ret = -1;
				break;
			}
			if (fwrite(buffer, 1, count, fd) != count) {
				error("ERROR: frite: %s\n", outfile);
				ret = -1;
				break;
			}

			bytes += size;
			if (print_progress) {
				progress = ((double)bytes / (double)zstat.size) * 100.0;
				print_progress_bar(progress);
			}
		}
		free(buffer);
		fclose(fd);
		zip_fclose(zfile);
	} else {
		char *filepath = build_path(archive->path, infile);
		char actual_filepath[PATH_MAX+1];
		char actual_outfile[PATH_MAX+1];
		if (!realpath(filepath, actual_filepath)) {
			error("ERROR: realpath failed on %s: %s\n", filepath, strerror(errno));
			ret = -1;
			goto leave;
		} else {
			actual_outfile[0] = '\0';
			if (realpath(outfile, actual_outfile) && (strcmp(actual_filepath, actual_outfile) == 0)) {
				/* files are identical */
				ret = 0;
			} else {
				if (actual_outfile[0] == '\0') {
					strcpy(actual_outfile, outfile);
				}
				FILE *fi = fopen(actual_filepath, "rb");
				if (!fi) {
					error("ERROR: fopen: %s: %s\n", actual_filepath, strerror(errno));
					ret = -1;
					goto leave;
				}
				struct stat fst;
				if (fstat(fileno(fi), &fst) != 0) {
					fclose(fi);
					error("ERROR: fstat: %s: %s\n", actual_filepath, strerror(errno));
					ret = -1;
					goto leave;
				}
				FILE *fo = fopen(actual_outfile, "wb");
				if (!fo) {
					fclose(fi);
					error("ERROR: fopen: %s: %s\n", actual_outfile, strerror(errno));
					ret = -1;
					goto leave;
				}
				char* buffer = (char*) malloc(BUFSIZE);
				if (buffer == NULL) {
					fclose(fi);
					fclose(fo);
					error("ERROR: Unable to allocate memory\n");
					ret = -1;
					goto leave;;
				}

				uint64_t bytes = 0;
				double progress;
				while (!feof(fi)) {
					if (cancel_flag) {
						break;
					}
					ssize_t r = fread(buffer, 1, BUFSIZE, fi);
					if (r < 0) {
						error("ERROR: fread failed: %s\n", strerror(errno));
						ret = -1;
						break;
					}
					if (fwrite(buffer, 1, r, fo) != r) {
						error("ERROR: fwrite failed\n");
						ret = -1;
						break;
					}
					bytes += r;
					if (print_progress) {
						progress = ((double)bytes / (double)fst.st_size) * 100.0;
						print_progress_bar(progress);
					}
				}

				free(buffer);
				fclose(fi);
				fclose(fo);
			}
		}
	leave:
		free(filepath);
	}
	ipsw_close(archive);
	if (cancel_flag) {
		ret = -2;
	}
	return ret;
}

int ipsw_extract_to_file(const char* ipsw, const char* infile, const char* outfile)
{
	return ipsw_extract_to_file_with_progress(ipsw, infile, outfile, 0);
}

int ipsw_file_exists(const char* ipsw, const char* infile)
{
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL) {
		return 0;
	}

	if (archive->zip) {
		int zindex = zip_name_locate(archive->zip, infile, 0);
		if (zindex < 0) {
			ipsw_close(archive);
			return 0;
		}
	} else {
		char *filepath = build_path(archive->path, infile);
		if (access(filepath, R_OK) != 0) {
			free(filepath);
			ipsw_close(archive);
			return 0;
		}
		free(filepath);
	}

	ipsw_close(archive);

	return 1;
}

int ipsw_extract_to_memory(const char* ipsw, const char* infile, unsigned char** pbuffer, unsigned int* psize)
{
	size_t size = 0;
	unsigned char* buffer = NULL;
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

	if (archive->zip) {
		int zindex = zip_name_locate(archive->zip, infile, 0);
		if (zindex < 0) {
			debug("NOTE: zip_name_locate: '%s' not found in archive.\n", infile);
			ipsw_close(archive);
			return -1;
		}

		struct zip_stat zstat;
		zip_stat_init(&zstat);
		if (zip_stat_index(archive->zip, zindex, 0, &zstat) != 0) {
			error("ERROR: zip_stat_index: %s\n", infile);
			ipsw_close(archive);
			return -1;
		}

		struct zip_file* zfile = zip_fopen_index(archive->zip, zindex, 0);
		if (zfile == NULL) {
			error("ERROR: zip_fopen_index: %s\n", infile);
			ipsw_close(archive);
			return -1;
		}

		size = zstat.size;
		buffer = (unsigned char*) malloc(size+1);
		if (buffer == NULL) {
			error("ERROR: Out of memory\n");
			zip_fclose(zfile);
			ipsw_close(archive);
			return -1;
		}

		if (zip_fread(zfile, buffer, size) != size) {
			error("ERROR: zip_fread: %s\n", infile);
			zip_fclose(zfile);
			free(buffer);
			ipsw_close(archive);
			return -1;
		}

		buffer[size] = '\0';

		zip_fclose(zfile);
	} else {
		char *filepath = build_path(archive->path, infile);
		FILE *f = fopen(filepath, "rb");
		if (!f) {
			error("ERROR: %s: fopen failed for %s: %s\n", __func__, filepath, strerror(errno));
			free(filepath);
			ipsw_close(archive);
			return -2;
		}
		struct stat fst;
		if (fstat(fileno(f), &fst) != 0) {
			fclose(f);
			error("ERROR: %s: fstat failed for %s: %s\n", __func__, filepath, strerror(errno));
			free(filepath);
			ipsw_close(archive);
			return -1;
		}

		size = fst.st_size;
		buffer = (unsigned char*)malloc(size+1);
		if (buffer == NULL) {
			error("ERROR: Out of memory\n");
			fclose(f);
			free(filepath);
			ipsw_close(archive);
			return -1;
		}
		if (fread(buffer, 1, size, f) != size) {
			fclose(f);
			error("ERROR: %s: fread failed for %s: %s\n", __func__, filepath, strerror(errno));
			free(filepath);
			ipsw_close(archive);
			return -1;
		}
		buffer[size] = '\0';

		fclose(f);
		free(filepath);
	}
	ipsw_close(archive);

	*pbuffer = buffer;
	*psize = size;
	return 0;
}

int ipsw_extract_build_manifest(const char* ipsw, plist_t* buildmanifest, int *tss_enabled)
{
	unsigned int size = 0;
	unsigned char* data = NULL;

	*tss_enabled = 0;

	/* older devices don't require personalized firmwares and use a BuildManifesto.plist */
	if (ipsw_file_exists(ipsw, "BuildManifesto.plist")) {
		if (ipsw_extract_to_memory(ipsw, "BuildManifesto.plist", &data, &size) == 0) {
			plist_from_xml((char*)data, size, buildmanifest);
			free(data);
			return 0;
		}
	}

	data = NULL;
	size = 0;

	/* whereas newer devices do not require personalized firmwares and use a BuildManifest.plist */
	if (ipsw_extract_to_memory(ipsw, "BuildManifest.plist", &data, &size) == 0) {
		*tss_enabled = 1;
		plist_from_xml((char*)data, size, buildmanifest);
		free(data);
		return 0;
	}

	return -1;
}

int ipsw_extract_restore_plist(const char* ipsw, plist_t* restore_plist)
{
	unsigned int size = 0;
	unsigned char* data = NULL;

	if (ipsw_extract_to_memory(ipsw, "Restore.plist", &data, &size) == 0) {
		plist_from_xml((char*)data, size, restore_plist);
		free(data);
		return 0;
	}

	return -1;
}

void ipsw_close(ipsw_archive* archive)
{
	if (archive != NULL) {
		free(archive->path);
		if (archive->zip) {
			zip_unchange_all(archive->zip);
			zip_close(archive->zip);
		}
		free(archive);
	}
}

int ipsw_get_signed_firmwares(const char* product, plist_t* firmwares)
{
	char url[256];
	char *jdata = NULL;
	uint32_t jsize = 0;
	plist_t dict = NULL;
	plist_t node = NULL;
	plist_t fws = NULL;
	uint32_t count = 0;
	uint32_t i = 0;

	if (!product || !firmwares) {
		return -1;
	}

	*firmwares = NULL;
	snprintf(url, sizeof(url), "https://api.ipsw.me/v3/device/%s", product);

	if (download_to_buffer(url, &jdata, &jsize) < 0) {
		error("ERROR: Download from %s failed.\n", url);
		return -1;
	}
	dict = json_to_plist(jdata);
	free(jdata);
	if (!dict || plist_get_node_type(dict) != PLIST_DICT) {
		error("ERROR: Failed to parse json data.\n");
		plist_free(dict);
		return -1;
	}

	node = plist_dict_get_item(dict, product);
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unexpected json data returned?!\n");
		plist_free(dict);
		return -1;
	}
	fws = plist_dict_get_item(node, "firmwares");
	if (!fws || plist_get_node_type(fws) != PLIST_ARRAY) {
		error("ERROR: Unexpected json data returned?!\n");
		plist_free(dict);
		return -1;
	}

	*firmwares = plist_new_array();
	count = plist_array_get_size(fws);
	for (i = 0; i < count; i++) {
		plist_t fw = plist_array_get_item(fws, i);
		node = plist_dict_get_item(fw, "signed");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			uint8_t bv = 0;
			plist_get_bool_val(node, &bv);
			if (bv) {
				plist_array_append_item(*firmwares, plist_copy(fw));
			}
		}
	}
	plist_free(dict);

	return 0;
}

int ipsw_get_latest_fw(plist_t version_data, const char* product, char** fwurl, unsigned char* sha1buf)
{
	*fwurl = NULL;
	if (sha1buf != NULL) {
		memset(sha1buf, '\0', 20);
	}

	plist_t n1 = plist_dict_get_item(version_data, "MobileDeviceSoftwareVersionsByVersion");
	if (!n1) {
		error("%s: ERROR: Can't find MobileDeviceSoftwareVersionsByVersion dict in version data\n", __func__);
		return -1;
	}

	plist_dict_iter iter = NULL;
	plist_dict_new_iter(n1, &iter);
	if (!iter) {
		error("%s: ERROR: Can't get dict iter\n", __func__);
		return -1;
	}
	char* key = NULL;
	uint64_t major = 0;
	plist_t val = NULL;
	do {
		plist_dict_next_item(n1, iter, &key, &val);
		if (key) {
			plist_t pr = plist_access_path(n1, 3, key, "MobileDeviceSoftwareVersions", product);
			if (pr) {
				long long unsigned int v = strtoull(key, NULL, 10);
				if (v > major)
					major = v;
			}
			free(key);
		}
	} while (val);
	free(iter);

	if (major == 0) {
		error("%s: ERROR: Can't find major version?!\n", __func__);
		return -1;
	}

	char majstr[32]; // should be enough for a uint64_t value
	sprintf(majstr, "%"PRIu64, (uint64_t)major);
	n1 = plist_access_path(version_data, 7, "MobileDeviceSoftwareVersionsByVersion", majstr, "MobileDeviceSoftwareVersions", product, "Unknown", "Universal", "Restore");
	if (!n1) {
		error("%s: ERROR: Can't get Unknown/Universal/Restore node?!\n", __func__);
		return -1;
	}

	plist_t n2 = plist_dict_get_item(n1, "BuildVersion");
	if (!n2 || (plist_get_node_type(n2) != PLIST_STRING)) {
		error("%s: ERROR: Can't get build version node?!\n", __func__);
		return -1;
	}

	char* strval = NULL;
	plist_get_string_val(n2, &strval);

	n1 = plist_access_path(version_data, 5, "MobileDeviceSoftwareVersionsByVersion", majstr, "MobileDeviceSoftwareVersions", product, strval);
	if (!n1) {
		error("%s: ERROR: Can't get MobileDeviceSoftwareVersions/%s node?!\n", __func__, strval);
		free(strval);
		return -1;
	}
	free(strval);

	strval = NULL;
	n2 = plist_dict_get_item(n1, "SameAs");
	if (n2) {
		plist_get_string_val(n2, &strval);
	}
	if (strval) {
		n1 = plist_access_path(version_data, 5, "MobileDeviceSoftwareVersionsByVersion", majstr, "MobileDeviceSoftwareVersions", product, strval);
		free(strval);
		strval = NULL;
		if (!n1 || (plist_dict_get_size(n1) == 0)) {
			error("%s: ERROR: Can't get MobileDeviceSoftwareVersions/%s dict\n", __func__, product);
			return -1;
		}
	}

	n2 = plist_access_path(n1, 2, "Update", "BuildVersion");
	if (n2) {
		strval = NULL;
		plist_get_string_val(n2, &strval);
		if (strval) {
			n1 = plist_access_path(version_data, 5, "MobileDeviceSoftwareVersionsByVersion", majstr, "MobileDeviceSoftwareVersions", product, strval);
			free(strval);
			strval = NULL;
		}
	}

	n2 = plist_access_path(n1, 2, "Restore", "FirmwareURL");
	if (!n2 || (plist_get_node_type(n2) != PLIST_STRING)) {
		error("%s: ERROR: Can't get FirmwareURL node\n", __func__);
		return -1;
	}

	plist_get_string_val(n2, fwurl);

	if (sha1buf != NULL) {
		n2 = plist_access_path(n1, 2, "Restore", "FirmwareSHA1");
		if (n2 && plist_get_node_type(n2) == PLIST_STRING) {
			strval = NULL;
			plist_get_string_val(n2, &strval);
			if (strval) {
				if (strlen(strval) == 40) {
					int i;
					int v;
					for (i = 0; i < 40; i+=2) {
						v = 0;
						sscanf(strval+i, "%02x", &v);
						sha1buf[i/2] = (unsigned char)v;
					}
				}
				free(strval);
			}
		}
	}

	return 0;
}

static int sha1_verify_fp(FILE* f, unsigned char* expected_sha1)
{
	unsigned char tsha1[20];
	char buf[8192];
	if (!f) return 0;
	SHA_CTX sha1ctx;
	SHA1_Init(&sha1ctx);
	rewind(f);
	while (!feof(f)) {
		size_t sz = fread(buf, 1, 8192, f);
		SHA1_Update(&sha1ctx, (const void*)buf, sz);
	}
	SHA1_Final(tsha1, &sha1ctx);
	return (memcmp(expected_sha1, tsha1, 20) == 0) ? 1 : 0;
}

int ipsw_download_fw(const char *fwurl, unsigned char* isha1, const char* todir, char** ipswfile)
{
	char* fwfn = strrchr(fwurl, '/');
	if (!fwfn) {
		error("ERROR: can't get local filename for firmware ipsw\n");
		return -2;
	}
	fwfn++;

	char fwlfn[PATH_MAX - 5];
	if (todir) {
		sprintf(fwlfn, "%s/%s", todir, fwfn);
	} else {
		sprintf(fwlfn, "%s", fwfn);
	}

	char fwlock[PATH_MAX];
	sprintf(fwlock, "%s.lock", fwlfn);

	lock_info_t lockinfo;

	if (lock_file(fwlock, &lockinfo) != 0) {
		error("WARNING: Could not lock file '%s'\n", fwlock);
	}

	int need_dl = 0;
	unsigned char zsha1[20] = {0, };
	FILE* f = fopen(fwlfn, "rb");
	if (f) {
		if (memcmp(zsha1, isha1, 20) != 0) {
			info("Verifying '%s'...\n", fwlfn);
			if (sha1_verify_fp(f, isha1)) {
				info("Checksum matches.\n");
			} else {
				info("Checksum does not match.\n");
				need_dl = 1;
			}
		}
		fclose(f);
	} else {
		need_dl = 1;
	}

	int res = 0;
	if (need_dl) {
		if (strncmp(fwurl, "protected:", 10) == 0) {
			error("ERROR: Can't download '%s' because it needs a purchase.\n", fwfn);
			res = -3;
		} else {
			remove(fwlfn);
			info("Downloading firmware (%s)\n", fwurl);
			download_to_file(fwurl, fwlfn, 1);
			if (memcmp(isha1, zsha1, 20) != 0) {
				info("\nVerifying '%s'...\n", fwlfn);
				FILE* f = fopen(fwlfn, "rb");
				if (f) {
					if (sha1_verify_fp(f, isha1)) {
						info("Checksum matches.\n");
					} else {
						error("ERROR: File download failed (checksum mismatch).\n");
						res = -4;
					}
					fclose(f);

					// make sure to remove invalid files
					if (res < 0)
						remove(fwlfn);
				} else {
					error("ERROR: Can't open '%s' for checksum verification\n", fwlfn);
					res = -5;
				}
			}
		}
	}
	if (res == 0) {
		*ipswfile = strdup(fwlfn);
	}

	if (unlock_file(&lockinfo) != 0) {
		error("WARNING: Could not unlock file '%s'\n", fwlock);
	}

	return res;
}

int ipsw_download_latest_fw(plist_t version_data, const char* product, const char* todir, char** ipswfile)
{
	char* fwurl = NULL;
	unsigned char isha1[20];

	*ipswfile = NULL;

	if ((ipsw_get_latest_fw(version_data, product, &fwurl, isha1) < 0) || !fwurl) {
		error("ERROR: can't get URL for latest firmware\n");
		return -1;
	}
	char* fwfn = strrchr(fwurl, '/');
	if (!fwfn) {
		error("ERROR: can't get local filename for firmware ipsw\n");
		return -2;
	}
	fwfn++;

	info("Latest firmware is %s\n", fwfn);

	int res = ipsw_download_fw(fwurl, isha1, todir, ipswfile);

	free(fwurl);

	return res;
}

void ipsw_cancel(void)
{
	cancel_flag++;
}
