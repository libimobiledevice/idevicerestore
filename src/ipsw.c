/*
 * ipsw.c
 * Utilities for extracting and manipulating IPSWs
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

#include <zip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "ipsw.h"
#include "locking.h"
#include "download.h"
#include "common.h"
#include "idevicerestore.h"

#define BUFSIZE 0x100000

typedef struct {
	struct zip* zip;
} ipsw_archive;

ipsw_archive* ipsw_open(const char* ipsw);
void ipsw_close(ipsw_archive* archive);

ipsw_archive* ipsw_open(const char* ipsw) {
	int err = 0;
	ipsw_archive* archive = (ipsw_archive*) malloc(sizeof(ipsw_archive));
	if (archive == NULL) {
		error("ERROR: Out of memory\n");
		return NULL;
	}

	archive->zip = zip_open(ipsw, 0, &err);
	if (archive->zip == NULL) {
		error("ERROR: zip_open: %s: %d\n", ipsw, err);
		free(archive);
		return NULL;
	}

	return archive;
}

int ipsw_get_file_size(const char* ipsw, const char* infile, off_t* size) {
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL || archive->zip == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

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

	*size = zstat.size;

	ipsw_close(archive);
	return 0;
}

int ipsw_extract_to_file(const char* ipsw, const char* infile, const char* outfile) {
	int ret = 0;
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL || archive->zip == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

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

	off_t i, bytes = 0;
	int count, size = BUFSIZE;
	double progress;
	for(i = zstat.size; i > 0; i -= count) {
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
		progress = ((double)bytes / (double)zstat.size) * 100.0;
		print_progress_bar(progress);
	}

	fclose(fd);
	zip_fclose(zfile);
	ipsw_close(archive);
	free(buffer);
	return ret;
}

int ipsw_file_exists(const char* ipsw, const char* infile)
{
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL || archive->zip == NULL) {
		return -1;
	}

	int zindex = zip_name_locate(archive->zip, infile, 0);
	if (zindex < 0) {
		ipsw_close(archive);
		return -2;
	}

	ipsw_close(archive);

	return 0;
}

int ipsw_extract_to_memory(const char* ipsw, const char* infile, unsigned char** pbuffer, unsigned int* psize) {
	ipsw_archive* archive = ipsw_open(ipsw);
	if (archive == NULL || archive->zip == NULL) {
		error("ERROR: Invalid archive\n");
		return -1;
	}

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

	struct zip_file* zfile = zip_fopen_index(archive->zip, zindex, 0);
	if (zfile == NULL) {
		error("ERROR: zip_fopen_index: %s\n", infile);
		return -1;
	}

	int size = zstat.size;
	unsigned char* buffer = (unsigned char*) malloc(size+1);
	if (buffer == NULL) {
		error("ERROR: Out of memory\n");
		zip_fclose(zfile);
		return -1;
	}

	if (zip_fread(zfile, buffer, size) != size) {
		error("ERROR: zip_fread: %s\n", infile);
		zip_fclose(zfile);
		free(buffer);
		return -1;
	}

	buffer[size] = '\0';

	zip_fclose(zfile);
	ipsw_close(archive);

	*pbuffer = buffer;
	*psize = size;
	return 0;
}

int ipsw_extract_build_manifest(const char* ipsw, plist_t* buildmanifest, int *tss_enabled) {
	unsigned int size = 0;
	unsigned char* data = NULL;

	*tss_enabled = 0;

	/* older devices don't require personalized firmwares and use a BuildManifesto.plist */
	if (ipsw_file_exists(ipsw, "BuildManifesto.plist") == 0) {
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

int ipsw_extract_restore_plist(const char* ipsw, plist_t* restore_plist) {
	unsigned int size = 0;
	unsigned char* data = NULL;

	if (ipsw_extract_to_memory(ipsw, "Restore.plist", &data, &size) == 0) {
		plist_from_xml((char*)data, size, restore_plist);
		free(data);
		return 0;
	}

	return -1;
}

void ipsw_close(ipsw_archive* archive) {
	if (archive != NULL) {
		zip_unchange_all(archive->zip);
		zip_close(archive->zip);
		free(archive);
	}
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
	long long unsigned int major = 0;
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
	sprintf(majstr, FMT_qu, (long long unsigned int)major);
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

	char fwlfn[256];
	if (todir) {
		sprintf(fwlfn, "%s/%s", todir, fwfn);
	} else {
		sprintf(fwlfn, "%s", fwfn);
	}

	char fwlock[256];
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
			info("Downloading latest firmware (%s)\n", fwurl);
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
	free(fwurl);
	if (res == 0) {
		*ipswfile = strdup(fwlfn);
	}

	if (unlock_file(&lockinfo) != 0) {
		error("WARNING: Could not unlock file '%s'\n", fwlock);
	}

	return res;
}
