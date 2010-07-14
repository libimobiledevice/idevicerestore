/*
 * ipsw.h
 * Utilities for extracting and manipulating IPSWs
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

#include <zip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipsw.h"
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

int ipsw_extract_to_file(const char* ipsw, const char* infile, const char* outfile) {
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

	int i = 0;
	int size = 0;
	int bytes = 0;
	int count = 0;
	double progress = 0;
	for(i = zstat.size; i > 0; i -= count) {
		if (i < BUFSIZE)
			size = i;
		else
			size = BUFSIZE;
		count = zip_fread(zfile, buffer, size);
		if (count < 0) {
			error("ERROR: zip_fread: %s\n", infile);
			zip_fclose(zfile);
			free(buffer);
			return -1;
		}
		fwrite(buffer, 1, count, fd);

		bytes += size;
		progress = ((double) bytes/ (double) zstat.size) * 100.0;
		print_progress_bar(progress);
	}

	fclose(fd);
	zip_fclose(zfile);
	ipsw_close(archive);
	free(buffer);
	return 0;
}

int ipsw_extract_to_memory(const char* ipsw, const char* infile, char** pbuffer, uint32_t* psize) {
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
	char* buffer = (unsigned char*) malloc(size);
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

	zip_fclose(zfile);
	ipsw_close(archive);

	*pbuffer = buffer;
	*psize = size;
	return 0;
}

int ipsw_extract_build_manifest(const char* ipsw, plist_t* buildmanifest, int *tss_enabled) {
	int size = 0;
	char* data = NULL;

	*tss_enabled = 0;

	/* older devices don't require personalized firmwares and use a BuildManifesto.plist */
	if (ipsw_extract_to_memory(ipsw, "BuildManifesto.plist", &data, &size) == 0) {
		plist_from_xml(data, size, buildmanifest);
		return 0;
	}

	data = NULL;
	size = 0;

	/* whereas newer devices do not require personalized firmwares and use a BuildManifest.plist */
	if (ipsw_extract_to_memory(ipsw, "BuildManifest.plist", &data, &size) == 0) {
		*tss_enabled = 1;
		plist_from_xml(data, size, buildmanifest);
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
