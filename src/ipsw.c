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
#include <stdlib.h>
#include <string.h>
#include "ipsw.h"

ipsw_archive* ipsw_open(const char* ipsw) {
	int err = 0;
	ipsw_archive* archive = (ipsw_archive*) malloc(sizeof(ipsw_archive));
	if(archive == NULL) {
		error("ERROR: Out of memory\n");
		return NULL;
	}

	archive->zip = zip_open(ipsw, 0, &err);
	if(archive->zip == NULL) {
		error("ERROR: zip_open: %s: %d\n", ipsw, err);
		free(archive);
		return NULL;
	}

	return archive;
}

ipsw_file* ipsw_extract_file(ipsw_archive* archive, const char* filename) {
	if(archive == NULL || archive->zip == NULL) {
		error("ERROR: Invalid archive\n");
		return NULL;
	}

	int zindex = zip_name_locate(archive->zip, filename, 0);
	if(zindex < 0) {
		error("ERROR: zip_name_locate: %s\n", filename);
		return NULL;
	}

	struct zip_stat zstat;
	zip_stat_init(&zstat);
	if(zip_stat_index(archive->zip, zindex, 0, &zstat) != 0) {
		error("ERROR: zip_stat_index: %s\n", filename);
		return NULL;
	}

	struct zip_file* zfile = zip_fopen_index(archive->zip, zindex, 0);
	if(zfile == NULL) {
		error("ERROR: zip_fopen_index: %s\n", filename);
		return NULL;
	}

	ipsw_file* file = (ipsw_file*) malloc(sizeof(ipsw_file));
	if(file == NULL) {
		error("ERROR: Out of memory\n");
		zip_fclose(zfile);
		return NULL;
	}

	file->size = zstat.size;
	file->index = zstat.index;
	file->name = strdup(zstat.name);
	file->data = (unsigned char*) malloc(file->size);
	if(file->data == NULL) {
		error("ERROR: Out of memory\n");
		ipsw_free_file(file);
		zip_fclose(zfile);
		return NULL;
	}

	if(zip_fread(zfile, file->data, file->size) != file->size) {
		error("ERROR: zip_fread: %s\n", filename);
		ipsw_free_file(file);
		zip_fclose(zfile);
		return NULL;
	}

	zip_fclose(zfile);
	return file;
}

void ipsw_free_file(ipsw_file* file) {
	if(file != NULL) {
		if(file->name != NULL) {
			free(file->name);
		}
		if(file->data != NULL) {
			free(file->data);
		}
		free(file);
	}
}

void ipsw_close(ipsw_archive* archive) {
	if(archive != NULL) {
		zip_unchange_all(archive->zip);
		zip_close(archive->zip);
		free(archive);
	}
}
