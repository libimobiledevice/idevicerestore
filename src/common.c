/*
 * common.c
 * Misc functions used in idevicerestore
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

#include "common.h"

int idevicerestore_debug = 0;

int write_file(const char* filename, const void* data, size_t size) {
	size_t bytes = 0;
	FILE* file = NULL;

	debug("Writing data to %s\n", filename);
	file = fopen(filename, "wb");
	if (file == NULL) {
		error("read_file: Unable to open file %s\n", filename);
		return -1;
	}

	bytes = fwrite(data, 1, size, file);
	fclose(file);

	if (bytes != size) {
		error("ERROR: Unable to write entire file: %s: %d of %d\n", filename, bytes, size);
		return -1;
	}

	return size;
}

int read_file(const char* filename, void** data, size_t* size) {
	size_t bytes = 0;
	size_t length = 0;
	FILE* file = NULL;
	char* buffer = NULL;
	debug("Reading data from %s\n", filename);

	*size = 0;
	*data = NULL;

	file = fopen(filename, "rb");
	if (file == NULL) {
		error("read_file: File %s not found\n", filename);
		return -1;
	}

	fseek(file, 0, SEEK_END);
	length = ftell(file);
	rewind(file);

	buffer = (char*) malloc(length);
	if (buffer == NULL) {
		error("ERROR: Out of memory\n");
		fclose(file);
		return -1;
	}
	bytes = fread(buffer, 1, length, file);
	fclose(file);

	if (bytes != length) {
		error("ERROR: Unable to read entire file\n");
		free(buffer);
		return -1;
	}

	*size = length;
	*data = buffer;
	return 0;
}

void debug_plist(plist_t plist) {
	int size = 0;
	char* data = NULL;
	plist_to_xml(plist, &data, &size);
	info("%s", data);
	free(data);
}

void print_progress_bar(double progress) {
	int i = 0;
	if(progress < 0) return;
	if(progress > 100) progress = 100;
	info("\r[");
	for(i = 0; i < 50; i++) {
		if(i < progress / 2) info("=");
		else info(" ");
	}
	info("] %3.1f%%", progress);
	if(progress == 100) info("\n");
	fflush(stdout);
}
