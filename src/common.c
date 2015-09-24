/*
 * common.c
 * Misc functions used in idevicerestore
 *
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
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
#include <errno.h>
#include <libgen.h>
#include <time.h>

#include "common.h"

#define MAX_PRINT_LEN 64*1024

struct idevicerestore_mode_t idevicerestore_modes[] = {
	{  0, "WTF"      },
	{  1, "DFU"      },
	{  2, "Recovery" },
	{  3, "Restore"  },
	{  4, "Normal"   },
	{ -1,  NULL      }
};

int idevicerestore_debug = 0;

#define idevicerestore_err_buff_size 256
static char idevicerestore_err_buff[idevicerestore_err_buff_size] = {0, };

static FILE* info_stream = NULL;
static FILE* error_stream = NULL;
static FILE* debug_stream = NULL;

static int info_disabled = 0;
static int error_disabled = 0;
static int debug_disabled = 0;

void info(const char* format, ...)
{
	if (info_disabled) return;
	va_list vargs;
	va_start(vargs, format);
	vfprintf((info_stream) ? info_stream : stdout, format, vargs);
	va_end(vargs);
}

void error(const char* format, ...)
{
	va_list vargs, vargs2;
	va_start(vargs, format);
	va_copy(vargs2, vargs);
	vsnprintf(idevicerestore_err_buff, idevicerestore_err_buff_size, format, vargs);
	va_end(vargs);
	if (!error_disabled) {
		vfprintf((error_stream) ? error_stream : stderr, format, vargs2);
	}
	va_end(vargs2);
}

void debug(const char* format, ...)
{
	if (debug_disabled) return;
	if (!idevicerestore_debug) {
		return;
	}
	va_list vargs;
	va_start(vargs, format);
	vfprintf((debug_stream) ? debug_stream : stderr, format, vargs);
	va_end(vargs);
}

void idevicerestore_set_info_stream(FILE* strm)
{
	if (strm) {
		info_disabled = 0;
		info_stream = strm;
	} else {
		info_disabled = 1;
	}
}

void idevicerestore_set_error_stream(FILE* strm)
{
	if (strm) {
		error_disabled = 0;
		error_stream = strm;
	} else {
		error_disabled = 1;
	}
}

void idevicerestore_set_debug_stream(FILE* strm)
{
	if (strm) {
		debug_disabled = 0;
		debug_stream = strm;
	} else {
		debug_disabled = 1;
	}
}

const char* idevicerestore_get_error(void)
{
	if (idevicerestore_err_buff[0] == 0) {
		return NULL;
	} else {
		char* p = NULL;
		while ((strlen(idevicerestore_err_buff) > 0) && (p = strrchr(idevicerestore_err_buff, '\n'))) {
			p[0] = '\0';
		}
		return (const char*)idevicerestore_err_buff;
	}
}

int write_file(const char* filename, const void* data, size_t size) {
	size_t bytes = 0;
	FILE* file = NULL;

	debug("Writing data to %s\n", filename);
	file = fopen(filename, "wb");
	if (file == NULL) {
		error("write_file: Unable to open file %s\n", filename);
		return -1;
	}

	bytes = fwrite(data, 1, size, file);
	fclose(file);

	if (bytes != size) {
		error("ERROR: Unable to write entire file: %s: %d of %d\n", filename, (int)bytes, (int)size);
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

	fseeko(file, 0, SEEK_END);
	length = ftello(file);
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
	uint32_t size = 0;
	char* data = NULL;
	plist_to_xml(plist, &data, &size);
	if (size <= MAX_PRINT_LEN)
		info("%s:printing %i bytes plist:\n%s", __FILE__, size, data);
	else
		info("%s:supressed printing %i bytes plist...\n", __FILE__, size);
	free(data);
}

void print_progress_bar(double progress) {
#ifndef WIN32
	if (info_disabled) return;
	int i = 0;
	if(progress < 0) return;
	if(progress > 100) progress = 100;
	info("\r[");
	for(i = 0; i < 50; i++) {
		if(i < progress / 2) info("=");
		else info(" ");
	}
	info("] %5.1f%%", progress);
	if(progress == 100) info("\n");
	fflush((info_stream) ? info_stream : stdout);
#endif
}

#define GET_RAND(min, max) ((rand() % (max - min)) + min)

char *generate_guid(void)
{
	char *guid = (char *) malloc(sizeof(char) * 37);
	const char *chars = "ABCDEF0123456789";
	srand(time(NULL));
	int i = 0;

	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			guid[i] = '-';
			continue;
		} else {
			guid[i] = chars[GET_RAND(0, 16)];
		}
	}
	guid[36] = '\0';
	return guid;
}

int mkdir_with_parents(const char *dir, int mode)
{
	if (!dir) return -1;
	if (__mkdir(dir, mode) == 0) {
		return 0;
	} else {
		if (errno == EEXIST) {
			return 0;
		} else if (errno == ENOENT) {
			// ignore
		} else {
			return -1;
		}
	}
	int res;
	char *parent = strdup(dir);
	char *parentdir = dirname(parent);
	if (parentdir && (strcmp(parentdir, ".") != 0) && (strcmp(parentdir, dir) != 0)) {
		res = mkdir_with_parents(parentdir, mode);
	} else {
		res = -1;	
	}
	free(parent);
	if (res == 0) {
		mkdir_with_parents(dir, mode);
	}
	return res;
}

void idevicerestore_progress(struct idevicerestore_client_t* client, int step, double progress)
{
	if(client && client->progress_cb) {
		client->progress_cb(step, progress, client->progress_cb_data);
	} else {
		// we don't want to be too verbose in regular idevicerestore.
		if ((step == RESTORE_STEP_UPLOAD_FS) || (step == RESTORE_STEP_FLASH_FS) || (step == RESTORE_STEP_FLASH_FW)) {
			print_progress_bar(100.0f * progress);
		}
	}
}
