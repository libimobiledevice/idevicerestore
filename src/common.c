/*
 * common.c
 * Misc functions used in idevicerestore
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
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
#include <libgen.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#ifdef WIN32
#include <windows.h>
#include <conio.h>
#ifndef _O_EXCL
#define _O_EXCL  0x0400
#endif
#ifndef O_EXCL
#define O_EXCL   _O_EXCL
#endif
#else
#include <sys/time.h>
#include <pthread.h>
#include <termios.h>
#endif

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
	struct stat fst;

	debug("Reading data from %s\n", filename);

	*size = 0;
	*data = NULL;

	file = fopen(filename, "rb");
	if (file == NULL) {
		error("read_file: cannot open %s: %s\n", filename, strerror(errno));
		return -1;
	}

	if (fstat(fileno(file), &fst) < 0) {
		error("read_file: fstat: %s\n", strerror(errno));
		return -1;
	}
	length = fst.st_size;

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

#ifndef HAVE_MKSTEMP
/* Based on libc's __gen_tempname() from sysdeps/posix/tempname.c
   Copyright (C) 1991-2018 Free Software Foundation, Inc.
   With changes from https://stackoverflow.com/a/6036308 and some
   additional changes. */
int mkstemp(char *tmpl)
{
	static const char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	int len;
	char *XXXXXX;
	static unsigned long long value;
	unsigned long long random_time_bits;
	unsigned int count;
	int fd = -1;
	int save_errno = errno;

	/* A lower bound on the number of temporary files to attempt to
	   generate.  The maximum total number of temporary file names that
	   can exist for a given template is 62**6.  It should never be
	   necessary to try all these combinations.  Instead if a reasonable
	   number of names is tried (we define reasonable as 62**3) fail to
	   give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)

	/* The number of times to attempt to generate a temporary file.  To
	   conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
	unsigned int attempts = TMP_MAX;
#else
	unsigned int attempts = ATTEMPTS_MIN;
#endif

	len = strlen (tmpl);
	if (len < 6 || strcmp (&tmpl[len - 6], "XXXXXX"))
	{
		errno = EINVAL;
		return -1;
	}

	/* This is where the Xs start.  */
	XXXXXX = &tmpl[len - 6];

	/* Get some more or less random data.  */
#ifdef WIN32
	{
		SYSTEMTIME stNow;
		FILETIME ftNow;

		// get system time
		GetSystemTime(&stNow);
		if (!SystemTimeToFileTime(&stNow, &ftNow))
		{
			errno = -1;
			return -1;
		}

		random_time_bits = (((unsigned long long)ftNow.dwHighDateTime << 32)
		                    | (unsigned long long)ftNow.dwLowDateTime);
	}
	value += random_time_bits ^ ((unsigned long long)GetCurrentProcessId() << 32 | (unsigned long long)GetCurrentThreadId());
#else
	{
		struct timeval tvNow = {0, 0};
		gettimeofday(&tvNow, NULL);
		random_time_bits = (((unsigned long long)tvNow.tv_sec << 32)
		                    | (unsigned long long)tvNow.tv_usec);
	}
	value += random_time_bits ^ ((unsigned long long)getpid() << 32 | (unsigned long long)(uintptr_t)pthread_self());
#endif

	for (count = 0; count < attempts; value += 7777, ++count)
	{
		unsigned long long v = value;

		/* Fill in the random bits.  */
		XXXXXX[0] = letters[v % 62];
		v /= 62;
		XXXXXX[1] = letters[v % 62];
		v /= 62;
		XXXXXX[2] = letters[v % 62];
		v /= 62;
		XXXXXX[3] = letters[v % 62];
		v /= 62;
		XXXXXX[4] = letters[v % 62];
		v /= 62;
		XXXXXX[5] = letters[v % 62];

#ifdef WIN32
		fd = open (tmpl, O_RDWR | O_CREAT | O_EXCL, _S_IREAD | _S_IWRITE);
#else
		fd = open (tmpl, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
		if (fd >= 0)
		{
			errno = save_errno;
			return fd;
		}
		else if (errno != EEXIST)
			return -1;
	}

	/* We got out of the loop because we ran out of combinations to try.  */
	errno = EEXIST;
	return -1;
}
#endif

char *get_temp_filename(const char *prefix)
{
	char *result = NULL;
	char *tmpdir;
	size_t lt;
	size_t lp;
	const char *TMPVARS[] = { "TMPDIR", "TMP", "TEMP", "TEMPDIR", NULL };
	int i = 0;
	int fd;

	/* check the prefix parameter */
	if (!prefix) {
		prefix = "tmp_";
	}
#ifdef WIN32
	if (strchr(prefix, '/') || strchr(prefix, '\\')) return NULL;
#else
	if (strchr(prefix, '/')) return NULL;
#endif

	while (TMPVARS[i] && ((tmpdir = getenv(TMPVARS[i])) == NULL)) i++;
	if (!tmpdir || access(tmpdir, W_OK|X_OK) != 0) {
#ifdef WIN32
		tmpdir = "C:\\WINDOWS\\TEMP";
#else
		tmpdir = P_tmpdir;
#endif
	}
	if (!tmpdir || access(tmpdir, W_OK|X_OK) != 0) {
		return NULL;
	}

	lt = strlen(tmpdir);
	if (lt < 1) {
		return NULL;
	}
	lp = strlen(prefix);
	result = malloc(lt + lp + 8);
	strncpy(result, tmpdir, lt);
#ifdef WIN32
	if (tmpdir[lt-1] != '/' && tmpdir[lt-1] != '\\') result[lt++] = '\\';
#else
	if (tmpdir[lt-1] != '/') result[lt++] = '/';
#endif
	strncpy(result + lt, prefix, lp);
	strcpy(result + lt + lp, "XXXXXX");
	fd = mkstemp(result);
	if (fd < 0) {
		free(result);
		result = NULL;
	}
	close(fd);
	return result;
}

void idevicerestore_progress(struct idevicerestore_client_t* client, int step, double progress)
{
	if(client && client->progress_cb) {
		client->progress_cb(step, progress, client->progress_cb_data);
	} else {
		// we don't want to be too verbose in regular idevicerestore.
		if ((step == RESTORE_STEP_UPLOAD_FS) || (step == RESTORE_STEP_VERIFY_FS) || (step == RESTORE_STEP_FLASH_FW)) {
			print_progress_bar(100.0f * progress);
		}
	}
}

#ifndef HAVE_STRSEP
char* strsep(char** strp, const char* delim)
{
        char *p, *s;
        if (strp == NULL || *strp == NULL || **strp == '\0') return NULL;
        s = *strp;
        p = s + strcspn(s, delim);
        if (*p != '\0') *p++ = '\0';
        *strp = p;
        return s;
}
#endif

#ifndef HAVE_REALPATH
char* realpath(const char *filename, char *resolved_name)
{
#ifdef WIN32
	if (access(filename, F_OK) != 0) {
		return NULL;
	}
	if (GetFullPathName(filename, MAX_PATH, resolved_name, NULL) == 0) {
		return NULL;
	}
	return resolved_name;
#else
#error please provide a realpath implementation for this platform
	return NULL;
#endif
}
#endif

#ifdef WIN32
#define BS_CC '\b'
#define my_getch getch
#else
#define BS_CC 0x7f
static int my_getch(void)
{
	struct termios oldt, newt;
	int ch;
	tcgetattr(STDIN_FILENO, &oldt);
	newt = oldt;
	newt.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &newt);
	ch = getchar();
	tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
	return ch;
}
#endif

void get_user_input(char *buf, int maxlen, int secure)
{
	int len = 0;
	int c;

	while ((c = my_getch()) > 0) {
		if ((c == '\r') || (c == '\n')) {
			break;
		} else if (isprint(c)) {
			if (len < maxlen-1)
				buf[len++] = c;
			fputc((secure) ? '*' : c, stdout);
		} else if (c == BS_CC) {
			if (len > 0) {
				fputs("\b \b", stdout);
				len--;
			}
		}
	}
	if (c < 0) {
		len = 0;
	}
	fputs("\n", stdout);
	buf[len] = 0;
}
