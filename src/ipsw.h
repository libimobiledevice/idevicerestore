/*
 * ipsw.h
 * Definitions for IPSW utilities
 *
 * Copyright (c) 2012 Nikias Bassen. All Rights Reserved.
 * Copyright (c) 2010 Martin Szulecki. All Rights Reserved.
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

#ifndef IDEVICERESTORE_IPSW_H
#define IDEVICERESTORE_IPSW_H

#ifdef __cplusplus
extern "C" {
#endif

#include <zip.h>
#include <stdint.h>
#include <plist/plist.h>

typedef struct {
	int index;
	char* name;
	unsigned int size;
	unsigned char* data;
} ipsw_file;

int ipsw_get_file_size(const char* ipsw, const char* infile, off_t* size);
int ipsw_extract_to_file(const char* ipsw, const char* infile, const char* outfile);
int ipsw_extract_to_memory(const char* ipsw, const char* infile, unsigned char** pbuffer, unsigned int* psize);
int ipsw_extract_build_manifest(const char* ipsw, plist_t* buildmanifest, int *tss_enabled);
int ipsw_extract_restore_plist(const char* ipsw, plist_t* restore_plist);
void ipsw_free_file(ipsw_file* file);

int ipsw_get_latest_fw(plist_t version_data, const char* product, char** fwurl, unsigned char* sha1buf);
int ipsw_download_latest_fw(plist_t version_data, const char* product, const char* todir, char** ipswfile);

#ifdef __cplusplus
}
#endif

#endif
