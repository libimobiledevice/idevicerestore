/*
 * ipsw.h
 * Definitions for IPSW utilities
 *
 * Copyright (c) 2012-2019 Nikias Bassen. All Rights Reserved.
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

#include <stdint.h>
#include <plist/plist.h>

int ipsw_is_directory(const char* ipsw);
int ipsw_file_exists(const char* ipsw, const char* infile);
int ipsw_get_file_size(const char* ipsw, const char* infile, uint64_t* size);
int ipsw_extract_to_file(const char* ipsw, const char* infile, const char* outfile);
int ipsw_extract_to_file_with_progress(const char* ipsw, const char* infile, const char* outfile, int print_progress);
int ipsw_extract_to_memory(const char* ipsw, const char* infile, unsigned char** pbuffer, unsigned int* psize);
int ipsw_extract_build_manifest(const char* ipsw, plist_t* buildmanifest, int *tss_enabled);
int ipsw_extract_restore_plist(const char* ipsw, plist_t* restore_plist);

int ipsw_get_signed_firmwares(const char* product, plist_t* firmwares);
int ipsw_download_fw(const char *fwurl, unsigned char* isha1, const char* todir, char** ipswfile);

int ipsw_get_latest_fw(plist_t version_data, const char* product, char** fwurl, unsigned char* sha1buf);
int ipsw_download_latest_fw(plist_t version_data, const char* product, const char* todir, char** ipswfile);

void ipsw_cancel(void);

#ifdef __cplusplus
}
#endif

#endif
