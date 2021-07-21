/*
 * download.h
 * file download helper functions (header file)
 *
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen. All Rights Reserved.
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
#ifndef IDEVICERESTORE_DOWNLOAD_H
#define IDEVICERESTORE_DOWNLOAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int download_to_buffer(const char* url, char** buf, uint32_t* length);
int download_to_file(const char* url, const char* filename, int enable_progress);
int download_firmware_component_to_path(char* ipsw_url, char* component_path, char* out_path);
int download_firmware_component(char* ipsw_url, char* component_path, char** out_buf, size_t* component_len);

#ifdef __cplusplus
}
#endif

#endif
