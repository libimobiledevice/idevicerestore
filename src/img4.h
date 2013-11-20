/*
 * img4.h
 * Functions for handling the new IMG4 format
 *
 * Copyright (c) 2013 Nikias Bassen. All Rights Reserved.
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

#ifndef IDEVICERESTORE_IMG4_H
#define IDEVICERESTORE_IMG4_H

#ifdef __cplusplus
extern "C" {
#endif

int img4_stitch_component(const char* component_name, const unsigned char* component_data, unsigned int component_size, const unsigned char* blob, unsigned int blob_size, unsigned char** img4_data, unsigned int *img4_size);

#ifdef __cplusplus
}s
#endif

#endif
