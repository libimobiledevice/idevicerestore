/*
 * ipsw.c
 * Definitions for communicating with Apple's TSS server.
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

#ifndef IDEVICERESTORE_TSS_H
#define IDEVICERESTORE_TSS_H

#include <plist/plist.h>

#include "img3.h"

plist_t tss_create_request(plist_t build_identity, uint64_t ecid);
plist_t tss_send_request(plist_t tss_request);
void tss_stitch_img3(img3_file* file, plist_t signature);

#endif
