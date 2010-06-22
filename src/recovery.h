/*
 * recovery.h
 * Functions for handling idevices in recovery mode
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

#ifndef RECOVERY_H
#define RECOVERY_H

#include <stdint.h>
#include <plist/plist.h>

int recovery_send_signed_component(irecv_client_t client, char* ipsw, plist_t tss, char* component);
irecv_error_t recovery_open_with_timeout(irecv_client_t* client);
int recovery_send_ibec(char* ipsw, plist_t tss);
int recovery_send_applelogo(char* ipsw, plist_t tss);
int recovery_send_devicetree(char* ipsw, plist_t tss);
int recovery_send_ramdisk(char* ipsw, plist_t tss);
int recovery_send_kernelcache(char* ipsw, plist_t tss);
int recovery_get_ecid(uint64_t* ecid);

#endif
