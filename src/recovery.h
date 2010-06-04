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

#ifndef IDEVICERESTORE_RECOVERY_H
#define IDEVICERESTORE_RECOVERY_H

#include <stdint.h>
#include <plist/plist.h>

int recovery_check_mode();
int recovery_enter_restore(const char* ipsw, plist_t tss);
int recovery_send_signed_component(irecv_client_t client, const char* ipsw, plist_t tss, char* component);
irecv_error_t recovery_open_with_timeout(irecv_client_t* client);
int recovery_send_ibec(const char* ipsw, plist_t tss);
int recovery_send_applelogo(const char* ipsw, plist_t tss);
int recovery_send_devicetree(const char* ipsw, plist_t tss);
int recovery_send_ramdisk(const char* ipsw, plist_t tss);
int recovery_send_kernelcache(const char* ipsw, plist_t tss);
int recovery_get_ecid(uint64_t* ecid);
int recovery_get_cpid(uint32_t* cpid);
int recovery_get_bdid(uint32_t* bdid);

#endif
