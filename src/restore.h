/*
 * restore.h
 * Functions for handling idevices in restore mode
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

#ifndef IDEVICERESTORE_RESTORE_H
#define IDEVICERESTORE_RESTORE_H

#include <plist/plist.h>
#include <libimobiledevice/restore.h>
#include <libimobiledevice/libimobiledevice.h>

int restore_check_mode(const char* uuid);
const char* restore_progress_string(unsigned int operation);
void restore_close(idevice_t device, restored_client_t restore);
int restore_handle_status_msg(restored_client_t client, plist_t msg);
int restore_handle_progress_msg(restored_client_t client, plist_t msg);
int restore_send_nor(restored_client_t client, const char* ipsw, plist_t tss);
int restore_send_kernelcache(restored_client_t client, char *kernel_data, int len);
int restore_device(const char* uuid, const char* ipsw, plist_t tss, const char* filesystem);
int restore_open_with_timeout(const char* uuid, idevice_t* device, restored_client_t* client);
int restore_send_filesystem(idevice_t device, restored_client_t client, const char *filesystem);

#endif
