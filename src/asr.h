/*
 * asr.h
 * Functions for handling asr connections
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

#ifndef IDEVICERESTORE_ASR_H
#define IDEVICERESTORE_ASR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libimobiledevice/libimobiledevice.h>

int asr_open_with_timeout(idevice_t device, idevice_connection_t* asr);
int asr_send(idevice_connection_t asr, plist_t* data);
int asr_receive(idevice_connection_t asr, plist_t* data);
int asr_send_buffer(idevice_connection_t asr, const char* data, uint32_t size);
void asr_close(idevice_connection_t asr);
int asr_perform_validation(idevice_connection_t asr, const char* filesystem);
int asr_send_payload(idevice_connection_t asr, const char* filesystem);
int asr_handle_oob_data_request(idevice_connection_t asr, plist_t packet, FILE* file);


#ifdef __cplusplus
}
#endif

#endif
