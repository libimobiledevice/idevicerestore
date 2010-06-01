/*
 * dfu.c
 * Functions for handling idevices in DFU mode
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

#include <stdint.h>
#include <libirecovery.h>

#include "dfu.h"

int dfu_check_mode() {
	irecv_client_t dfu = NULL;
	irecv_error_t dfu_error = IRECV_E_SUCCESS;

	dfu_error = irecv_open(&dfu);
	if (dfu_error != IRECV_E_SUCCESS) {
		return -1;
	}

	if(dfu->mode != kDfuMode) {
		irecv_close(dfu);
		return -1;
	}

	irecv_close(dfu);
	dfu = NULL;
	return 0;
}

int dfu_get_cpid(uint32_t* cpid) {
	return 0;
}

int dfu_get_bdid(uint32_t* bdid) {
	return 0;
}

int dfu_get_ecid(uint64_t* ecid) {
	return 0;
}
