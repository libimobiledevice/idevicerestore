/*
 * mbn.h
 * support for .mbn file format (found in .bbfw files)
 *
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
#ifndef MBN_H
#define MBN_H

#include <stdint.h>

struct _mbn_header {
	uint32_t type;           // the signed .mbn files have 0xA as value.
	uint32_t unk_0x04;
	uint32_t unk_0x08;
	uint32_t unk_0x0c;
	uint32_t data_size;       // data_size = total_size - sizeof(mbn_header)
	uint32_t sig_offset; // real offset = enc_sig_offset & 0xFFFFFF00
	uint32_t unk_0x18;
	uint32_t unk_0x1c;
	uint32_t unk_0x20;
	uint32_t unk_0x24;
} __attribute__((packed));
typedef struct _mbn_header mbn_header;

typedef struct {
	mbn_header header;
	uint32_t parsed_size;
	uint32_t parsed_sig_offset;
	void* data;
	uint32_t size;
} mbn_file;

mbn_file* mbn_parse(unsigned char* data, unsigned int size);
void mbn_free(mbn_file* mbn);
int mbn_update_sig_blob(mbn_file* mbn, const unsigned char* data, unsigned int size);

#endif
