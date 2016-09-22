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

#define MBN_V1_MAGIC "\x0A\x00\x00\x00"
#define MBN_V1_MAGIC_SIZE 4

struct _mbn_header_v1 {
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
typedef struct _mbn_header_v1 mbn_header_v1;

#define MBN_V2_MAGIC "\xD1\xDC\x4B\x84\x34\x10\xD7\x73"
#define MBN_V2_MAGIC_SIZE 8

struct _mbn_header_v2 {
	unsigned char magic1[8];
	uint32_t unk_0x08;
	uint32_t unk_0x0c; // 0xFFFFFFFF
	uint32_t unk_0x10; // 0xFFFFFFFF
	uint32_t header_size;
	uint32_t unk_0x18;
	uint32_t data_size;  // data_size = total_size - sizeof(mbn_header_v2)
	uint32_t sig_offset;
	uint32_t unk_0x24;
	uint32_t unk_0x28;
	uint32_t unk_0x2c;
	uint32_t unk_0x30;
	uint32_t unk_0x34; // 0x1
	uint32_t unk_0x38; // 0x1
	uint32_t unk_0x3c; // 0xFFFFFFFF
	uint32_t unk_0x40; // 0xFFFFFFFF
	uint32_t unk_0x44; // 0xFFFFFFFF
	uint32_t unk_0x48; // 0xFFFFFFFF
	uint32_t unk_0x4c; // 0xFFFFFFFF
} __attribute__((packed));
typedef struct _mbn_header_v2 mbn_header_v2;

#define BIN_MAGIC "\x7D\x04\x00\xEA\x6C\x69\x48\x55"
#define BIN_MAGIC_SIZE 8

struct _bin_header {
	unsigned char magic[8];
	uint32_t unk_0x08;
	uint32_t version;
	uint32_t total_size; // size including header
	uint32_t unk_0x14; // some offset
} __attribute__((packed));
typedef struct _bin_header bin_header;

#define ELF_MAGIC "\x7F\x45\x4C\x46\x01\x01\x01\x00" // ELF magic, 32bit, little endian, SYSV
#define ELF_MAGIC_SIZE 8

struct _elf_header {
	unsigned char magic[8];
} __attribute__((packed));
typedef struct _elf_header elf_header;

typedef struct {
	uint32_t version;
	union {
		mbn_header_v1 v1;
		mbn_header_v2 v2;
		bin_header bin;
		elf_header elf;
	} header;
	uint32_t parsed_size;
	uint32_t parsed_sig_offset;
	void* data;
	uint32_t size;
} mbn_file;

mbn_file* mbn_parse(unsigned char* data, unsigned int size);
void mbn_free(mbn_file* mbn);
int mbn_update_sig_blob(mbn_file* mbn, const unsigned char* data, unsigned int size);

#endif
