/*
 * mbn.c
 * support for .mbn file format (found in .bbfw files)
 *
 * Copyright (c) 2012 Martin Szulecki. All Rights Reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbn.h"
#include "common.h"

mbn_file* mbn_parse(unsigned char* data, unsigned int size)
{
	mbn_file* mbn = (mbn_file*)malloc(sizeof(mbn_file));
	if (!mbn) {
		return NULL;
	}
	memset(mbn, '\0', sizeof(mbn_file));
	mbn->data = malloc(size);
	mbn->size = size;
	memcpy(mbn->data, data, size);
	/* FIXME: header parsing is not big endian safe */
	if (memcmp(data, MBN_V2_MAGIC, MBN_V2_MAGIC_SIZE) == 0) {
		mbn->version = 2;
		memcpy(&mbn->header.v2, data, sizeof(mbn_header_v2));
		mbn->parsed_size = mbn->header.v2.data_size + sizeof(mbn_header_v2);
	} else if (memcmp(data, MBN_V1_MAGIC, MBN_V1_MAGIC_SIZE) == 0) {
		mbn->version = 1;
		memcpy(&mbn->header.v1, data, sizeof(mbn_header_v1));
		mbn->parsed_size = mbn->header.v1.data_size + sizeof(mbn_header_v1);
	} else if (memcmp(data, BIN_MAGIC, BIN_MAGIC_SIZE) == 0) {
		mbn->version = 3;
		memcpy(&mbn->header.bin, data, sizeof(bin_header));
		mbn->parsed_size = mbn->header.bin.total_size;
	} else if (memcmp(data, ELF_MAGIC, ELF_MAGIC_SIZE) == 0) {
		mbn->version = 4;
		memcpy(&mbn->header.elf, data, sizeof(elf_header));
		// we cheat here since we don't parse the actual ELF file
		mbn->parsed_size = mbn->size;
	} else {
		debug("DEBUG: Unknown file format passed to %s\n", __func__);
	}
	if (mbn->parsed_size != mbn->size) {
		info("WARNING: size mismatch when parsing MBN file. Continuing anyway.\n");
	}
	return mbn;
}

void mbn_free(mbn_file* mbn)
{
	if (mbn) {
		if (mbn->data) {
			free(mbn->data);
		}
		free(mbn);
	}
}

int mbn_update_sig_blob(mbn_file* mbn, const unsigned char* sigdata, unsigned int siglen)
{
	if (!mbn) {
		error("ERROR: %s: no data\n", __func__);
		return -1;
	}
	mbn->parsed_sig_offset = mbn->size - siglen;
	if ((mbn->parsed_sig_offset + siglen) > mbn->size) {
		error("ERROR: %s: signature is larger than mbn file size\n", __func__);
		return -1;
	}

	memcpy(mbn->data + mbn->parsed_sig_offset, sigdata, siglen);

	return 0;
}

