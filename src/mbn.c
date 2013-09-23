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
	memcpy(&mbn->header, data, sizeof(mbn_header));
	mbn->parsed_size = mbn->header.data_size + sizeof(mbn_header);
	if (mbn->parsed_size != mbn->size) {
		debug("WARNING: size mismatch when parsing MBN file.\n");
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

