/*
 * img4.c
 * Functions for handling the new IMG4 format
 *
 * Copyright (c) 2013 Nikias Bassen. All Rights Reserved.
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

#include <stdlib.h>
#include <string.h>

#include "img4.h"

#define ASN1_CONSTRUCTED 0x20
#define ASN1_SEQUENCE 0x10
#define ASN1_CONTEXT_SPECIFIC 0x80
#define ASN1_IA5_STRING 0x16

#define IMG4_MAGIC "IMG4"
#define IMG4_MAGIC_SIZE 4

static unsigned char* asn1_create_element_header(unsigned char type, unsigned int size, unsigned char** data, unsigned int *data_size)
{
	unsigned char buf[6];
	unsigned int off = 0;

	if (!type || size == 0 || !data || !data_size) {
		return NULL;
	}

	buf[off++] = type;

	// first, calculate the size
	if (size >= 0x1000000) {
		// 1+4 bytes length
		buf[off++] = 0x84;
		buf[off++] = (size >> 24) & 0xFF;
		buf[off++] = (size >> 16) & 0xFF;
		buf[off++] = (size >> 8) & 0xFF;
		buf[off++] = size & 0xFF;
	} else if (size >= 0x10000) {
		// 1+3 bytes length
		buf[off++] = 0x83;
		buf[off++] = (size >> 16) & 0xFF;
		buf[off++] = (size >> 8) & 0xFF;
		buf[off++] = size & 0xFF;
	} else if (size >= 0x100) {
		// 1+2 bytes length
		buf[off++] = 0x82;
		buf[off++] = (size >> 8) & 0xFF;
		buf[off++] = (size & 0xFF);
	} else if (size >= 0x80) {
		// 1+1 byte length
		buf[off++] = 0x81;
		buf[off++] = (size & 0xFF);
	} else {
		// 1 byte length
		buf[off++] = size & 0xFF;
	}

	*data = malloc(off);
	memcpy(*data, buf, off);
	*data_size = off;

	return *data;
}	

int img4_stitch_component(const char* component_name, const unsigned char* component_data, unsigned int component_size, const unsigned char* blob, unsigned int blob_size, unsigned char** img4_data, unsigned int *img4_size)
{
	unsigned char* magic_header = NULL;
	unsigned int magic_header_size = 0;
	unsigned char* blob_header = NULL;
	unsigned int blob_header_size = 0;
	unsigned char* img4header = NULL;
	unsigned int img4header_size = 0;
	unsigned int content_size;
	unsigned char* outbuf;
	unsigned char* p;

	if (!component_name || !component_data || component_size == 0 || !blob || blob_size == 0 || !img4_data || !img4_size) {
		return -1;
	}

	/* first we need check if we have to change the tag for the given component */
	// FIXME: write proper ASN1 handling code for this
	if (strcmp(component_name, "RestoreKernelCache") == 0) {
		memcpy((char*)component_data+0xD, "rkrn", 4);
	} else if (strcmp(component_name, "RestoreDeviceTree") == 0) {
		memcpy((char*)component_data+0xD, "rdtr", 4);
	} else if (strcmp(component_name, "RestoreSEP") == 0) {
		memcpy((char*)component_data+0xD, "rsep", 4);
	}

	// create element header for the "IMG4" magic
	asn1_create_element_header(ASN1_IA5_STRING, IMG4_MAGIC_SIZE, &magic_header, &magic_header_size);
	// create element header for the blob (ApImg4Ticket)
	asn1_create_element_header(ASN1_CONTEXT_SPECIFIC|ASN1_CONSTRUCTED, blob_size, &blob_header, &blob_header_size);

	// calculate the size for the final IMG4 file (asn1 sequence)
	content_size = magic_header_size + IMG4_MAGIC_SIZE + component_size + blob_header_size + blob_size;

	// create element header for the final IMG4 asn1 blob
	asn1_create_element_header(ASN1_SEQUENCE|ASN1_CONSTRUCTED, content_size, &img4header, &img4header_size);

	outbuf = (unsigned char*)malloc(img4header_size + content_size);
	if (!outbuf) {
		if (magic_header) {
			free(magic_header);
		}
		if (blob_header) {
			free(blob_header);
		}
		if (img4header) {
			free(img4header);
		}
		return -1;
	}
	p = outbuf;

	// now put everything together
	memcpy(p, img4header, img4header_size);
	p += img4header_size;
	memcpy(p, magic_header, magic_header_size);
	p += magic_header_size;
	memcpy(p, IMG4_MAGIC, IMG4_MAGIC_SIZE);
	p += IMG4_MAGIC_SIZE;
	memcpy(p, component_data, component_size);
	p += component_size;
	memcpy(p, blob_header, blob_header_size);
	p += blob_header_size;
	memcpy(p, blob, blob_size);
	p += blob_size;

	*img4_data = outbuf;
	*img4_size = (p - outbuf);

	if (magic_header) {
		free(magic_header);
	}
	if (blob_header) {
		free(blob_header);
	}
	if (img4header) {
		free(img4header);
	}

	return 0;
}
