/*
 * img3.c
 * Functions for handling with Apple's IMG3 format
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "img3.h"
#include "idevicerestore.h"

img3_file* img3_parse_file(unsigned char* data, int size) {
	int data_offset = 0;
	img3_header* header = (img3_header*) data;
	if(header->signature != kImg3Container) {
		error("ERROR: Invalid IMG3 file\n");
		return NULL;
	}

	img3_file* image = (img3_file*) malloc(sizeof(img3_file));
	if(image == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 file\n");
		return NULL;
	}
	memset(image, '\0', sizeof(img3_file));

	image->header = (img3_header*) malloc(sizeof(img3_header));
	if(image->header == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 header\n");
		img3_free(image);
		return NULL;
	}
	memcpy(image->header, data, sizeof(img3_header));
	data_offset += sizeof(img3_header);

	img3_element_header* current = NULL;
	while(data_offset < size) {
		current = (img3_element_header*) &data[data_offset];
		switch(current->signature) {
		case kTypeElement:
			image->type_element = img3_parse_element(&data[data_offset]);
			if(image->type_element == NULL) {
				error("ERROR: Unable to parse TYPE element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed TYPE element\n");
			break;

		case kDataElement:
			image->data_element = img3_parse_element(&data[data_offset]);
			if(image->data_element == NULL) {
				error("ERROR: Unable to parse DATA element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed DATA element\n");
			break;

		case kVersElement:
			image->vers_element = img3_parse_element(&data[data_offset]);
			if(image->vers_element == NULL) {
				error("ERROR: Unable to parse VERS element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed VERS element\n");
			break;

		case kSepoElement:
			image->sepo_element = img3_parse_element(&data[data_offset]);
			if(image->sepo_element == NULL) {
				error("ERROR: Unable to parse SEPO element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed SEPO element\n");
			break;

		case kBordElement:
			image->bord_element = img3_parse_element(&data[data_offset]);
			if(image->bord_element == NULL) {
				error("ERROR: Unable to parse BORD element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed BORD element\n");
			break;

		case kKbagElement:
			if(image->kbag1_element == NULL) {
				image->kbag1_element = img3_parse_element(&data[data_offset]);
				image->kbag1_element = img3_parse_element(&data[data_offset]);
				if(image->kbag1_element == NULL) {
					error("ERROR: Unable to parse first KBAG element\n");
					img3_free(image);
					return NULL;
				}

			} else {
				image->kbag2_element = img3_parse_element(&data[data_offset]);
				image->kbag2_element = img3_parse_element(&data[data_offset]);
				if(image->kbag2_element == NULL) {
					error("ERROR: Unable to parse second KBAG element\n");
					img3_free(image);
					return NULL;
				}
			}
			debug("Parsed KBAG element\n");
			break;

		case kEcidElement:
			image->ecid_element = img3_parse_element(&data[data_offset]);
			if(image->ecid_element == NULL) {
				error("ERROR: Unable to parse ECID element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed ECID element\n");
			break;

		case kShshElement:
			image->shsh_element = img3_parse_element(&data[data_offset]);
			if(image->shsh_element == NULL) {
				error("ERROR: Unable to parse SHSH element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed SHSH element\n");
			break;

		case kCertElement:
			image->cert_element = img3_parse_element(&data[data_offset]);
			if(image->cert_element == NULL) {
				error("ERROR: Unable to parse CERT element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed CERT element\n");
			break;

		default:
			error("ERROR: Unknown IMG3 element type\n");
			img3_free(image);
			return NULL;
		}
		data_offset += current->full_size;
	}

	return image;
}

img3_element* img3_parse_element(char* element) {
	img3_element_header* element_header = (img3_element_header*) element;
	return 1;
}

void img3_free(img3_file* image) {
	if(image != NULL) {
		if(image->header != NULL) {
			free(image->header);
		}

		free(image);
	}
}

void img3_replace_signature(img3_file* image, char* signature) {
	return;
}

char* img3_get_data(img3_file* image) {
	return NULL;
}
