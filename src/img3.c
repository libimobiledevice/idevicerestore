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
#include "common.h"
#include "idevicerestore.h"

img3_file* img3_parse_file(char* data, int size) {
	int data_offset = 0;
	img3_header* header = (img3_header*) data;
	if (header->signature != kImg3Container) {
		error("ERROR: Invalid IMG3 file\n");
		return NULL;
	}

	img3_file* image = (img3_file*) malloc(sizeof(img3_file));
	if (image == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 file\n");
		return NULL;
	}
	memset(image, '\0', sizeof(img3_file));

	image->header = (img3_header*) malloc(sizeof(img3_header));
	if (image->header == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 header\n");
		img3_free(image);
		return NULL;
	}
	memcpy(image->header, data, sizeof(img3_header));
	data_offset += sizeof(img3_header);

	img3_element_header* current = NULL;
	while (data_offset < size) {
		current = (img3_element_header*) &data[data_offset];
		switch (current->signature) {
		case kTypeElement:
			image->type_element = img3_parse_element(&data[data_offset]);
			if (image->type_element == NULL) {
				error("ERROR: Unable to parse TYPE element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed TYPE element\n");
			break;

		case kDataElement:
			image->data_element = img3_parse_element(&data[data_offset]);
			if (image->data_element == NULL) {
				error("ERROR: Unable to parse DATA element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed DATA element\n");
			break;

		case kVersElement:
			image->vers_element = img3_parse_element(&data[data_offset]);
			if (image->vers_element == NULL) {
				error("ERROR: Unable to parse VERS element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed VERS element\n");
			break;

		case kSepoElement:
			image->sepo_element = img3_parse_element(&data[data_offset]);
			if (image->sepo_element == NULL) {
				error("ERROR: Unable to parse SEPO element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed SEPO element\n");
			break;

		case kBordElement:
			image->bord_element = img3_parse_element(&data[data_offset]);
			if (image->bord_element == NULL) {
				error("ERROR: Unable to parse BORD element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed BORD element\n");
			break;

		case kKbagElement:
			if (image->kbag1_element == NULL) {
				image->kbag1_element = img3_parse_element(&data[data_offset]);
				if (image->kbag1_element == NULL) {
					error("ERROR: Unable to parse first KBAG element\n");
					img3_free(image);
					return NULL;
				}

			} else {
				image->kbag2_element = img3_parse_element(&data[data_offset]);
				if (image->kbag2_element == NULL) {
					error("ERROR: Unable to parse second KBAG element\n");
					img3_free(image);
					return NULL;
				}
			}
			debug("Parsed KBAG element\n");
			break;

		case kEcidElement:
			image->ecid_element = img3_parse_element(&data[data_offset]);
			if (image->ecid_element == NULL) {
				error("ERROR: Unable to parse ECID element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed ECID element\n");
			break;

		case kShshElement:
			image->shsh_element = img3_parse_element(&data[data_offset]);
			if (image->shsh_element == NULL) {
				error("ERROR: Unable to parse SHSH element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed SHSH element\n");
			break;

		case kCertElement:
			image->cert_element = img3_parse_element(&data[data_offset]);
			if (image->cert_element == NULL) {
				error("ERROR: Unable to parse CERT element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed CERT element\n");
			break;

		case kUnknElement:
			image->unkn_element = img3_parse_element(&data[data_offset]);
			if (image->unkn_element == NULL) {
				error("ERROR: Unable to parse UNKN element\n");
				img3_free(image);
				return NULL;
			}
			debug("Parsed UNKN element\n");
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

img3_element* img3_parse_element(char* data) {
	img3_element_header* element_header = (img3_element_header*) data;
	img3_element* element = (img3_element*) malloc(sizeof(img3_element));
	if (element == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 element\n");
		return NULL;
	}
	memset(element, '\0', sizeof(img3_element));

	element->data = (char*) malloc(element_header->full_size);
	if (element->data == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 element data\n");
		free(element);
		return NULL;
	}
	memcpy(element->data, data, element_header->full_size);
	element->header = (img3_element_header*) element->data;
	element->type = (img3_element_type) element->header->signature;

	return element;
}

void img3_free(img3_file* image) {
	if (image != NULL) {
		if (image->header != NULL) {
			free(image->header);
		}

		if (image->type_element != NULL) {
			img3_free_element(image->type_element);
			image->type_element = NULL;
		}

		if (image->data_element != NULL) {
			img3_free_element(image->data_element);
			image->data_element = NULL;
		}

		if (image->vers_element != NULL) {
			img3_free_element(image->vers_element);
			image->vers_element = NULL;
		}

		if (image->sepo_element != NULL) {
			img3_free_element(image->sepo_element);
			image->sepo_element = NULL;
		}

		if (image->bord_element != NULL) {
			img3_free_element(image->bord_element);
			image->bord_element = NULL;
		}

		if (image->kbag1_element != NULL) {
			img3_free_element(image->kbag1_element);
			image->kbag1_element = NULL;
		}

		if (image->kbag2_element != NULL) {
			img3_free_element(image->kbag2_element);
			image->kbag2_element = NULL;
		}

		if (image->ecid_element != NULL) {
			img3_free_element(image->ecid_element);
			image->ecid_element = NULL;
		}

		if (image->shsh_element != NULL) {
			img3_free_element(image->shsh_element);
			image->shsh_element = NULL;
		}

		if (image->cert_element != NULL) {
			img3_free_element(image->cert_element);
			image->cert_element = NULL;
		}

		if (image->unkn_element != NULL) {
			img3_free_element(image->unkn_element);
			image->unkn_element = NULL;
		}

		free(image);
		image = NULL;
	}
}

void img3_free_element(img3_element* element) {
	if (element != NULL) {
		if (element->data != NULL) {
			free(element->data);
			element->data = NULL;
		}
		free(element);
		element = NULL;
	}
}

int img3_replace_signature(img3_file* image, char* signature) {
	int offset = 0;
	img3_element* ecid = img3_parse_element(&signature[offset]);
	if (ecid == NULL || ecid->type != kEcidElement) {
		error("ERROR: Unable to find ECID element in signature\n");
		return -1;
	}
	offset += ecid->header->full_size;

	img3_element* shsh = img3_parse_element(&signature[offset]);
	if (shsh == NULL || shsh->type != kShshElement) {
		error("ERROR: Unable to find SHSH element in signature\n");
		return -1;
	}
	offset += shsh->header->full_size;

	img3_element* cert = img3_parse_element(&signature[offset]);
	if (cert == NULL || cert->type != kCertElement) {
		error("ERROR: Unable to find CERT element in signature\n");
		return -1;
	}
	offset += cert->header->full_size;

	if (image->ecid_element != NULL) {
		img3_free_element(image->ecid_element);
	}
	image->ecid_element = ecid;

	if (image->shsh_element != NULL) {
		img3_free_element(image->shsh_element);
	}
	image->shsh_element = shsh;

	if (image->cert_element != NULL) {
		img3_free_element(image->cert_element);
	}
	image->cert_element = cert;

	return 0;
}

int img3_get_data(img3_file* image, char** pdata, int* psize) {
	int offset = 0;
	int size = sizeof(img3_header);

	// Add up the size of the image first so we can allocate our memory
	if (image->type_element != NULL) {
		size += image->type_element->header->full_size;
	}
	if (image->data_element != NULL) {
		size += image->data_element->header->full_size;
	}
	if (image->vers_element != NULL) {
		size += image->vers_element->header->full_size;
	}
	if (image->sepo_element != NULL) {
		size += image->sepo_element->header->full_size;
	}
	if (image->bord_element != NULL) {
		size += image->bord_element->header->full_size;
	}
	if (image->kbag1_element != NULL) {
		size += image->kbag1_element->header->full_size;
	}
	if (image->kbag2_element != NULL) {
		size += image->kbag2_element->header->full_size;
	}
	if (image->ecid_element != NULL) {
		size += image->ecid_element->header->full_size;
	}
	if (image->shsh_element != NULL) {
		size += image->shsh_element->header->full_size;
	}
	if (image->cert_element != NULL) {
		size += image->cert_element->header->full_size;
	}
	if (image->unkn_element != NULL) {
		size += image->unkn_element->header->full_size;
	}

	char* data = (char*) malloc(size);
	if (data == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 data\n");
		return -1;
	}

	// Add data to our new header (except shsh_offset)
	img3_header* header = (img3_header*) data;
	header->full_size = size;
	header->signature = image->header->signature;
	header->data_size = size - sizeof(img3_header);
	header->image_type = image->header->image_type;
	offset += sizeof(img3_header);

	// Copy each section over to the new buffer
	if (image->type_element != NULL) {
		memcpy(&data[offset], image->type_element->data, image->type_element->header->full_size);
		offset += image->type_element->header->full_size;
	}
	if (image->data_element != NULL) {
		memcpy(&data[offset], image->data_element->data, image->data_element->header->full_size);
		offset += image->data_element->header->full_size;
	}
	if (image->vers_element != NULL) {
		memcpy(&data[offset], image->vers_element->data, image->vers_element->header->full_size);
		offset += image->vers_element->header->full_size;
	}
	if (image->sepo_element != NULL) {
		memcpy(&data[offset], image->sepo_element->data, image->sepo_element->header->full_size);
		offset += image->sepo_element->header->full_size;
	}
	if (image->bord_element != NULL) {
		memcpy(&data[offset], image->bord_element->data, image->bord_element->header->full_size);
		offset += image->bord_element->header->full_size;
	}
	if (image->kbag1_element != NULL) {
		memcpy(&data[offset], image->kbag1_element->data, image->kbag1_element->header->full_size);
		offset += image->kbag1_element->header->full_size;
	}
	if (image->kbag2_element != NULL) {
		memcpy(&data[offset], image->kbag2_element->data, image->kbag2_element->header->full_size);
		offset += image->kbag2_element->header->full_size;
	}
	if (image->ecid_element != NULL) {
		memcpy(&data[offset], image->ecid_element->data, image->ecid_element->header->full_size);
		offset += image->ecid_element->header->full_size;
	}
	if (image->shsh_element != NULL) {
		memcpy(&data[offset], image->shsh_element->data, image->shsh_element->header->full_size);
		header->shsh_offset = offset - sizeof(img3_header);
		offset += image->shsh_element->header->full_size;
	}
	if (image->cert_element != NULL) {
		memcpy(&data[offset], image->cert_element->data, image->cert_element->header->full_size);
		offset += image->cert_element->header->full_size;
	}
	if (image->unkn_element != NULL) {
		memcpy(&data[offset], image->unkn_element->data, image->unkn_element->header->full_size);
		offset += image->unkn_element->header->full_size;
	}

	if (offset != size) {
		error("ERROR: Incorrectly sized image data\n");
		free(data);
		*pdata = 0;
		*psize = 0;
		return -1;
	}

	*pdata = data;
	*psize = size;
	return 0;
}
