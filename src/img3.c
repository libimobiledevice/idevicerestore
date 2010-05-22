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

#include "img3.h"
#include "idevicerestore.h"

img3_file* image3_parse_file(unsigned char* data, unsigned int size) {
	img3_header* header = (img3_header*) data;
	if(header->imageType != kImg3Container) {
		error("ERROR: Invalid IMG3 file\n");
		return NULL;
	}
	return NULL;
}

void image3_free(img3_file* file) {
	if(file != NULL) {
		free(file);
	}
}
