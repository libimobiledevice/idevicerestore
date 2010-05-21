/*
 * tss.c
 * Functions for communicating with Apple's TSS server
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
#include <plist/plist.h>

plist_t tss_create_request(plist_t buildmanifest) {
	plist_t build_identities_array = plist_dict_get_item(buildmanifest, "BuildIdentities");
	if(!build_identities_array || plist_get_node_type(build_identities_array) != PLIST_ARRAY) {
		error("ERROR: Unable to find BuildIdentities array\n");
		return NULL;
	}

	plist_t restore_identity_dict = plist_array_get_item(build_identities_array, 0);
	if(!restore_identity_dict || plist_get_node_type(restore_identity_dict) != PLIST_DICT) {
		error("ERROR: Unable to find restore identity\n");
		return NULL;
	}

	plist_t unique_build_node = plist_dict_get_item(restore_identity_dict, "UniqueBuildID");
	if(!unique_build_node || plist_get_node_type(unique_build_node) != PLIST_DATA) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return NULL;
	}

	int chip_id = 0;
	char* chip_id_string = NULL;
	plist_t chip_id_node = plist_dict_get_item(restore_identity_dict, "ApChipID");
	if(!chip_id_node || plist_get_node_type(chip_id_node) != PLIST_STRING) {
		error("ERROR: Unable to find ApChipID node\n");
		return NULL;
	}
	plist_get_string_val(chip_id_node, &chip_id_string);
    sscanf(chip_id_string, "%x", &chip_id);

    int board_id = 0;
    char* board_id_string = NULL;
    plist_t board_id_node =  plist_dict_get_item(restore_identity_dict, "ApBoardID");
    if(!board_id_node || plist_get_node_type(board_id_node) != PLIST_STRING) {
    	error("ERROR: Unable to find ApBoardID node\n");
    	return NULL;
    }
    plist_get_string_val(board_id_node, &board_id_string);
    sscanf(board_id_string, "%x", &board_id);

    int security_domain = 0;
    char* security_domain_string = NULL;
    plist_t security_domain_node = plist_dict_get_item(restore_identity_dict, "ApSecurityDomain");
    if(!security_domain_node || plist_get_node_type(security_domain_node) != PLIST_STRING) {
    	error("ERROR: Unable to find ApSecurityDomain node\n");
    	return NULL;
    }
    plist_get_string_val(security_domain_node, &security_domain_string);
    sscanf(security_domain_string, "%x", &security_domain);



	return NULL;
}
