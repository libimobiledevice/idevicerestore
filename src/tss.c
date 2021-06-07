/*
 * tss.c
 * Functions for communicating with Apple's TSS server
 *
 * Copyright (c) 2010-2013 Martin Szulecki. All Rights Reserved.
 * Copyright (c) 2012 Nikias Bassen. All Rights Reserved.
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
#include <unistd.h>
#include <curl/curl.h>
#include <plist/plist.h>

#include "tss.h"
#include "img3.h"
#include "common.h"
#include "idevicerestore.h"

#include "endianness.h"

#define TSS_CLIENT_VERSION_STRING "libauthinstall-776.60.1"
#define ECID_STRSIZE 0x20

typedef struct {
	int length;
	char* content;
} tss_response;

char* ecid_to_string(uint64_t ecid) {
	char* ecid_string = malloc(ECID_STRSIZE);
	memset(ecid_string, '\0', ECID_STRSIZE);
	if (ecid == 0) {
		error("ERROR: Invalid ECID passed.\n");
		return NULL;
	}
	snprintf(ecid_string, ECID_STRSIZE, "%"PRIu64, ecid);
	return ecid_string;
}

plist_t tss_request_new(plist_t overrides) {

	plist_t request = plist_new_dict();

	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@HostPlatformInfo",
#ifdef WIN32
		plist_new_string("windows")
#else
		plist_new_string("mac")
#endif
	);

	plist_dict_set_item(request, "@VersionInfo", plist_new_string(TSS_CLIENT_VERSION_STRING));
	char* guid = generate_guid();
	if (guid) {
		plist_dict_set_item(request, "@UUID", plist_new_string(guid));
		free(guid);
	}

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return request;
}

int tss_request_add_local_policy_tags(plist_t request, plist_t parameters)
{
	plist_t node = NULL;

	plist_dict_set_item(request, "@ApImg4Ticket", plist_new_bool(1));

	/* Ap,LocalBoot */
	node = plist_dict_get_item(parameters, "Ap,LocalBoot");
	if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
		error("ERROR: Unable to find required Ap,LocalBoot in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "Ap,LocalBoot", plist_copy(node));
	node = NULL;

	/* Ap,LocalPolicy */
	node = plist_dict_get_item(parameters, "Ap,LocalPolicy");
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to find required Ap,LocalPolicy in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "Ap,LocalPolicy", plist_copy(node));
	node = NULL;

	/* Ap,NextStageIM4MHash */
	node = plist_dict_get_item(parameters, "Ap,NextStageIM4MHash");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		error("ERROR: Unable to find required Ap,NextStageIM4MHash in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "Ap,NextStageIM4MHash", plist_copy(node));
	node = NULL;

	/* Ap,RecoveryOSPolicyNonceHash */
	node = plist_dict_get_item(parameters, "Ap,RecoveryOSPolicyNonceHash");
	if (node) {
		plist_dict_set_item(request, "Ap,RecoveryOSPolicyNonceHash", plist_copy(node));
	}
	node = NULL;

	/* Ap,VolumeUUID */
	node = plist_dict_get_item(parameters, "Ap,VolumeUUID");
	if (node) {
		plist_dict_set_item(request, "Ap,VolumeUUID", plist_copy(node));
	}
	node = NULL;

	/* ApECID */
	node = plist_dict_get_item(parameters, "ApECID");
	if (node) {
		plist_dict_set_item(request, "ApECID", plist_copy(node));
	}
	node = NULL;

	/* ApChipID */
	node = plist_dict_get_item(parameters, "ApChipID");
	if (node) {
		plist_dict_set_item(request, "ApChipID", plist_copy(node));
	}
	node = NULL;

	/* ApBoardID */
	node = plist_dict_get_item(parameters, "ApBoardID");
	if (node) {
		plist_dict_set_item(request, "ApBoardID", plist_copy(node));
	}
	node = NULL;

	/* ApSecurityDomain */
	node = plist_dict_get_item(parameters, "ApSecurityDomain");
	if (node) {
		plist_dict_set_item(request, "ApSecurityDomain", plist_copy(node));
	}
	node = NULL;

	/* ApNonce */
	node = plist_dict_get_item(parameters, "ApNonce");
	if (node) {
		plist_dict_set_item(request, "ApNonce", plist_copy(node));
	}
	node = NULL;

	/* ApSecurityMode */
	node = plist_dict_get_item(request, "ApSecurityMode");
	if (!node) {
		/* copy from parameters if available */
		node = plist_dict_get_item(parameters, "ApSecurityMode");
		if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
			error("ERROR: Unable to find required ApSecurityMode in parameters\n");
			return -1;
		}
		plist_dict_set_item(request, "ApSecurityMode", plist_copy(node));
		node = NULL;
	}

	node = plist_dict_get_item(request, "ApProductionMode");
	if (!node) {
		/* ApProductionMode */
		node = plist_dict_get_item(parameters, "ApProductionMode");
		if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
			error("ERROR: Unable to find required ApProductionMode in parameters\n");
			return -1;
		}
		plist_dict_set_item(request, "ApProductionMode", plist_copy(node));
		node = NULL;
	}

	return 0;
}

int tss_parameters_add_from_manifest(plist_t parameters, plist_t build_identity)
{
	plist_t node = NULL;
	char* string = NULL;

	/* UniqueBuildID */
	node = plist_dict_get_item(build_identity, "UniqueBuildID");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return -1;
	}
	plist_dict_set_item(parameters, "UniqueBuildID", plist_copy(node));
	node = NULL;

	/* Ap,OSLongVersion */
	node = plist_dict_get_item(build_identity, "Ap,OSLongVersion");
	if (node) {
		plist_dict_set_item(parameters, "Ap,OSLongVersion", plist_copy(node));
	}

	/* ApChipID */
	int chip_id = 0;
	node = plist_dict_get_item(build_identity, "ApChipID");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ApChipID node\n");
		return -1;
	}
	plist_get_string_val(node, &string);
	sscanf(string, "%x", &chip_id);
	plist_dict_set_item(parameters, "ApChipID", plist_new_uint(chip_id));
	free(string);
	string = NULL;
	node = NULL;

	/* ApBoardID */
	int board_id = 0;
	node = plist_dict_get_item(build_identity, "ApBoardID");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ApBoardID node\n");
		return -1;
	}
	plist_get_string_val(node, &string);
	sscanf(string, "%x", &board_id);
	plist_dict_set_item(parameters, "ApBoardID", plist_new_uint(board_id));
	free(string);
	string = NULL;
	node = NULL;

	/* ApSecurityDomain */
	int security_domain = 0;
	node = plist_dict_get_item(build_identity, "ApSecurityDomain");
	if (!node || plist_get_node_type(node) != PLIST_STRING) {
		error("ERROR: Unable to find ApSecurityDomain node\n");
		return -1;
	}
	plist_get_string_val(node, &string);
	sscanf(string, "%x", &security_domain);
	plist_dict_set_item(parameters, "ApSecurityDomain", plist_new_uint(security_domain));
	free(string);
	string = NULL;
	node = NULL;

	/* BMU,BoardID */
	node = plist_dict_get_item(build_identity, "BMU,BoardID");
	if (node) {
		plist_dict_set_item(parameters, "BMU,BoardID", plist_copy(node));
	}

	/* BMU,ChipID */
	node = plist_dict_get_item(build_identity, "BMU,ChipID");
	if (node) {
		plist_dict_set_item(parameters, "BMU,ChipID", plist_copy(node));
	}

	/* BbChipID */
	int bb_chip_id = 0;
	char* bb_chip_id_string = NULL;
	node = plist_dict_get_item(build_identity, "BbChipID");
	if (node && plist_get_node_type(node) == PLIST_STRING) {
		plist_get_string_val(node, &bb_chip_id_string);
		sscanf(bb_chip_id_string, "%x", &bb_chip_id);
		plist_dict_set_item(parameters, "BbChipID", plist_new_uint(bb_chip_id));
	} else {
		debug("NOTE: Unable to find BbChipID node\n");
	}
	node = NULL;

	/* BbProvisioningManifestKeyHash */
	node = plist_dict_get_item(build_identity, "BbProvisioningManifestKeyHash");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbProvisioningManifestKeyHash", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbProvisioningManifestKeyHash node\n");
	}
	node = NULL;

	/* BbActivationManifestKeyHash - Used by Qualcomm MDM6610 */
	node = plist_dict_get_item(build_identity, "BbActivationManifestKeyHash");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbActivationManifestKeyHash", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbActivationManifestKeyHash node\n");
	}
	node = NULL;

	node = plist_dict_get_item(build_identity, "BbCalibrationManifestKeyHash");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbCalibrationManifestKeyHash", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbCalibrationManifestKeyHash node\n");
	}
	node = NULL;

	/* BbFactoryActivationManifestKeyHash */
	node = plist_dict_get_item(build_identity, "BbFactoryActivationManifestKeyHash");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbFactoryActivationManifestKeyHash", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbFactoryActivationManifestKeyHash node\n");
	}
	node = NULL;

	/* BbFDRSecurityKeyHash */
	node = plist_dict_get_item(build_identity, "BbFDRSecurityKeyHash");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbFDRSecurityKeyHash", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbFDRSecurityKeyHash node\n");
	}
	node = NULL;

	/* BbSkeyId - Used by XMM 6180/GSM */
	node = plist_dict_get_item(build_identity, "BbSkeyId");
	if (node && plist_get_node_type(node) == PLIST_DATA) {
		plist_dict_set_item(parameters, "BbSkeyId", plist_copy(node));
	} else {
		debug("NOTE: Unable to find BbSkeyId node\n");
	}
	node = NULL;

	/* SE,ChipID - Used for SE firmware request */
	node = plist_dict_get_item(build_identity, "SE,ChipID");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "SE,ChipID", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "SE,ChipID", plist_copy(node));
		}
	}
	node = NULL;

	/* Savage,ChipID - Used for Savage firmware request */
	node = plist_dict_get_item(build_identity, "Savage,ChipID");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "Savage,ChipID", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "Savage,ChipID", plist_copy(node));
		}
	}
	node = NULL;

	/* add Savage,PatchEpoch - Used for Savage firmware request */
	node = plist_dict_get_item(build_identity, "Savage,PatchEpoch");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "Savage,PatchEpoch", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "Savage,PatchEpoch", plist_copy(node));
		}
	}
	node = NULL;

	/* Yonkers,BoardID - Used for Yonkers firmware request */
	node = plist_dict_get_item(build_identity, "Yonkers,BoardID");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "Yonkers,BoardID", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "Yonkers,BoardID", plist_copy(node));
		}
	}
	node = NULL;

	/* Yonkers,ChipID - Used for Yonkers firmware request */
	node = plist_dict_get_item(build_identity, "Yonkers,ChipID");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "Yonkers,ChipID", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "Yonkers,ChipID", plist_copy(node));
		}
	}
	node = NULL;

	/* add Yonkers,PatchEpoch - Used for Yonkers firmware request */
	node = plist_dict_get_item(build_identity, "Yonkers,PatchEpoch");
	if (node) {
		if (plist_get_node_type(node) == PLIST_STRING) {
			char *strval = NULL;
			int intval = 0;
			plist_get_string_val(node, &strval);
			sscanf(strval, "%x", &intval);
			plist_dict_set_item(parameters, "Yonkers,PatchEpoch", plist_new_uint(intval));
		} else {
			plist_dict_set_item(parameters, "Yonkers,PatchEpoch", plist_copy(node));
		}
	}
	node = NULL;

	/* add Rap,BoardID */
	node = plist_dict_get_item(build_identity, "Rap,BoardID");
	if (node) {
		plist_dict_set_item(parameters, "Rap,BoardID", plist_copy(node));
	}
	node = NULL;

	/* add Rap,ChipID */
	node = plist_dict_get_item(build_identity, "Rap,ChipID");
	if (node) {
		plist_dict_set_item(parameters, "Rap,ChipID", plist_copy(node));
	}
	node = NULL;

	/* add Rap,SecurityDomain */
	node = plist_dict_get_item(build_identity, "Rap,SecurityDomain");
	if (node) {
		plist_dict_set_item(parameters, "Rap,SecurityDomain", plist_copy(node));
	}
	node = NULL;

	/* add eUICC,ChipID */
	node = plist_dict_get_item(build_identity, "eUICC,ChipID");
	if (node) {
		plist_dict_set_item(parameters, "eUICC,ChipID", plist_copy(node));
	}
	node = NULL;

	node = plist_dict_get_item(build_identity, "PearlCertificationRootPub");
	if (node) {
		plist_dict_set_item(parameters, "PearlCertificationRootPub", plist_copy(node));
	}
	node = NULL;

	/* add build identity manifest dictionary */
	node = plist_dict_get_item(build_identity, "Manifest");
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to find Manifest node\n");
		return -1;
	}
	plist_dict_set_item(parameters, "Manifest", plist_copy(node));

	return 0;
}

int tss_request_add_ap_img4_tags(plist_t request, plist_t parameters) {
	plist_t node = NULL;

	if (!parameters) {
		error("ERROR: Missing required AP parameters\n");
		return -1;
	}

	/* Ap,OSLongVersion */
	node = plist_dict_get_item(parameters, "Ap,OSLongVersion");
	if (node) {
		plist_dict_set_item(request, "Ap,OSLongVersion", plist_copy(node));
	}

	/* ApNonce */
	node = plist_dict_get_item(parameters, "ApNonce");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		error("ERROR: Unable to find required ApNonce in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "ApNonce", plist_copy(node));
	node = NULL;

	plist_dict_set_item(request, "@ApImg4Ticket", plist_new_bool(1));

	/* ApSecurityMode */
	node = plist_dict_get_item(request, "ApSecurityMode");
	if (!node) {
		/* copy from parameters if available */
		node = plist_dict_get_item(parameters, "ApSecurityMode");
		if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
			error("ERROR: Unable to find required ApSecurityMode in parameters\n");
			return -1;
		}
		plist_dict_set_item(request, "ApSecurityMode", plist_copy(node));
		node = NULL;
	}

	node = plist_dict_get_item(request, "ApProductionMode");
	if (!node) {
		/* ApProductionMode */
		node = plist_dict_get_item(parameters, "ApProductionMode");
		if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
			error("ERROR: Unable to find required ApProductionMode in parameters\n");
			return -1;
		}
		plist_dict_set_item(request, "ApProductionMode", plist_copy(node));
		node = NULL;
	}

	/* ApSepNonce */
	node = plist_dict_get_item(parameters, "ApSepNonce");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		error("ERROR: Unable to find required ApSepNonce in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "SepNonce", plist_copy(node));
	node = NULL;

	/* PearlCertificationRootPub */
	node = plist_dict_get_item(parameters, "PearlCertificationRootPub");
	if (node) {
		plist_dict_set_item(request, "PearlCertificationRootPub", plist_copy(node));
	}

	return 0;
}

int tss_request_add_ap_img3_tags(plist_t request, plist_t parameters) {
	plist_t node = NULL;

	if (!parameters) {
		error("ERROR: Missing required AP parameters\n");
		return -1;
	}

	/* ApNonce */
	node = plist_dict_get_item(parameters, "ApNonce");
	if (node) {
		if (plist_get_node_type(node) != PLIST_DATA) {
			error("ERROR: Unable to find required ApNonce in parameters\n");
			return -1;
		}
		plist_dict_set_item(request, "ApNonce", plist_copy(node));
		node = NULL;
	}

	/* @APTicket */
	plist_dict_set_item(request, "@APTicket", plist_new_bool(1));

	/* ApBoardID */
	node = plist_dict_get_item(request, "ApBoardID");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		error("ERROR: Unable to find required ApBoardID in request\n");
		return -1;
	}
	node = NULL;

	/* ApChipID */
	node = plist_dict_get_item(request, "ApChipID");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		error("ERROR: Unable to find required ApChipID in request\n");
		return -1;
	}
	node = NULL;

	/* ApSecurityDomain */
	node = plist_dict_get_item(request, "ApSecurityDomain");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		error("ERROR: Unable to find required ApSecurityDomain in request\n");
		return -1;
	}
	node = NULL;

	/* ApProductionMode */
	node = plist_dict_get_item(parameters, "ApProductionMode");
	if (!node || plist_get_node_type(node) != PLIST_BOOLEAN) {
		error("ERROR: Unable to find required ApProductionMode in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "ApProductionMode", plist_copy(node));
	node = NULL;

	return 0;
}

int tss_request_add_common_tags(plist_t request, plist_t parameters, plist_t overrides) {
	plist_t node = NULL;

	/* ApECID */
	node = plist_dict_get_item(parameters, "ApECID");
	if (node) {
		plist_dict_set_item(request, "ApECID", plist_copy(node));
	}
	node = NULL;

	/* UniqueBuildID */
	node = plist_dict_get_item(parameters, "UniqueBuildID");
	if (node) {
		plist_dict_set_item(request, "UniqueBuildID", plist_copy(node));
	}
	node = NULL;

	/* ApChipID */
	node = plist_dict_get_item(parameters, "ApChipID");
	if (node) {
		plist_dict_set_item(request, "ApChipID", plist_copy(node));
	}
	node = NULL;

	/* ApBoardID */
	node = plist_dict_get_item(parameters, "ApBoardID");
	if (node) {
		plist_dict_set_item(request, "ApBoardID", plist_copy(node));
	}
	node = NULL;

	/* ApSecurityDomain */
	node = plist_dict_get_item(parameters, "ApSecurityDomain");
	if (node) {
		plist_dict_set_item(request, "ApSecurityDomain", plist_copy(node));
	}
	node = NULL;

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

static void tss_entry_apply_restore_request_rules(plist_t tss_entry, plist_t parameters, plist_t rules)
{
	if (!tss_entry || !rules) {
		return;
	}
	if (plist_get_node_type(tss_entry) != PLIST_DICT) {
		return;
	}
	if (plist_get_node_type(rules) != PLIST_ARRAY) {
		return;
	}

	uint32_t i;
	for (i = 0; i < plist_array_get_size(rules); i++) {
		plist_t rule = plist_array_get_item(rules, i);
		plist_t conditions = plist_dict_get_item(rule, "Conditions");
		plist_dict_iter iter = NULL;
		plist_dict_new_iter(conditions, &iter);
		char* key = NULL;
		plist_t value = NULL;
		plist_t value2 = NULL;
		int conditions_fulfilled = 1;
		while (conditions_fulfilled) {
			plist_dict_next_item(conditions, iter, &key, &value);
			if (key == NULL)
				break;
			if (!strcmp(key, "ApRawProductionMode")) {
				value2 = plist_dict_get_item(parameters, "ApProductionMode");
			} else if (!strcmp(key, "ApCurrentProductionMode")) {
				value2 = plist_dict_get_item(parameters, "ApProductionMode");
			} else if (!strcmp(key, "ApRawSecurityMode")) {
				value2 = plist_dict_get_item(parameters, "ApSecurityMode");
			} else if (!strcmp(key, "ApRequiresImage4")) {
				value2 = plist_dict_get_item(parameters, "ApSupportsImg4");
			} else if (!strcmp(key, "ApDemotionPolicyOverride")) {
				value2 = plist_dict_get_item(parameters, "DemotionPolicy");
			} else if (!strcmp(key, "ApInRomDFU")) {
				value2 = plist_dict_get_item(parameters, "ApInRomDFU");
			} else {
				error("WARNING: Unhandled condition '%s' while parsing RestoreRequestRules\n", key);
				value2 = NULL;
			}
			if (value2) {
				conditions_fulfilled = plist_compare_node_value(value, value2);
			} else {
				conditions_fulfilled = 0;
			}
			free(key);
		}
		free(iter);
		iter = NULL;

		if (!conditions_fulfilled) {
			continue;
		}

		plist_t actions = plist_dict_get_item(rule, "Actions");
		plist_dict_new_iter(actions, &iter);
		while (1) {
			plist_dict_next_item(actions, iter, &key, &value);
			if (key == NULL)
				break;
			uint8_t bv = 255;
			plist_get_bool_val(value, &bv);
			if (bv != 255) {
				value2 = plist_dict_get_item(tss_entry, key);
				if (value2) {
					plist_dict_remove_item(tss_entry, key);
				}
				debug("DEBUG: Adding %s=%s to TSS entry\n", key, (bv) ? "true" : "false");
				plist_dict_set_item(tss_entry, key, plist_new_bool(bv));
			}
			free(key);
		}
	}
}

int tss_request_add_ap_recovery_tags(plist_t request, plist_t parameters, plist_t overrides) {
	/* loop over components from build manifest */
	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find restore manifest\n");
		return -1;
	}

	/* add components to request */
	char* key = NULL;
	plist_t manifest_entry = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (1) {
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			return -1;
		}

		/* do not populate BaseBandFirmware, only in basebaseband request */
		if ((strcmp(key, "BasebandFirmware") == 0)) {
			free(key);
			continue;
		}

		// Compared to ac2, not needed for RecoveryOSRootTicket
		if ((strcmp(key, "SE,UpdatePayload") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "BaseSystem") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "ANS") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,AudioBootChime") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,CIO") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,RestoreCIO") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,RestoreTMU") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,TMU") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,rOSLogo1") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "Ap,rOSLogo2") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "AppleLogo") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "DCP") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "LLB") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RecoveryMode") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreANS") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreDCP") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreDeviceTree") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreKernelCache") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreLogo") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreRamDisk") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "RestoreSEP") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "SEP") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "ftap") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "ftsp") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "iBEC") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "iBSS") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "rfta") == 0)) {
			free(key);
			continue;
		}
		if ((strcmp(key, "rfts") == 0)) {
			free(key);
			continue;
		}

		/* FIXME: only used with diagnostics firmware */
		if (strcmp(key, "Diags") == 0) {
			free(key);
			continue;
		}

		if (_plist_dict_get_bool(parameters, "_OnlyFWComponents")) {
			if (!_plist_dict_get_bool(manifest_entry, "Trusted")) {
				debug("DEBUG: %s: Skipping '%s' as it is not trusted", __func__, key);
				continue;
			}

			plist_t info_dict = plist_dict_get_item(manifest_entry, "Info");
			if (!_plist_dict_get_bool(info_dict, "IsFirmwarePayload") && !_plist_dict_get_bool(info_dict, "IsSecondaryFirmwarePayload") && !_plist_dict_get_bool(info_dict, "IsFUDFirmware")) {
				debug("DEBUG: %s: Skipping '%s' as it is neither firmware nor secondary nor FUD firmware payload\n", __func__, key);
				continue;
			}
		}

		/* copy this entry */
		plist_t tss_entry = plist_copy(manifest_entry);

		/* remove obsolete Info node */
		plist_dict_remove_item(tss_entry, "Info");

		/* handle RestoreRequestRules */
		plist_t rules = plist_access_path(manifest_entry, 2, "Info", "RestoreRequestRules");
		if (rules) {
			debug("DEBUG: Applying restore request rules for entry %s\n", key);
			tss_entry_apply_restore_request_rules(tss_entry, parameters, rules);
		}

		/* Make sure we have a Digest key for Trusted items even if empty */
		plist_t node = plist_dict_get_item(manifest_entry, "Trusted");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			uint8_t trusted;
			plist_get_bool_val(node, &trusted);
			if (trusted && !plist_access_path(manifest_entry, 1, "Digest")) {
				debug("DEBUG: No Digest data, using empty value for entry %s\n", key);
				plist_dict_set_item(tss_entry, "Digest", plist_new_data(NULL, 0));
			}
		}

		/* finally add entry to request */
		plist_dict_set_item(request, key, tss_entry);

		free(key);
	}
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_ap_tags(plist_t request, plist_t parameters, plist_t overrides) {
	/* loop over components from build manifest */
	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: Unable to find restore manifest\n");
		return -1;
	}

	/* add components to request */
	char* key = NULL;
	plist_t manifest_entry = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (1) {
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			return -1;
		}

		/* do not populate BaseBandFirmware, only in basebaseband request */
		if ((strcmp(key, "BasebandFirmware") == 0)) {
			free(key);
			continue;
		}

		// Compared to ac2, not needed
		if ((strcmp(key, "SE,UpdatePayload") == 0)) {
			free(key);
			continue;
		}

		// Compared to ac2, not needed
		if ((strcmp(key, "BaseSystem") == 0)) {
			free(key);
			continue;
		}

		/* FIXME: only used with diagnostics firmware */
		if (strcmp(key, "Diags") == 0) {
			free(key);
			continue;
		}

		if (_plist_dict_get_bool(parameters, "_OnlyFWComponents")) {
			if (!_plist_dict_get_bool(manifest_entry, "Trusted")) {
				debug("DEBUG: %s: Skipping '%s' as it is not trusted", __func__, key);
				continue;
			}

			plist_t info_dict = plist_dict_get_item(manifest_entry, "Info");
			if (!_plist_dict_get_bool(info_dict, "IsFirmwarePayload") && !_plist_dict_get_bool(info_dict, "IsSecondaryFirmwarePayload") && !_plist_dict_get_bool(info_dict, "IsFUDFirmware")) {
				debug("DEBUG: %s: Skipping '%s' as it is neither firmware nor secondary nor FUD firmware payload\n", __func__, key);
				continue;
			}
		}

		/* copy this entry */
		plist_t tss_entry = plist_copy(manifest_entry);

		/* remove obsolete Info node */
		plist_dict_remove_item(tss_entry, "Info");

		/* handle RestoreRequestRules */
		plist_t rules = plist_access_path(manifest_entry, 2, "Info", "RestoreRequestRules");
		if (rules) {
			debug("DEBUG: Applying restore request rules for entry %s\n", key);
			tss_entry_apply_restore_request_rules(tss_entry, parameters, rules);
		}

		/* Make sure we have a Digest key for Trusted items even if empty */
		plist_t node = plist_dict_get_item(manifest_entry, "Trusted");
		if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
			uint8_t trusted;
			plist_get_bool_val(node, &trusted);
			if (trusted && !plist_access_path(manifest_entry, 1, "Digest")) {
				debug("DEBUG: No Digest data, using empty value for entry %s\n", key);
				plist_dict_set_item(tss_entry, "Digest", plist_new_data(NULL, 0));
			}
		}

		/* finally add entry to request */
		plist_dict_set_item(request, key, tss_entry);

		free(key);
	}
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_baseband_tags(plist_t request, plist_t parameters, plist_t overrides) {
	plist_t node = NULL;

	/* BbChipID */
	uint64_t bb_chip_id = _plist_dict_get_uint(parameters, "BbChipID");
	if (bb_chip_id) {
		plist_dict_set_item(request, "BbChipID", plist_new_uint(bb_chip_id));
	}

	/* BbProvisioningManifestKeyHash */
	node = plist_dict_get_item(parameters, "BbProvisioningManifestKeyHash");
	if (node) {
		plist_dict_set_item(request, "BbProvisioningManifestKeyHash", plist_copy(node));
	}
	node = NULL;

	/* BbActivationManifestKeyHash - Used by Qualcomm MDM6610 */
	node = plist_dict_get_item(parameters, "BbActivationManifestKeyHash");
	if (node) {
		plist_dict_set_item(request, "BbActivationManifestKeyHash", plist_copy(node));
	}
	node = NULL;

	node = plist_dict_get_item(parameters, "BbCalibrationManifestKeyHash");
	if (node) {
		plist_dict_set_item(request, "BbCalibrationManifestKeyHash", plist_copy(node));
	}
	node = NULL;

	/* BbFactoryActivationManifestKeyHash */
	node = plist_dict_get_item(parameters, "BbFactoryActivationManifestKeyHash");
	if (node) {
		plist_dict_set_item(request, "BbFactoryActivationManifestKeyHash", plist_copy(node));
	}
	node = NULL;

	/* BbFDRSecurityKeyHash */
	node = plist_dict_get_item(parameters, "BbFDRSecurityKeyHash");
	if (node) {
		plist_dict_set_item(request, "BbFDRSecurityKeyHash", plist_copy(node));
	}
	node = NULL;

	/* BbSkeyId - Used by XMM 6180/GSM */
	node = plist_dict_get_item(parameters, "BbSkeyId");
	if (node) {
		plist_dict_set_item(request, "BbSkeyId", plist_copy(node));
	}
	node = NULL;

	/* BbNonce */
	node = plist_dict_get_item(parameters, "BbNonce");
	if (node) {
		plist_dict_set_item(request, "BbNonce", plist_copy(node));
	}
	node = NULL;

	/* @BBTicket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));

	/* BbGoldCertId */
	node = plist_dict_get_item(parameters, "BbGoldCertId");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		error("ERROR: Unable to find required BbGoldCertId in parameters\n");
		return -1;
	}
	node = plist_copy(node);
	uint64_t val;
	plist_get_uint_val(node, &val);
	int32_t bb_cert_id = (int32_t)val;
	plist_set_uint_val(node, bb_cert_id);
	plist_dict_set_item(request, "BbGoldCertId", node);
	node = NULL;

	/* BbSNUM */
	node = plist_dict_get_item(parameters, "BbSNUM");
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		error("ERROR: Unable to find required BbSNUM in parameters\n");
		return -1;
	}
	plist_dict_set_item(request, "BbSNUM", plist_copy(node));
	node = NULL;

	/* BasebandFirmware */
	node = plist_access_path(parameters, 2, "Manifest", "BasebandFirmware");
	if (!node || plist_get_node_type(node) != PLIST_DICT) {
		error("ERROR: Unable to get BasebandFirmware node\n");
		return -1;
	}
	plist_t bbfwdict = plist_copy(node);
	node = NULL;
	if (plist_dict_get_item(bbfwdict, "Info")) {
		plist_dict_remove_item(bbfwdict, "Info");
	}

	if (bb_chip_id == 0x68) {
		/* depending on the BasebandCertId remove certain nodes */
		if (bb_cert_id == 0x26F3FACC || bb_cert_id == 0x5CF2EC4E || bb_cert_id == 0x8399785A) {
			plist_dict_remove_item(bbfwdict, "PSI2-PartialDigest");
			plist_dict_remove_item(bbfwdict, "RestorePSI2-PartialDigest");
		} else {
			plist_dict_remove_item(bbfwdict, "PSI-PartialDigest");
			plist_dict_remove_item(bbfwdict, "RestorePSI-PartialDigest");
		}
	}

	plist_dict_set_item(request, "BasebandFirmware", bbfwdict);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_se_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the SE,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@SE,Ticket", plist_new_bool(1));

	/* add SE,ChipID */
	node = plist_dict_get_item(parameters, "SE,ChipID");
	if (!node || plist_get_node_type(node) != PLIST_UINT) {
		error("ERROR: %s: Unable to find required SE,ChipID in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "SE,ChipID", plist_copy(node));
	node = NULL;

	/* add SE,ID */
	node = plist_dict_get_item(parameters, "SE,ID");
	if (!node) {
		error("ERROR: %s: Unable to find required SE,ID in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "SE,ID", plist_copy(node));
	node = NULL;

	/* add SE,Nonce */
	node = plist_dict_get_item(parameters, "SE,Nonce");
	if (!node) {
		error("ERROR: %s: Unable to find required SE,Nonce in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "SE,Nonce", plist_copy(node));
	node = NULL;

	/* add SE,RootKeyIdentifier */
	node = plist_dict_get_item(parameters, "SE,RootKeyIdentifier");
	if (!node) {
		error("ERROR: %s: Unable to find required SE,RootKeyIdentifier in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "SE,RootKeyIdentifier", plist_copy(node));
	node = NULL;

	/* 'IsDev' determines whether we have Production or Development */
	uint8_t is_dev = 0;
	node = plist_dict_get_item(parameters, "SE,IsDev");
	if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
		plist_get_bool_val(node, &is_dev);
	}

	/* add SE,* components from build manifest to request */
	char* key = NULL;
	plist_t manifest_entry = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (1) {
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			free(key);
			error("ERROR: Unable to fetch BuildManifest entry\n");
			return -1;
		}

		if (strncmp(key, "SE,", 3)) {
			free(key);
			continue;
		}

		/* copy this entry */
		plist_t tss_entry = plist_copy(manifest_entry);

		/* remove Info node */
		plist_dict_remove_item(tss_entry, "Info");

		/* remove Development or Production key/hash node */
		if (is_dev) {
			if (plist_dict_get_item(tss_entry, "ProductionCMAC"))
				plist_dict_remove_item(tss_entry, "ProductionCMAC");
			if (plist_dict_get_item(tss_entry, "ProductionUpdatePayloadHash"))
				plist_dict_remove_item(tss_entry, "ProductionUpdatePayloadHash");
		} else {
			if (plist_dict_get_item(tss_entry, "DevelopmentCMAC"))
				plist_dict_remove_item(tss_entry, "DevelopmentCMAC");
			if (plist_dict_get_item(tss_entry, "DevelopmentUpdatePayloadHash"))
				plist_dict_remove_item(tss_entry, "DevelopmentUpdatePayloadHash");
		}

		/* add entry to request */
		plist_dict_set_item(request, key, tss_entry);

		free(key);
	}
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_savage_tags(plist_t request, plist_t parameters, plist_t overrides, char **component_name)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Savage,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@Savage,Ticket", plist_new_bool(1));

	/* add Savage,UID */
	node = plist_dict_get_item(parameters, "Savage,UID");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,UID in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,UID", plist_copy(node));
	node = NULL;

	/* add SEP */
	node = plist_access_path(manifest_node, 2, "SEP", "Digest");
	if (!node) {
		error("ERROR: Unable to get SEP digest from manifest\n");
		return -1;
	}
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Digest", plist_copy(node));
	plist_dict_set_item(request, "SEP", dict);

	/* add Savage,PatchEpoch */
	node = plist_dict_get_item(parameters, "Savage,PatchEpoch");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,PatchEpoch in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,PatchEpoch", plist_copy(node));
	node = NULL;

	/* add Savage,ChipID */
	node = plist_dict_get_item(parameters, "Savage,ChipID");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,ChipID in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,ChipID", plist_copy(node));
	node = NULL;

	/* add Savage,AllowOfflineBoot */
	node = plist_dict_get_item(parameters, "Savage,AllowOfflineBoot");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,AllowOfflineBoot in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,AllowOfflineBoot", plist_copy(node));
	node = NULL;

	/* add Savage,ReadFWKey */
	node = plist_dict_get_item(parameters, "Savage,ReadFWKey");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,ReadFWKey in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,ReadFWKey", plist_copy(node));
	node = NULL;

	/* add Savage,ProductionMode */
	node = plist_dict_get_item(parameters, "Savage,ProductionMode");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,ProductionMode in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,ProductionMode", plist_copy(node));
	const char *comp_name = NULL;
	uint8_t isprod = 0;
	plist_get_bool_val(node, &isprod);
	node = NULL;

	/* get the right component name */
	comp_name = (isprod) ?  "Savage,B0-Prod-Patch" : "Savage,B0-Dev-Patch";
	node = plist_dict_get_item(parameters, "Savage,Revision");
	if (node && (plist_get_node_type(node) == PLIST_DATA)) {
		unsigned char *savage_rev = NULL;
		uint64_t savage_rev_len = 0;
		plist_get_data_val(node, (char**)&savage_rev, &savage_rev_len);
		if (savage_rev_len > 0) {
			if (((savage_rev[0] | 0x10) & 0xF0) == 0x30) {
				comp_name = (isprod) ? "Savage,B2-Prod-Patch" : "Savage,B2-Dev-Patch";
			} else if ((savage_rev[0] & 0xF0) == 0xA0) {
				comp_name = (isprod) ? "Savage,BA-Prod-Patch" : "Savage,BA-Dev-Patch";
			}
		}
		free(savage_rev);
	}

	/* add Savage,B?-*-Patch */
	node = plist_dict_get_item(manifest_node, comp_name);
	if (!node) {
		error("ERROR: Unable to get %s entry from manifest\n", comp_name);
		return -1;
	}
	dict = plist_copy(node);
	plist_dict_remove_item(dict, "Info");
	plist_dict_set_item(request, comp_name, dict);

	if (component_name) {
		*component_name = strdup(comp_name);
	}

	/* add Savage,Nonce */
	node = plist_dict_get_item(parameters, "Savage,Nonce");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,Nonce in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,Nonce", plist_copy(node));
	node = NULL;

	/* add Savage,ReadECKey */
	node = plist_dict_get_item(parameters, "Savage,ReadECKey");
	if (!node) {
		error("ERROR: %s: Unable to find required Savage,ReadECKey in parameters\n", __func__);
		return -1;
	}
	plist_dict_set_item(request, "Savage,ReadECKey", plist_copy(node));
	node = NULL;

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_yonkers_tags(plist_t request, plist_t parameters, plist_t overrides, char **component_name)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Savage,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@Yonkers,Ticket", plist_new_bool(1));

	/* add SEP */
	node = plist_access_path(manifest_node, 2, "SEP", "Digest");
	if (!node) {
		error("ERROR: Unable to get SEP digest from manifest\n");
		return -1;
	}
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Digest", plist_copy(node));
	plist_dict_set_item(request, "SEP", dict);

	{
		static const char *keys[] = {"Yonkers,AllowOfflineBoot", "Yonkers,BoardID", "Yonkers,ChipID", "Yonkers,ECID", "Yonkers,Nonce", "Yonkers,PatchEpoch", "Yonkers,ProductionMode", "Yonkers,ReadECKey", "Yonkers,ReadFWKey", };
		int i;
		for (i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); ++i) {
			node = plist_dict_get_item(parameters, keys[i]);
			if (!node) {
				error("ERROR: %s: Unable to find required %s in parameters\n", __func__, keys[i]);
			}
			plist_dict_set_item(request, keys[i], plist_copy(node));
			node = NULL;
		}
	}

	char *comp_name = NULL;
	plist_t comp_node = NULL;
	uint8_t isprod = 1;
	uint64_t fabrevision = (uint64_t)-1;

	node = plist_dict_get_item(parameters, "Yonkers,ProductionMode");
	if (node && (plist_get_node_type(node) == PLIST_BOOLEAN)) {
		plist_get_bool_val(node, &isprod);
	}

	node = plist_dict_get_item(parameters, "Yonkers,FabRevision");
	if (node && (plist_get_node_type(node) == PLIST_UINT)) {
		plist_get_uint_val(node, &fabrevision);
	}

	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (iter) {
		node = NULL;
		comp_name = NULL;
		plist_dict_next_item(manifest_node, iter, &comp_name, &node);
		if (comp_name == NULL) {
			node = NULL;
			break;
		}
		if (strncmp(comp_name, "Yonkers,", 8) == 0) {
			int target_node = 1;
			plist_t sub_node;
			if ((sub_node = plist_dict_get_item(node, "EPRO")) != NULL && plist_get_node_type(sub_node) == PLIST_BOOLEAN) {
				uint8_t b = 0;
				plist_get_bool_val(sub_node, &b);
				target_node &= ((isprod) ? b : !b);
			}
			if ((sub_node = plist_dict_get_item(node, "FabRevision")) != NULL && plist_get_node_type(sub_node) == PLIST_UINT) {
				uint64_t v = 0;
				plist_get_uint_val(sub_node, &v);
				target_node &= (v == fabrevision);
			}
			if (target_node) {
				comp_node = node;
				break;
			}
		}
		free(comp_name);
	}
	free(iter);

	if (comp_name == NULL) {
		error("ERROR: No Yonkers node for %s/%lu\n", (isprod) ? "Production" : "Development", (unsigned long)fabrevision);
		return -1;
	}

	/* add Yonkers,SysTopPatch* */
	if (comp_node != NULL) {
		plist_t comp_dict = plist_copy(comp_node);
		plist_dict_remove_item(comp_dict, "Info");
		plist_dict_set_item(request, comp_name, comp_dict);
	}

	if (component_name) {
		*component_name = comp_name;
	} else {
		free(comp_name);
	}

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_vinyl_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the eUICC,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@eUICC,Ticket", plist_new_bool(1));

	node = plist_dict_get_item(parameters, "eUICC,ChipID");
	if (node) {
		plist_dict_set_item(request, "eUICC,ChipID", plist_copy(node));
	}
	node = plist_dict_get_item(parameters, "eUICC,EID");
	if (node) {
		plist_dict_set_item(request, "eUICC,EID", plist_copy(node));
	}
	node = plist_dict_get_item(parameters, "eUICC,RootKeyIdentifier");
	if (node) {
		plist_dict_set_item(request, "eUICC,RootKeyIdentifier", plist_copy(node));
	}

	/* set Nonce for eUICC,Gold component */
	node = plist_dict_get_item(parameters, "EUICCGoldNonce");
	if (node) {
		plist_t n = plist_dict_get_item(request, "eUICC,Gold");
		if (n) {
			plist_dict_set_item(n, "Nonce", plist_copy(node));
		}
	}

	/* set Nonce for eUICC,Main component */
	node = plist_dict_get_item(parameters, "EUICCMainNonce");
	if (node) {
		plist_t n = plist_dict_get_item(request, "eUICC,Main");
		if (n) {
			plist_dict_set_item(n, "Nonce", plist_copy(node));
		}
	}

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_rose_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Rap,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@Rap,Ticket", plist_new_bool(1));

	uint64_t u64val = 0;
	uint8_t bval = 0;

	u64val = _plist_dict_get_uint(parameters, "Rap,BoardID");
	plist_dict_set_item(request, "Rap,BoardID", plist_new_uint(u64val));

	u64val = _plist_dict_get_uint(parameters, "Rap,ChipID");
	plist_dict_set_item(request, "Rap,ChipID", plist_new_uint(u64val));

	u64val = _plist_dict_get_uint(parameters, "Rap,ECID");
	plist_dict_set_item(request, "Rap,ECID", plist_new_uint(u64val));

	node = plist_dict_get_item(parameters, "Rap,Nonce");
	if (node) {
		plist_dict_set_item(request, "Rap,Nonce", plist_copy(node));
	}

	bval = _plist_dict_get_bool(parameters, "Rap,ProductionMode");
	plist_dict_set_item(request, "Rap,ProductionMode", plist_new_bool(bval));

	u64val = _plist_dict_get_uint(parameters, "Rap,SecurityDomain");
	plist_dict_set_item(request, "Rap,SecurityDomain", plist_new_uint(u64val));

	bval = _plist_dict_get_bool(parameters, "Rap,SecurityMode");
	plist_dict_set_item(request, "Rap,SecurityMode", plist_new_bool(bval));

	char *comp_name = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (iter) {
		node = NULL;
		comp_name = NULL;
		plist_dict_next_item(manifest_node, iter, &comp_name, &node);
		if (comp_name == NULL) {
			node = NULL;
			break;
		}
		if (strncmp(comp_name, "Rap,", 4) == 0) {
			plist_t manifest_entry = plist_copy(node);

			/* handle RestoreRequestRules */
			plist_t rules = plist_access_path(manifest_entry, 2, "Info", "RestoreRequestRules");
			if (rules) {
				debug("DEBUG: Applying restore request rules for entry %s\n", comp_name);
				tss_entry_apply_restore_request_rules(manifest_entry, parameters, rules);
			}

			/* Make sure we have a Digest key for Trusted items even if empty */
			plist_t node = plist_dict_get_item(manifest_entry, "Trusted");
			if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
				uint8_t trusted;
				plist_get_bool_val(node, &trusted);
				if (trusted && !plist_access_path(manifest_entry, 1, "Digest")) {
					debug("DEBUG: No Digest data, using empty value for entry %s\n", comp_name);
					plist_dict_set_item(manifest_entry, "Digest", plist_new_data(NULL, 0));
				}
			}

			plist_dict_remove_item(manifest_entry, "Info");

			/* finally add entry to request */
			plist_dict_set_item(request, comp_name, manifest_entry);
		}
		free(comp_name);
	}
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_veridian_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Rap,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@BMU,Ticket", plist_new_bool(1));

	uint64_t u64val = 0;
	uint8_t bval = 0;

	u64val = _plist_dict_get_uint(parameters, "BMU,BoardID");
	plist_dict_set_item(request, "BMU,BoardID", plist_new_uint(u64val));

	u64val = _plist_dict_get_uint(parameters, "ChipID");
	plist_dict_set_item(request, "BMU,ChipID", plist_new_uint(u64val));

	node = plist_dict_get_item(parameters, "Nonce");
	if (node) {
		plist_dict_set_item(request, "BMU,Nonce", plist_copy(node));
	}

	bval = _plist_dict_get_bool(parameters, "ProductionMode");
	plist_dict_set_item(request, "BMU,ProductionMode", plist_new_bool(bval));

	u64val = _plist_dict_get_uint(parameters, "UniqueID");
	plist_dict_set_item(request, "BMU,UniqueID", plist_new_uint(u64val));

	char *comp_name = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (iter) {
		node = NULL;
		comp_name = NULL;
		plist_dict_next_item(manifest_node, iter, &comp_name, &node);
		if (comp_name == NULL) {
			node = NULL;
			break;
		}
		if (strncmp(comp_name, "BMU,", 4) == 0) {
			plist_t manifest_entry = plist_copy(node);

			/* handle RestoreRequestRules */
			plist_t rules = plist_access_path(manifest_entry, 2, "Info", "RestoreRequestRules");
			if (rules) {
				debug("DEBUG: Applying restore request rules for entry %s\n", comp_name);
				tss_entry_apply_restore_request_rules(manifest_entry, parameters, rules);
			}

			/* Make sure we have a Digest key for Trusted items even if empty */
			plist_t node = plist_dict_get_item(manifest_entry, "Trusted");
			if (node && plist_get_node_type(node) == PLIST_BOOLEAN) {
				uint8_t trusted;
				plist_get_bool_val(node, &trusted);
				if (trusted && !plist_access_path(manifest_entry, 1, "Digest")) {
					debug("DEBUG: No Digest data, using empty value for entry %s\n", comp_name);
					plist_dict_set_item(manifest_entry, "Digest", plist_new_data(NULL, 0));
				}
			}

			plist_dict_remove_item(manifest_entry, "Info");

			/* finally add entry to request */
			plist_dict_set_item(request, comp_name, manifest_entry);
		}
		free(comp_name);
	}
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

static size_t tss_write_callback(char* data, size_t size, size_t nmemb, tss_response* response) {
	size_t total = size * nmemb;
	if (total != 0) {
		response->content = realloc(response->content, response->length + total + 1);
		memcpy(response->content + response->length, data, total);
		response->content[response->length + total] = '\0';
		response->length += total;
	}

	return total;
}

plist_t tss_request_send(plist_t tss_request, const char* server_url_string) {

	if (idevicerestore_debug) {
		debug_plist(tss_request);
	}

	char* request = NULL;
	int status_code = -1;
	int retry = 0;
	int max_retries = 15;
	unsigned int size = 0;
	char curl_error_message[CURL_ERROR_SIZE];

	const char* urls[6] = {
		"https://gs.apple.com/TSS/controller?action=2",
		"https://17.171.36.30/TSS/controller?action=2",
		"https://17.151.36.30/TSS/controller?action=2",
		"http://gs.apple.com/TSS/controller?action=2",
		"http://17.171.36.30/TSS/controller?action=2",
		"http://17.151.36.30/TSS/controller?action=2"
	};

	plist_to_xml(tss_request, &request, &size);

	tss_response* response = NULL;
	memset(curl_error_message, '\0', CURL_ERROR_SIZE);

	while (retry++ < max_retries) {
		response = NULL;
		CURL* handle = curl_easy_init();
		if (handle == NULL) {
			break;
		}
		struct curl_slist* header = NULL;
		header = curl_slist_append(header, "Cache-Control: no-cache");
		header = curl_slist_append(header, "Content-type: text/xml; charset=\"utf-8\"");
		header = curl_slist_append(header, "Expect:");

		response = malloc(sizeof(tss_response));
		if (response == NULL) {
			fprintf(stderr, "Unable to allocate sufficient memory\n");
			return NULL;
		}

		response->length = 0;
		response->content = malloc(1);
		response->content[0] = '\0';

		/* disable SSL verification to allow download from untrusted https locations */
		curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0);

		curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, curl_error_message);
		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, (curl_write_callback)&tss_write_callback);
		curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);
		curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request);
		curl_easy_setopt(handle, CURLOPT_USERAGENT, USER_AGENT_STRING);
		curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(request));
		if (server_url_string) {
			curl_easy_setopt(handle, CURLOPT_URL, server_url_string);
		} else {
			int url_index = (retry - 1) % 6;
			curl_easy_setopt(handle, CURLOPT_URL, urls[url_index]);
			info("Request URL set to %s\n", urls[url_index]);
		}

		info("Sending TSS request attempt %d... ", retry);

		curl_easy_perform(handle);
		curl_slist_free_all(header);
		curl_easy_cleanup(handle);

		if (strstr(response->content, "MESSAGE=SUCCESS")) {
			status_code = 0;
			info("response successfully received\n");
			break;
		}

		if (response->length > 0) {
			error("TSS server returned: %s\n", response->content);
		}

		char* status = strstr(response->content, "STATUS=");
		if (status) {
			sscanf(status+7, "%d&%*s", &status_code);
		}
		if (status_code == -1) {
			error("%s\n", curl_error_message);
			// no status code in response. retry
			free(response->content);
			free(response);
			response = NULL;
			sleep(2);
			continue;
		} else if (status_code == 8) {
			// server error (invalid bb request?)
			break;
		} else if (status_code == 49) {
			// server error (invalid bb data, e.g. BbSNUM?)
			break;
		} else if (status_code == 69 || status_code == 94) {
			// This device isn't eligible for the requested build.
			break;
		} else if (status_code == 100) {
			// server error, most likely the request was malformed
			break;
		} else if (status_code == 126) {
			// An internal error occured, most likely the request was malformed
			break;
		} else {
			error("ERROR: tss_send_request: Unhandled status code %d\n", status_code);
		}
	}

	if (status_code != 0) {
		if (response && strstr(response->content, "MESSAGE=") != NULL) {
			char* message = strstr(response->content, "MESSAGE=") + strlen("MESSAGE=");
			error("ERROR: TSS request failed (status=%d, message=%s)\n", status_code, message);
		} else {
			error("ERROR: TSS request failed: %s (status=%d)\n", curl_error_message, status_code);
		}
		free(request);
		if (response) free(response->content);
		if (response) free(response);
		return NULL;
	}

	char* tss_data = strstr(response->content, "<?xml");
	if (tss_data == NULL) {
		error("ERROR: Incorrectly formatted TSS response\n");
		free(request);
		free(response->content);
		free(response);
		return NULL;
	}

	uint32_t tss_size = 0;
	plist_t tss_response = NULL;
	tss_size = response->length - (tss_data - response->content);
	plist_from_xml(tss_data, tss_size, &tss_response);
	free(response->content);
	free(response);

	if (idevicerestore_debug) {
		debug_plist(tss_response);
	}

	free(request);

	return tss_response;
}

static int tss_response_get_data_by_key(plist_t response, const char* name, unsigned char** buffer, unsigned int* length) {

	plist_t node = plist_dict_get_item(response, name);
	if (!node || plist_get_node_type(node) != PLIST_DATA) {
		debug("DEBUG: %s: No entry '%s' in TSS response\n", __func__, name);
		return -1;
	}

	char *data = NULL;
	uint64_t len = 0;
	plist_get_data_val(node, &data, &len);
	if (data) {
		*length = (unsigned int)len;
		*buffer = (unsigned char*)data;
		return 0;
	} else {
		error("ERROR: Unable to get %s data from TSS response\n", name);
		return -1;
	}
}

int tss_response_get_ap_img4_ticket(plist_t response, unsigned char** ticket, unsigned int* length) {
	return tss_response_get_data_by_key(response, "ApImg4Ticket", ticket, length);
}

int tss_response_get_ap_ticket(plist_t response, unsigned char** ticket, unsigned int* length) {
	return tss_response_get_data_by_key(response, "APTicket", ticket, length);
}

int tss_response_get_baseband_ticket(plist_t response, unsigned char** ticket, unsigned int* length) {
	return tss_response_get_data_by_key(response, "BBTicket", ticket, length);
}

int tss_response_get_path_by_entry(plist_t response, const char* entry, char** path) {
	char* path_string = NULL;
	plist_t path_node = NULL;
	plist_t entry_node = NULL;

	*path = NULL;

	entry_node = plist_dict_get_item(response, entry);
	if (!entry_node || plist_get_node_type(entry_node) != PLIST_DICT) {
		debug("DEBUG: %s: No entry '%s' in TSS response\n", __func__, entry);
		return -1;
	}

	path_node = plist_dict_get_item(entry_node, "Path");
	if (!path_node || plist_get_node_type(path_node) != PLIST_STRING) {
		debug("NOTE: Unable to find %s path in TSS entry\n", entry);
		return -1;
	}
	plist_get_string_val(path_node, &path_string);

	*path = path_string;
	return 0;
}

int tss_response_get_blob_by_path(plist_t tss, const char* path, unsigned char** blob) {
	uint32_t i = 0;
	uint32_t tss_size = 0;
	uint64_t blob_size = 0;
	char* entry_key = NULL;
	char* blob_data = NULL;
	char* entry_path = NULL;
	plist_t tss_entry = NULL;
	plist_t blob_node = NULL;
	plist_t path_node = NULL;
	plist_dict_iter iter = NULL;

	*blob = NULL;

	plist_dict_new_iter(tss, &iter);
	tss_size = plist_dict_get_size(tss);
	for (i = 0; i < tss_size; i++) {
		plist_dict_next_item(tss, iter, &entry_key, &tss_entry);
		if (entry_key == NULL)
			break;

		if (!tss_entry || plist_get_node_type(tss_entry) != PLIST_DICT) {
			continue;
		}

		path_node = plist_dict_get_item(tss_entry, "Path");
		if (!path_node || plist_get_node_type(path_node) != PLIST_STRING) {
			error("ERROR: Unable to find TSS path node in entry %s\n", entry_key);
			free(iter);
			return -1;
		}

		plist_get_string_val(path_node, &entry_path);
		if (strcmp(path, entry_path) == 0) {
			blob_node = plist_dict_get_item(tss_entry, "Blob");
			if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
				error("ERROR: Unable to find TSS blob node in entry %s\n", entry_key);
				free(iter);
				return -1;
			}
			plist_get_data_val(blob_node, &blob_data, &blob_size);
			break;
		}

		free(entry_key);
	}
	free(iter);

	if (blob_data == NULL || blob_size <= 0) {
		return -1;
	}

	*blob = (unsigned char*)blob_data;
	return 0;
}

int tss_response_get_blob_by_entry(plist_t response, const char* entry, unsigned char** blob) {
	uint64_t blob_size = 0;
	char* blob_data = NULL;
	plist_t blob_node = NULL;
	plist_t tss_entry = NULL;

	*blob = NULL;

	tss_entry = plist_dict_get_item(response, entry);
	if (!tss_entry || plist_get_node_type(tss_entry) != PLIST_DICT) {
		debug("DEBUG: %s: No entry '%s' in TSS response\n", __func__, entry);
		return -1;
	}

	blob_node = plist_dict_get_item(tss_entry, "Blob");
	if (!blob_node || plist_get_node_type(blob_node) != PLIST_DATA) {
		error("ERROR: Unable to find blob in %s entry\n", entry);
		return -1;
	}
	plist_get_data_val(blob_node, &blob_data, &blob_size);

	*blob = (unsigned char*)blob_data;
	return 0;
}
