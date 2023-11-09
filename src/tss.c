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

#define AUTH_VERSION "914.120.2"

#ifdef WIN32
#define TSS_CLIENT_VERSION_STRING "libauthinstall_Win-"AUTH_VERSION"" 
#else
#define TSS_CLIENT_VERSION_STRING "libauthinstall-"AUTH_VERSION""
#endif
#define ECID_STRSIZE 0x20

typedef struct {
	int length;
	char* content;
} tss_response;

char* ecid_to_string(uint64_t ecid)
{
	char* ecid_string = malloc(ECID_STRSIZE);
	memset(ecid_string, '\0', ECID_STRSIZE);
	if (ecid == 0) {
		error("ERROR: Invalid ECID passed.\n");
		return NULL;
	}
	snprintf(ecid_string, ECID_STRSIZE, "%"PRIu64, ecid);
	return ecid_string;
}

plist_t tss_request_new(plist_t overrides)
{
	plist_t request = plist_new_dict();

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
	plist_dict_set_item(request, "@ApImg4Ticket", plist_new_bool(1));

	if (_plist_dict_copy_bool(request, parameters, "Ap,LocalBoot", NULL) < 0) {
		error("ERROR: Unable to find required Ap,LocalBoot in parameters\n");
		return -1;
	}

	if (_plist_dict_copy_item(request, parameters, "Ap,LocalPolicy", NULL) < 0) {
		error("ERROR: Unable to find required Ap,LocalPolicy in parameters\n");
		return -1;
	}

	if (_plist_dict_copy_data(request, parameters, "Ap,NextStageIM4MHash", NULL) < 0) {
		error("ERROR: Unable to find required Ap,NextStageIM4MHash in parameters\n");
		return -1;
	}

	_plist_dict_copy_data(request, parameters, "Ap,RecoveryOSPolicyNonceHash", NULL);
	_plist_dict_copy_data(request, parameters, "Ap,VolumeUUID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApECID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApChipID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApBoardID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApSecurityDomain", NULL);
	_plist_dict_copy_data(request, parameters, "ApNonce", NULL);

	if (!plist_dict_get_item(request, "ApSecurityMode")) {
		/* copy from parameters if available */
		if (_plist_dict_copy_bool(request, parameters, "ApSecurityMode", NULL) < 0) {
			error("ERROR: Unable to find required ApSecurityMode in parameters\n");
			return -1;
		}
	}
	if (!plist_dict_get_item(request, "ApProductionMode")) {
		/* copy from parameters if available */
		if (_plist_dict_copy_bool(request, parameters, "ApProductionMode", NULL) < 0) {
			error("ERROR: Unable to find required ApProductionMode in parameters\n");
			return -1;
		}
	}

	return 0;
}

int tss_parameters_add_from_manifest(plist_t parameters, plist_t build_identity, bool include_manifest)
{
	plist_t node = NULL;

	if (_plist_dict_copy_data(parameters, build_identity, "UniqueBuildID", NULL) < 0) {
		error("ERROR: Unable to find UniqueBuildID node\n");
		return -1;
	}

	_plist_dict_copy_string(parameters, build_identity, "Ap,OSLongVersion", NULL);

	if (_plist_dict_copy_uint(parameters, build_identity, "ApChipID", NULL) < 0) {;
		error("ERROR: Unable to find ApChipID node\n");
		return -1;
	}

	if (_plist_dict_copy_uint(parameters, build_identity, "ApBoardID", NULL) < 0) {
		error("ERROR: Unable to find ApBoardID node\n");
		return -1;
	}

	_plist_dict_copy_uint(parameters, build_identity, "ApSecurityDomain", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "BMU,BoardID", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "BMU,ChipID", NULL);

	if (_plist_dict_copy_uint(parameters, build_identity, "BbChipID", NULL) < 0) {
		debug("NOTE: Unable to find BbChipID node\n");
	}

	if (_plist_dict_copy_data(parameters, build_identity, "BbProvisioningManifestKeyHash", NULL) < 0) {
		debug("NOTE: Unable to find BbProvisioningManifestKeyHash node\n");
	}

	if (_plist_dict_copy_data(parameters, build_identity, "BbActivationManifestKeyHash", NULL) < 0) {
		debug("NOTE: Unable to find BbActivationManifestKeyHash node\n");
	}

	if (_plist_dict_copy_data(parameters, build_identity, "BbCalibrationManifestKeyHash", NULL) < 0) {
		debug("NOTE: Unable to find BbCalibrationManifestKeyHash node\n");
	}

	if (_plist_dict_copy_data(parameters, build_identity, "BbFactoryActivationManifestKeyHash", NULL) < 0) {
		debug("NOTE: Unable to find BbFactoryActivationManifestKeyHash node\n");
	}

	if (_plist_dict_copy_data(parameters, build_identity, "BbFDRSecurityKeyHash", NULL) < 0) {
		debug("NOTE: Unable to find BbFDRSecurityKeyHash node\n");
	}

	/* BbSkeyId - Used by XMM 6180/GSM */
	if (_plist_dict_copy_data(parameters, build_identity, "BbSkeyId", NULL) < 0) {
		debug("NOTE: Unable to find BbSkeyId node\n");
	}

	/* SE,ChipID - Used for SE firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "SE,ChipID", NULL);

	/* Savage,ChipID - Used for Savage firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "Savage,ChipID", NULL);

	/* add Savage,PatchEpoch - Used for Savage firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "Savage,PatchEpoch", NULL);

	/* Yonkers,BoardID - Used for Yonkers firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "Yonkers,BoardID", NULL);

	/* Yonkers,ChipID - Used for Yonkers firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "Yonkers,ChipID", NULL);

	/* add Yonkers,PatchEpoch - Used for Yonkers firmware request */
	_plist_dict_copy_uint(parameters, build_identity, "Yonkers,PatchEpoch", NULL);

	_plist_dict_copy_uint(parameters, build_identity, "Rap,BoardID", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Rap,ChipID", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Rap,SecurityDomain", NULL);

	_plist_dict_copy_uint(parameters, build_identity, "Baobab,BoardID", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Baobab,ChipID", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Baobab,ManifestEpoch", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Baobab,SecurityDomain", NULL);

	_plist_dict_copy_uint(parameters, build_identity, "eUICC,ChipID", NULL);

	_plist_dict_copy_uint(parameters, build_identity, "NeRDEpoch", NULL);
	_plist_dict_copy_data(parameters, build_identity, "PearlCertificationRootPub", NULL);

	_plist_dict_copy_uint(parameters, build_identity, "Timer,BoardID,1", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Timer,BoardID,2", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Timer,ChipID,1", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Timer,ChipID,2", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Timer,SecurityDomain,1", NULL);
	_plist_dict_copy_uint(parameters, build_identity, "Timer,SecurityDomain,2", NULL);

	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,ChipID", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,Type", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,SubType", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,ProductClass", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,UseProductClass", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,NonceDomain", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,Version", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,PreauthorizationVersion", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,FakeRoot", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,SystemOS", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,SystemVolume", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,SystemTrustCache", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,AppOS", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,AppVolume", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,AppTrustCache", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,MobileAssetBrainOS", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,MobileAssetBrainVolume", NULL);
	_plist_dict_copy_item(parameters, build_identity, "Cryptex1,MobileAssetBrainTrustCache", NULL);

	_plist_dict_copy_item(parameters, build_identity, "USBPortController1,BoardID", NULL);
	_plist_dict_copy_item(parameters, build_identity, "USBPortController1,ChipID", NULL);
	_plist_dict_copy_item(parameters, build_identity, "USBPortController1,SecurityDomain", NULL);

	node = plist_dict_get_item(build_identity, "Info");
	if (node) {
		_plist_dict_copy_bool(parameters, node, "RequiresUIDMode", NULL);
	}

	if (include_manifest) {
		/* add build identity manifest dictionary */
		node = plist_dict_get_item(build_identity, "Manifest");
		if (!node || plist_get_node_type(node) != PLIST_DICT) {
			error("ERROR: Unable to find Manifest node\n");
			return -1;
		}
		plist_dict_set_item(parameters, "Manifest", plist_copy(node));
	}

	return 0;
}

int tss_request_add_ap_img4_tags(plist_t request, plist_t parameters)
{
	if (!parameters) {
		error("ERROR: Missing required AP parameters\n");
		return -1;
	}

	_plist_dict_copy_string(request, parameters, "Ap,OSLongVersion", NULL);

	if (_plist_dict_copy_data(request, parameters, "ApNonce", NULL) < 0) {
		error("ERROR: Unable to find required ApNonce in parameters\n");
		return -1;
	}

	plist_dict_set_item(request, "@ApImg4Ticket", plist_new_bool(1));

	if (!plist_dict_get_item(request, "ApSecurityMode")) {
		/* copy from parameters if available */
		if (_plist_dict_copy_bool(request, parameters, "ApSecurityMode", NULL) < 0) {
			error("ERROR: Unable to find required ApSecurityMode in parameters\n");
			return -1;
		}
	}
	if (!plist_dict_get_item(request, "ApProductionMode")) {
		/* ApProductionMode */
		if (_plist_dict_copy_bool(request, parameters, "ApProductionMode", NULL) < 0) {
			error("ERROR: Unable to find required ApProductionMode in parameters\n");
			return -1;
		}
	}

	_plist_dict_copy_data(request, parameters, "SepNonce", "ApSepNonce");
	_plist_dict_copy_uint(request, parameters, "NeRDEpoch", NULL);
	_plist_dict_copy_data(request, parameters, "PearlCertificationRootPub", NULL);

	if (plist_dict_get_item(parameters, "UID_MODE")) {
		_plist_dict_copy_item(request, parameters, "UID_MODE", NULL);
	} else if (_plist_dict_get_bool(parameters, "RequiresUIDMode")) {
		// The logic here is missing why this value is expected to be 'false'
		plist_dict_set_item(request, "UID_MODE", plist_new_bool(0));
	}

	// FIXME: I didn't understand yet when this value is set, so for now we use a workaround
	if (plist_dict_get_item(parameters, "ApSikaFuse")) {
		_plist_dict_copy_item(request, parameters, "Ap,SikaFuse", "ApSikaFuse");
	} else if (_plist_dict_get_bool(parameters, "RequiresUIDMode")) {
		// Workaround: We have only seen Ap,SikaFuse together with UID_MODE
		plist_dict_set_item(request, "Ap,SikaFuse", plist_new_int(0));
	}

	return 0;
}

int tss_request_add_ap_img3_tags(plist_t request, plist_t parameters)
{
	if (!parameters) {
		error("ERROR: Missing required AP parameters\n");
		return -1;
	}

	if (_plist_dict_copy_data(request, parameters, "ApNonce", NULL) < 0) {
		error("WARNING: Unable to find ApNonce in parameters\n");
	}

	plist_dict_set_item(request, "@APTicket", plist_new_bool(1));

	if (_plist_dict_copy_uint(request, parameters, "ApBoardID", NULL) < 0) {
		error("ERROR: Unable to find required ApBoardID in request\n");
		return -1;
	}

	if (_plist_dict_copy_uint(request, parameters, "ApChipID", NULL) < 0) {
		error("ERROR: Unable to find required ApChipID in request\n");
		return -1;
	}

	if (_plist_dict_copy_uint(request, parameters, "ApSecurityDomain", NULL) < 0) {
		error("ERROR: Unable to find required ApSecurityDomain in request\n");
		return -1;
	}

	if (_plist_dict_copy_bool(request, parameters, "ApProductionMode", NULL) < 0) {
		error("ERROR: Unable to find required ApProductionMode in parameters\n");
		return -1;
	}

	return 0;
}

int tss_request_add_common_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	_plist_dict_copy_uint(request, parameters, "ApECID", NULL);
	_plist_dict_copy_data(request, parameters, "UniqueBuildID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApChipID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApBoardID", NULL);
	_plist_dict_copy_uint(request, parameters, "ApSecurityDomain", NULL);

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

int tss_request_add_ap_recovery_tags(plist_t request, plist_t parameters, plist_t overrides)
{
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
		free(key);
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			free(key);
			return -1;
		}

		/* do not populate BaseBandFirmware, only in basebaseband request */
		if ((strcmp(key, "BasebandFirmware") == 0)) {
			continue;
		}

		// Compared to ac2, not needed for RecoveryOSRootTicket
		if ((strcmp(key, "SE,UpdatePayload") == 0)) {
			continue;
		}
		if ((strcmp(key, "BaseSystem") == 0)) {
			continue;
		}
		if ((strcmp(key, "ANS") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,AudioBootChime") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,CIO") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,RestoreCIO") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,RestoreTMU") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,TMU") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,rOSLogo1") == 0)) {
			continue;
		}
		if ((strcmp(key, "Ap,rOSLogo2") == 0)) {
			continue;
		}
		if ((strcmp(key, "AppleLogo") == 0)) {
			continue;
		}
		if ((strcmp(key, "DCP") == 0)) {
			continue;
		}
		if ((strcmp(key, "LLB") == 0)) {
			continue;
		}
		if ((strcmp(key, "RecoveryMode") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreANS") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreDCP") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreDeviceTree") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreKernelCache") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreLogo") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreRamDisk") == 0)) {
			continue;
		}
		if ((strcmp(key, "RestoreSEP") == 0)) {
			continue;
		}
		if ((strcmp(key, "SEP") == 0)) {
			continue;
		}
		if ((strcmp(key, "ftap") == 0)) {
			continue;
		}
		if ((strcmp(key, "ftsp") == 0)) {
			continue;
		}
		if ((strcmp(key, "iBEC") == 0)) {
			continue;
		}
		if ((strcmp(key, "iBSS") == 0)) {
			continue;
		}
		if ((strcmp(key, "rfta") == 0)) {
			continue;
		}
		if ((strcmp(key, "rfts") == 0)) {
			continue;
		}

		/* FIXME: only used with diagnostics firmware */
		if (strcmp(key, "Diags") == 0) {
			continue;
		}

		plist_t info_dict = plist_dict_get_item(manifest_entry, "Info");
		if (!info_dict) {
			continue;
		}

		if (_plist_dict_get_bool(parameters, "_OnlyFWComponents")) {
			if (!_plist_dict_get_bool(manifest_entry, "Trusted")) {
				debug("DEBUG: %s: Skipping '%s' as it is not trusted\n", __func__, key);
				continue;
			}

			if (!_plist_dict_get_bool(info_dict, "IsFirmwarePayload")
			 && !_plist_dict_get_bool(info_dict, "IsSecondaryFirmwarePayload")
			 && !_plist_dict_get_bool(info_dict, "IsFUDFirmware")
			 && !_plist_dict_get_bool(info_dict, "IsLoadedByiBoot")
			 && !_plist_dict_get_bool(info_dict, "IsEarlyAccessFirmware")
			 && !_plist_dict_get_bool(info_dict, "IsiBootEANFirmware")
			 && !_plist_dict_get_bool(info_dict, "IsiBootNonEssentialFirmware"))
			{
				debug("DEBUG: %s: Skipping '%s' as it is not a firmware payload\n", __func__, key);
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
		if (_plist_dict_get_bool(manifest_entry, "Trusted") && !plist_dict_get_item(manifest_entry, "Digest")) {
			debug("DEBUG: No Digest data, using empty value for entry %s\n", key);
			plist_dict_set_item(tss_entry, "Digest", plist_new_data(NULL, 0));
		}

		/* finally add entry to request */
		plist_dict_set_item(request, key, tss_entry);
	}
	free(key);
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_ap_tags(plist_t request, plist_t parameters, plist_t overrides)
{
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
		free(key);
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			free(key);
			return -1;
		}

		/* do not populate BaseBandFirmware, only in basebaseband request */
		if ((strcmp(key, "BasebandFirmware") == 0)) {
			continue;
		}

		// Compared to ac2, not needed
		if ((strcmp(key, "SE,UpdatePayload") == 0)) {
			continue;
		}

		// Compared to ac2, not needed
		if ((strcmp(key, "BaseSystem") == 0)) {
			continue;
		}

		/* FIXME: only used with diagnostics firmware */
		if (strcmp(key, "Diags") == 0) {
			continue;
		}

		plist_t info_dict = plist_dict_get_item(manifest_entry, "Info");
		if (!info_dict) {
			continue;
		}

		if (_plist_dict_get_bool(parameters, "ApSupportsImg4")) {
			if (!plist_dict_get_item(info_dict, "RestoreRequestRules")) {
				debug("DEBUG: %s: Skipping '%s' as it doesn't have RestoreRequestRules\n", __func__, key);
				continue;
			}
		}

		int is_fw_payload = _plist_dict_get_bool(info_dict, "IsFirmwarePayload")
				 || _plist_dict_get_bool(info_dict, "IsSecondaryFirmwarePayload")
				 || _plist_dict_get_bool(info_dict, "IsFUDFirmware")
				 || _plist_dict_get_bool(info_dict, "IsLoadedByiBoot")
				 || _plist_dict_get_bool(info_dict, "IsEarlyAccessFirmware")
				 || _plist_dict_get_bool(info_dict, "IsiBootEANFirmware")
				 || _plist_dict_get_bool(info_dict, "IsiBootNonEssentialFirmware");

		if (_plist_dict_get_bool(parameters, "_OnlyFWOrTrustedComponents")) {
			if (!_plist_dict_get_bool(manifest_entry, "Trusted") && !is_fw_payload) {
				debug("DEBUG: %s: Skipping '%s' as it is neither firmware payload nor trusted\n", __func__, key);
				continue;
			}
		} else if (_plist_dict_get_bool(parameters, "_OnlyFWComponents")) {
			if (!_plist_dict_get_bool(manifest_entry, "Trusted")) {
				debug("DEBUG: %s: Skipping '%s' as it is not trusted\n", __func__, key);
				continue;
			}
			if (!is_fw_payload) {
				debug("DEBUG: %s: Skipping '%s' as it is not a firmware payload\n", __func__, key);
				continue;
			}
		}

		/* skip components with IsFTAB:true */
		if (_plist_dict_get_bool(info_dict, "IsFTAB")) {
			debug("DEBUG: %s: Skipping FTAB component '%s'\n", __func__, key);
			continue;
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
		if (_plist_dict_get_bool(manifest_entry, "Trusted") && !plist_dict_get_item(manifest_entry, "Digest")) {
			debug("DEBUG: No Digest data, using empty value for entry %s\n", key);
			plist_dict_set_item(tss_entry, "Digest", plist_new_data(NULL, 0));
		}

		/* finally add entry to request */
		plist_dict_set_item(request, key, tss_entry);
	}
	free(key);
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

int tss_request_add_baseband_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));

	_plist_dict_copy_uint(request, parameters, "BbChipID", NULL);
	_plist_dict_copy_data(request, parameters, "BbProvisioningManifestKeyHash", NULL);
	/* BbActivationManifestKeyHash - Used by Qualcomm MDM6610 */
	_plist_dict_copy_data(request, parameters, "BbActivationManifestKeyHash", NULL);
	_plist_dict_copy_data(request, parameters, "BbCalibrationManifestKeyHash", NULL);
	_plist_dict_copy_data(request, parameters, "BbFactoryActivationManifestKeyHash", NULL);
	_plist_dict_copy_data(request, parameters, "BbFDRSecurityKeyHash", NULL);
	/* BbSkeyId - Used by XMM 6180/GSM */
	_plist_dict_copy_data(request, parameters, "BbSkeyId", NULL);
	_plist_dict_copy_data(request, parameters, "BbNonce", NULL);
	_plist_dict_copy_uint(request, parameters, "BbGoldCertId", NULL);

	uint64_t bb_chip_id = _plist_dict_get_uint(request, "BbChipID");
	int32_t bb_cert_id = (int32_t)_plist_dict_get_uint(request, "BbGoldCertId");

	if (_plist_dict_copy_data(request, parameters, "BbSNUM", NULL) < 0) {
		error("ERROR: Unable to find required BbSNUM in parameters\n");
		return -1;
	}

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
	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));

	if (_plist_dict_copy_uint(request, parameters, "SE,ChipID", NULL) < 0) {
		error("ERROR: %s: Unable to find required SE,ChipID in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_data(request, parameters, "SE,ID", NULL) < 0) {
		error("ERROR: %s: Unable to find required SE,ID in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_data(request, parameters, "SE,Nonce", NULL) < 0) {
		error("ERROR: %s: Unable to find required SE,Nonce in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_data(request, parameters, "SE,RootKeyIdentifier", NULL) < 0) {
		error("ERROR: %s: Unable to find required SE,RootKeyIdentifier in parameters\n", __func__);
		return -1;
	}

	/* 'IsDev' determines whether we have Production or Development */
	uint8_t is_dev = _plist_dict_get_bool(parameters, "SE,IsDev");

	/* add SE,* components from build manifest to request */
	char* key = NULL;
	plist_t manifest_entry = NULL;
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(manifest_node, &iter);
	while (1) {
		free(key);
		key = NULL;
		plist_dict_next_item(manifest_node, iter, &key, &manifest_entry);
		if (key == NULL)
			break;
		if (!manifest_entry || plist_get_node_type(manifest_entry) != PLIST_DICT) {
			error("ERROR: Unable to fetch BuildManifest entry\n");
			free(key);
			return -1;
		}

		if (strncmp(key, "SE,", 3)) {
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
	}
	free(key);
	free(iter);

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	/* fallback in case no @SE2,Ticket or @SE,Ticket was provided */
	if (!plist_dict_get_item(request, "@SE2,Ticket") && !plist_dict_get_item(request, "@SE,Ticket")) {
		plist_dict_set_item(request, "@SE,Ticket", plist_new_bool(1));
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

	if (_plist_dict_copy_data(request, parameters, "Savage,UID", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,UID in parameters\n", __func__);
		return -1;
	}

	/* add SEP */
	node = plist_access_path(manifest_node, 2, "SEP", "Digest");
	if (!node) {
		error("ERROR: Unable to get SEP digest from manifest\n");
		return -1;
	}
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "Digest", plist_copy(node));
	plist_dict_set_item(request, "SEP", dict);

	if (_plist_dict_copy_uint(request, parameters, "Savage,PatchEpoch", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,PatchEpoch in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_uint(request, parameters, "Savage,ChipID", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,ChipID in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_bool(request, parameters, "Savage,AllowOfflineBoot", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,AllowOfflineBoot in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_bool(request, parameters, "Savage,ReadFWKey", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,ReadFWKey in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_bool(request, parameters, "Savage,ProductionMode", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,ProductionMode in parameters\n", __func__);
		return -1;
	}

	const char *comp_name = NULL;
	uint8_t isprod = _plist_dict_get_bool(request, "Savage,ProductionMode");

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

	if (_plist_dict_copy_data(request, parameters, "Savage,Nonce", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,Nonce in parameters\n", __func__);
		return -1;
	}

	if (_plist_dict_copy_bool(request, parameters, "Savage,ReadECKey", NULL) < 0) {
		error("ERROR: %s: Unable to find required Savage,ReadECKey in parameters\n", __func__);
		return -1;
	}

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
	uint8_t isprod = _plist_dict_get_bool(parameters, "Yonkers,ProductionMode");
	uint64_t fabrevision = _plist_dict_get_uint(parameters, "Yonkers,FabRevision");

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

	_plist_dict_copy_bool(request, parameters, "eUICC,ApProductionMode", "ApProductionMode");
	_plist_dict_copy_uint(request, parameters, "eUICC,ChipID", NULL);
	_plist_dict_copy_data(request, parameters, "eUICC,EID", NULL);
	_plist_dict_copy_data(request, parameters, "eUICC,RootKeyIdentifier", NULL);

	if (!plist_dict_get_item(request, "eUICC,Gold")) {
		plist_t n = plist_access_path(parameters, 2, "Manifest", "eUICC,Gold");
		if (n) {
			plist_t p = plist_new_dict();
			_plist_dict_copy_data(p, n, "Digest", NULL);
			plist_dict_set_item(request, "eUICC,Gold", p);
		}
	}

	if (!plist_dict_get_item(request, "eUICC,Main")) {
		plist_t n = plist_access_path(parameters, 2, "Manifest", "eUICC,Main");
		if (n) {
			plist_t p = plist_new_dict();
			_plist_dict_copy_data(p, n, "Digest", NULL);
			plist_dict_set_item(request, "eUICC,Main", p);
		}
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

	_plist_dict_copy_uint(request, parameters, "Rap,BoardID", NULL);
	_plist_dict_copy_uint(request, parameters, "Rap,ChipID", NULL);
	_plist_dict_copy_uint(request, parameters, "Rap,ECID", NULL);
	_plist_dict_copy_data(request, parameters, "Rap,Nonce", NULL);
	_plist_dict_copy_bool(request, parameters, "Rap,ProductionMode", NULL);
	_plist_dict_copy_uint(request, parameters, "Rap,SecurityDomain", NULL);
	_plist_dict_copy_bool(request, parameters, "Rap,SecurityMode", NULL);
	_plist_dict_copy_data(request, parameters, "Rap,FdrRootCaDigest", NULL);

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
			if (_plist_dict_get_bool(manifest_entry, "Trusted") && !plist_dict_get_item(manifest_entry, "Digest")) {
				debug("DEBUG: No Digest data, using empty value for entry %s\n", comp_name);
				plist_dict_set_item(manifest_entry, "Digest", plist_new_data(NULL, 0));
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

	/* add tags indicating we want to get the BMU,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@BMU,Ticket", plist_new_bool(1));

	_plist_dict_copy_uint(request, parameters, "BMU,BoardID", NULL);
	_plist_dict_copy_uint(request, parameters, "BMU,ChipID", "ChipID");
	_plist_dict_copy_data(request, parameters, "BMU,Nonce", "Nonce");
	_plist_dict_copy_bool(request, parameters, "BMU,ProductionMode", "ProductionMode");
	_plist_dict_copy_uint(request, parameters, "BMU,UniqueID", "UniqueID");

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
			if (_plist_dict_get_bool(manifest_entry, "Trusted") && !plist_dict_get_item(manifest_entry, "Digest")) {
				debug("DEBUG: No Digest data, using empty value for entry %s\n", comp_name);
				plist_dict_set_item(manifest_entry, "Digest", plist_new_data(NULL, 0));
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

int tss_request_add_tcon_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Baobab,Ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));
	plist_dict_set_item(request, "@Baobab,Ticket", plist_new_bool(1));

	_plist_dict_copy_uint(request, parameters, "Baobab,BoardID", NULL);
	_plist_dict_copy_uint(request, parameters, "Baobab,ChipID", NULL);
	_plist_dict_copy_data(request, parameters, "Baobab,ECID", NULL);
	_plist_dict_copy_uint(request, parameters, "Baobab,Life", NULL);
	_plist_dict_copy_uint(request, parameters, "Baobab,ManifestEpoch", NULL);
	_plist_dict_copy_bool(request, parameters, "Baobab,ProductionMode", NULL);
	_plist_dict_copy_uint(request, parameters, "Baobab,SecurityDomain", NULL);
	_plist_dict_copy_data(request, parameters, "Baobab,UpdateNonce", NULL);

	uint8_t isprod = _plist_dict_get_bool(parameters, "Baobab,ProductionMode");

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
		if (strncmp(comp_name, "Baobab,", 7) == 0) {
			plist_t manifest_entry = plist_copy(node);

			plist_dict_remove_item(manifest_entry, "Info");
			plist_dict_set_item(manifest_entry, "EPRO", plist_new_bool(isprod));

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

int tss_request_add_timer_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	plist_t node = NULL;
	uint32_t tag = 0;

	plist_t manifest_node = plist_dict_get_item(parameters, "Manifest");
	if (!manifest_node || plist_get_node_type(manifest_node) != PLIST_DICT) {
		error("ERROR: %s: Unable to get restore manifest from parameters\n", __func__);
		return -1;
	}

	/* add tags indicating we want to get the Timer ticket */
	plist_dict_set_item(request, "@BBTicket", plist_new_bool(1));

	node = plist_dict_get_item(parameters, "TicketName");
	if (!node) {
		error("ERROR: %s: Missing TicketName\n", __func__);
		return -1;
	}
	char key[64];
	sprintf(key, "@%s", plist_get_string_ptr(node, NULL));

	plist_dict_set_item(request, key, plist_new_bool(1));

	tag = (uint32_t)_plist_dict_get_uint(parameters, "TagNumber");

	sprintf(key, "Timer,BoardID,%u", tag);
	_plist_dict_copy_uint(request, parameters, key, NULL);

	sprintf(key, "Timer,ChipID,%u", tag);
	_plist_dict_copy_uint(request, parameters, key, NULL);

	sprintf(key, "Timer,SecurityDomain,%u", tag);
	_plist_dict_copy_uint(request, parameters, key, NULL);

	sprintf(key, "Timer,SecurityMode,%u", tag);
	_plist_dict_copy_bool(request, parameters, key, NULL);

	sprintf(key, "Timer,ProductionMode,%u", tag);
	_plist_dict_copy_bool(request, parameters, key, NULL);

	sprintf(key, "Timer,ECID,%u", tag);
	_plist_dict_copy_uint(request, parameters, key, NULL);

	sprintf(key, "Timer,Nonce,%u", tag);
	_plist_dict_copy_data(request, parameters, key, NULL);

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
		if (!strncmp(comp_name, "Timer,", 6)) {
			plist_t manifest_entry = plist_copy(node);

			/* handle RestoreRequestRules */
			plist_t rules = plist_access_path(manifest_entry, 2, "Info", "RestoreRequestRules");
			if (rules) {
				debug("DEBUG: Applying restore request rules for entry %s\n", comp_name);
				tss_entry_apply_restore_request_rules(manifest_entry, parameters, rules);
			}

			/* Make sure we have a Digest key for Trusted items even if empty */
			if (_plist_dict_get_bool(manifest_entry, "Trusted") && !plist_dict_get_item(manifest_entry, "Digest")) {
				debug("DEBUG: No Digest data, using empty value for entry %s\n", comp_name);
				plist_dict_set_item(manifest_entry, "Digest", plist_new_data(NULL, 0));
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

int tss_request_add_cryptex_tags(plist_t request, plist_t parameters, plist_t overrides)
{
	tss_request_add_common_tags(request, parameters, NULL);

	if (plist_dict_get_item(parameters, "Ap,LocalPolicy")) {
		/* Cryptex1LocalPolicy */
		tss_request_add_local_policy_tags(request, parameters);
		_plist_dict_copy_data(request, parameters, "Ap,NextStageCryptex1IM4MHash", NULL);
	} else {
		/* Cryptex1 */
		plist_dict_set_item(request, "@Cryptex1,Ticket", plist_new_bool(1));

		_plist_dict_copy_bool(request, parameters, "ApSecurityMode", NULL);
		_plist_dict_copy_bool(request, parameters, "ApProductionMode", NULL);

		plist_dict_iter iter = NULL;
		plist_dict_new_iter(parameters, &iter);
		plist_t value = NULL;
		while (1) {
			char *key = NULL;
			plist_dict_next_item(parameters, iter, &key, &value);
			if (key == NULL)
				break;
			if (strncmp(key, "Cryptex1", 8) == 0) {
				plist_dict_set_item(request, key, plist_copy(value));
			}
			free(key);
		}
	}

	/* apply overrides */
	if (overrides) {
		plist_dict_merge(&request, overrides);
	}

	return 0;
}

static size_t tss_write_callback(char* data, size_t size, size_t nmemb, tss_response* response)
{
	size_t total = size * nmemb;
	if (total != 0) {
		response->content = realloc(response->content, response->length + total + 1);
		memcpy(response->content + response->length, data, total);
		response->content[response->length + total] = '\0';
		response->length += total;
	}

	return total;
}

plist_t tss_request_send(plist_t tss_request, const char* server_url_string)
{
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
			info("Request URL set to %s\n", server_url_string);
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

static int tss_response_get_data_by_key(plist_t response, const char* name, unsigned char** buffer, unsigned int* length)
{
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

int tss_response_get_ap_img4_ticket(plist_t response, unsigned char** ticket, unsigned int* length)
{
	return tss_response_get_data_by_key(response, "ApImg4Ticket", ticket, length);
}

int tss_response_get_ap_ticket(plist_t response, unsigned char** ticket, unsigned int* length)
{
	return tss_response_get_data_by_key(response, "APTicket", ticket, length);
}

int tss_response_get_baseband_ticket(plist_t response, unsigned char** ticket, unsigned int* length)
{
	return tss_response_get_data_by_key(response, "BBTicket", ticket, length);
}

int tss_response_get_path_by_entry(plist_t response, const char* entry, char** path)
{
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

int tss_response_get_blob_by_path(plist_t tss, const char* path, unsigned char** blob)
{
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

int tss_response_get_blob_by_entry(plist_t response, const char* entry, unsigned char** blob)
{
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
