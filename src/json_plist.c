/*
 * json_plist.c
 * JSON/property list functions
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jsmn.h>
#include <plist/plist.h>

#include "json_plist.h"

static plist_t parse_primitive(const char* js, jsmntok_t* tokens, int* index);
static plist_t parse_string(const char* js, jsmntok_t* tokens, int* index);
static plist_t parse_array(const char* js, jsmntok_t* tokens, int* index);
static plist_t parse_object(const char* js, jsmntok_t* tokens, int* index);

static char* get_string_value(const char* js, jsmntok_t token)
{
	int len = (token.end - token.start);
	char* str = malloc(len+1);
	memcpy(str, js + token.start, len);
	str[len] = 0;
	return str;
}

static plist_t parse_primitive(const char* js, jsmntok_t* tokens, int* index)
{
	if (tokens[*index].type != JSMN_PRIMITIVE) {
		fprintf(stderr, "%s: ERROR: token type != JSMN_PRIMITIVE?!\n", __func__);
		return NULL;
	}
	plist_t val = NULL;
	char* strval = get_string_value(js, tokens[*index]);
	if (strval[0] == 'f') {
		val = plist_new_bool(0);
	} else if (strval[0] == 't') {
		val = plist_new_bool(1);
	} else if ((strval[0] == '-') || ((strval[0] >= '0') && (strval[0] <= '9'))) {
		val = plist_new_uint(strtoll(strval, NULL, 10));
	} else {
		fprintf(stderr, "%s: WARNING: invalid primitive value '%s' encountered, will return as string\n", __func__, strval);
		val = plist_new_string(strval);
	}
	free(strval);
	(*index)++;
	return val;
}

static plist_t parse_string(const char* js, jsmntok_t* tokens, int* index)
{
	if (tokens[*index].type != JSMN_STRING) {
		fprintf(stderr, "%s: ERROR: token type != JSMN_STRING?!\n", __func__);
		return NULL;
	}
	char* str = get_string_value(js, tokens[*index]);
	plist_t val = plist_new_string(str);
	free(str);
	(*index)++;
	return val;
}

static plist_t parse_array(const char* js, jsmntok_t* tokens, int* index)
{
	if (tokens[*index].type != JSMN_ARRAY) {
		fprintf(stderr, "%s: ERROR: token type != JSMN_ARRAY?!\n", __func__);
		return NULL;
	}
	plist_t arr = plist_new_array();
	int num_tokens = tokens[*index].size;
	int num;
	int j = (*index)+1;
	for (num = 0; num < num_tokens; num++) {
		plist_t val = NULL;
		switch (tokens[j].type) {
			case JSMN_OBJECT:
				val = parse_object(js, tokens, &j);
				break;
			case JSMN_ARRAY:
				val = parse_array(js, tokens, &j);
				break;
			case JSMN_STRING:
				val = parse_string(js, tokens, &j);
				break;
			case JSMN_PRIMITIVE:
				val = parse_primitive(js, tokens, &j);
				break;
			default:
				break;
		}
		if (val) {
			plist_array_append_item(arr, val);
		}
	}
	*(index) = j;
	return arr;
}

static plist_t parse_object(const char* js, jsmntok_t* tokens, int* index)
{
	if (tokens[*index].type != JSMN_OBJECT) {
		fprintf(stderr, "%s: ERROR: token type != JSMN_OBJECT?!\n", __func__);
		return NULL;
	}
	plist_t obj = plist_new_dict();
	int num_tokens = tokens[*index].size;
	int num;
	int j = (*index)+1;
	for (num = 0; num < num_tokens; num++) {
		if (tokens[j].type == JSMN_STRING) {
			char* key = get_string_value(js, tokens[j]);
			plist_t val = NULL;
			j++;
			num++;
			switch (tokens[j].type) {
			case JSMN_OBJECT:
				val = parse_object(js, tokens, &j);
				break;
			case JSMN_ARRAY:
				val = parse_array(js, tokens, &j);
				break;
			case JSMN_STRING:
				val = parse_string(js, tokens, &j);
				break;
			case JSMN_PRIMITIVE:
				val = parse_primitive(js, tokens, &j);
				break;
			default:
				break;
			}
			if (val) {
				plist_dict_set_item(obj, key, val);
			}
			free(key);
		} else {
			fprintf(stderr, "%s: keys must be of type STRING\n", __func__);
			return NULL;
		}
	}
	(*index) = j;
	return obj;
}

plist_t json_to_plist(const char* json_string)
{
	jsmn_parser parser;
	jsmn_init(&parser);
	int maxtoks = 256;
	jsmntok_t *tokens;

	if (!json_string) {
		fprintf(stderr, "%s: ERROR: no JSON string given.\n", __func__);
		return NULL;
	}

	tokens = malloc(sizeof(jsmntok_t)*maxtoks);
	if (!tokens) {
		fprintf(stderr, "%s: Out of memory\n", __func__);
		return NULL;
	}

	int r = 0;
reparse:
	r = jsmn_parse(&parser, json_string, tokens, maxtoks);
	if (r == JSMN_ERROR_NOMEM) {
		//printf("not enough tokens (%d), retrying...\n", maxtoks);
		maxtoks+=256;
		jsmntok_t* newtokens = realloc(tokens, sizeof(jsmntok_t)*maxtoks);
		if (newtokens) {
			tokens = newtokens;
			goto reparse;
		}
	}

	switch(r) {
	case JSMN_ERROR_NOMEM:
		fprintf(stderr, "%s: ERROR: Out of memory...\n", __func__);
		return NULL;
	case JSMN_ERROR_INVAL:
		fprintf(stderr, "%s: ERROR: Invalid character inside JSON string\n", __func__);
		return NULL;
	case JSMN_ERROR_PART:
		fprintf(stderr, "%s: ERROR: The string is not a full JSON packet, more bytes expected\n", __func__);
		return NULL;
	default:
		break;
	}

	int startindex = 0;
	plist_t plist = NULL;
	switch (tokens[startindex].type) {
	case JSMN_PRIMITIVE:
		plist = parse_primitive(json_string, tokens, &startindex);
		break;
	case JSMN_STRING:
		plist = parse_string(json_string, tokens, &startindex);
		break;
	case JSMN_ARRAY:
		plist = parse_array(json_string, tokens, &startindex);
		break;
	case JSMN_OBJECT:
		plist = parse_object(json_string, tokens, &startindex);
		break;
	default:
		break;
	}

	free(tokens);

	return plist;
}

