/*
 * BPFd (Berkeley Packet Filter daemon)
 * This header is only supposed to be used by bpfd.c
 *
 * Copyright (C) 2017 Joel Fernandes <agnel.joel@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "utils.h"
#include "lib/bpf/libbpf.h"
#include "base64.h"

#define PARSE_INT(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%d ", &var))		\
		goto invalid_command;

#define PARSE_UINT(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%u ", &var))		\
		goto invalid_command;

#define PARSE_STR(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	var = tok;

#define PARSE_FIRST_TOK				\
	len = strlen(argstr);			\
	tok = strtok(argstr, " ");		\
	if (strlen(tok) == len)			\
		goto invalid_command;

#define PARSE_FIRST_INT(var)		\
	PARSE_FIRST_TOK					\
	if (!sscanf(tok, "%d ", &var))	\
		goto invalid_command;

#define PARSE_FIRST_UINT(var)		\
	PARSE_FIRST_TOK					\
	if (!sscanf(tok, "%u ", &var))	\
		goto invalid_command;

#define PARSE_FIRST_STR(var)		\
	PARSE_FIRST_TOK					\
	var = tok;
