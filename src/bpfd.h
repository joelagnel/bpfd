/*
 * BPFd (Berkeley Packet Filter daemon)
 * This header is only supposed to be used by bpfd.c
 *
 * Copyright (C) 2017 Joel Fernandes <agnel.joel@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <inttypes.h>

#include "utils.h"
#include "base64.h"
#include "libbpf.h"

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

#define PARSE_UINT64(var)			\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%"SCNu64" ", &var))	\
		goto invalid_command;

#define PARSE_ULL(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%llu ", &var))	\
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

#define PARSE_FIRST_UINT64(var)		\
	PARSE_FIRST_TOK					\
	if (!sscanf(tok, "%"SCNu64" ", &var))	\
		goto invalid_command;

#define PARSE_FIRST_STR(var)		\
	PARSE_FIRST_TOK					\
	var = tok;

int bpf_remote_open_perf_buffer(int pid, int cpu, int page_cnt);
int remote_perf_reader_poll(int *fds, int len, int timeout);
