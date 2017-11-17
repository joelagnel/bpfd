/*
 * BPFd (Berkeley Packet Filter daemon)
 *
 * Copyright (C) 2017 Joel Fernandes <agnel.joel@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

#include "base64.h"
#include "bpfd.h"
#include "lib/bpf/libbpf.h"

#define LINEBUF_SIZE  2000000
#define LINE_TOKENS   10

int read_avail_filter(char *tracefs) {
	char tracef[100], ch;
	char buf[4096];
	int len, fd;

	tracef[0] = 0;
	strcat(tracef, tracefs);
	strcat(tracef, "/");
	strcat(tracef, "available_filter_functions");

	fd = open(tracef, O_RDONLY);
	if (fd < 0) {
		printf("Open failed, ignoring\n");
		return fd;
	}

	printf("START_TRACEFS_READ\n");
	fflush(stdout);

	while ((len = read(fd, &buf, 4096)) > 0)
		write(1, buf, len);

	close(fd);

	printf("END_TRACEFS_READ\n");
	return 0;

}

/* Command format: BPF_PROG_LOAD type prog_len license kern_version binary_data
 *
 * Prototype of lib call:
 int bpf_prog_load(enum bpf_prog_type prog_type,
 const struct bpf_insn *insns, int prog_len,
 const char *license, unsigned kern_version,
 char *log_buf, unsigned log_buf_size)
 */
int bpf_prog_load_handle(int type, char *bin_b64, int prog_len, char *license,
			 unsigned int kern_version)
{
	int bin_len, ret;
	char *bin_buf;
	const struct bpf_insn *insns;

	bin_len = strlen(bin_b64);
	bin_buf = (char *)malloc(bin_len);

	if (!base64_decode(bin_b64, bin_buf, bin_len))
		return -1;

	insns = (const struct bpf_insn *)bin_buf;

	ret = bpf_prog_load((enum bpf_prog_type)type, insns, prog_len,
			    (const char *)license, kern_version, NULL, 0);


	printf("bpf_prog_load: ret=%d\n", ret);
}

int main(int argc, char **argv)
{
	char line_buf[LINEBUF_SIZE];
	char *cmd, *lineptr, *argstr;
	int len, fd;

	if (argc == 2 && !strcmp(argv[1], "base64"))
		test_base64("bpfd.c");

	while (fgets(line_buf, LINEBUF_SIZE, stdin)) {
		int fd;
		line_buf[strcspn(line_buf, "\r\n")] = 0;
		line_buf[strcspn(line_buf, "\n")] = 0;

		lineptr = line_buf;
		len = strlen(lineptr);

		/* Empty input */
		if (!len)
			continue;

		if (!strcmp(lineptr, "exit"))
			break;

		/* Command parsing logic */
		cmd = strtok(lineptr, " ");

		/* No "command args" format found */
		if (strlen(cmd) == len)
			cmd = NULL;

		if (cmd) {
			lineptr = line_buf;
			while (*lineptr)
				lineptr++;
			lineptr++;

			if (!*lineptr) {
				cmd = NULL;
			} else {
				argstr = lineptr;
			}
		}

		if (cmd && !strcmp(cmd, "READ_AVAILABLE_FILTER_FUNCTIONS")) {
			if (read_avail_filter(argstr) < 0)
				goto invalid_command;
		} else if (cmd && !strcmp(cmd, "BPF_PROG_LOAD")) {
			int len, prog_len, type;
			char *tok, *license, *bin_data;
			unsigned int kern_version;
			/*
			 * Command format: BPF_PROG_LOAD type prog_len license kern_version binary_data
			 * Prototype of lib call:
			 * int bpf_prog_load(enum bpf_prog_type prog_type,
			 * const struct bpf_insn *insns, int prog_len,
			 * const char *license, unsigned kern_version, char *log_buf, unsigned log_buf_size)
			*/
			len = strlen(argstr);
			tok = strtok(argstr, " ");
			if (strlen(tok) == len)
				goto invalid_command;
			if (!sscanf(tok, "%d ", &type))
				goto invalid_command;

			PARSE_INT(prog_len);
			PARSE_STR(license);
			PARSE_UINT(kern_version);
			PARSE_STR(bin_data);

			bpf_prog_load_handle(type, bin_data, prog_len, license, kern_version);

		} else if (cmd && !strcmp(cmd, "BPF_CREATE_MAP")) {
			/*
			 * Command format: BPF_CREATE_MAP map_type, table.key_size, table.leaf_size, table.max_entries, table.flags);
			 * Prototype of lib call:
			 * int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, int map_flags)
			 */
			int ret, type, len, key_size, value_size, max_entries, map_flags;
			char *tok;

			len = strlen(argstr);
			tok = strtok(argstr, " ");
			if (strlen(tok) == len)
				goto invalid_command;
			if (!sscanf(tok, "%d ", &type))
				goto invalid_command;

			PARSE_INT(key_size);
			PARSE_INT(value_size);
			PARSE_INT(max_entries);
			PARSE_INT(map_flags);

			ret = bpf_create_map((enum bpf_map_type)type, key_size, value_size, max_entries, map_flags);
			printf("bpf_create_map: ret=%d\n", ret);
		} else {
invalid_command:
			printf("Command not recognized\n");
		}

		fflush(stdout);
	}
	return 0;
}
