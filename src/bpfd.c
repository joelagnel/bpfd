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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/bpf.h>
#include <arpa/inet.h>

#include "bpfd.h"

#define LINEBUF_SIZE  2000000
#define LINE_TOKENS   10

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

int get_trace_events(char *tracefs, char *category)
{
	char tracef[256];

	tracef[0] = 0;
	strcat(tracef, tracefs);
	strcat(tracef, "/events/");
	strcat(tracef, category);

	return cat_dir(tracef, 1);
}

int get_trace_events_categories(char *tracefs)
{
	char tracef[256];

	tracef[0] = 0;
	strcat(tracef, tracefs);
	strcat(tracef, "/events");

	return cat_dir(tracef, 1);
}

int bpf_remote_update_elem(int map_fd, char *kstr, int klen,
		char *lstr, int llen, unsigned long flags)
{
	int ret = -ENOMEM;
	void *kbin, *lbin;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_update;

	lbin = (void *)malloc(llen);
	if (!lbin)
		goto err_update;

	ret = -EINVAL;
	if (!base64_decode(kstr, kbin, klen))
		goto err_update;

	if (!base64_decode(lstr, lbin, llen))
		goto err_update;

	ret = bpf_update_elem(map_fd, kbin, lbin, flags);
err_update:
	if (kbin) free(kbin);
	if (lbin) free(lbin);
	return ret;
}

char *bpf_remote_lookup_elem(int map_fd, char *kstr, int klen, int llen)
{
	void *lbin, *kbin;
	char *lstr, *rets = NULL;
	int ret;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_update;

	lbin = (void *)malloc(llen);
	if (!lbin)
		goto err_update;

	lstr = (char *)malloc(llen * 4);

	if (!lstr ||
		!base64_decode(kstr, kbin, klen) ||
		(bpf_lookup_elem(map_fd, kbin, lbin) < 0))
		goto err_update;

	if (base64_encode(lbin, llen, lstr, llen*4))
		rets = (char *)lstr;

err_update:
	if (lbin) free(lbin);
	if (kbin) free(kbin);
	if (!rets && lstr) free(lstr);
	return rets;
}

char *bpf_remote_get_first_key(int map_fd, int klen)
{
	void *kbin;
	char *kstr, *rets = NULL;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_get;

	kstr = (char *)malloc(klen * 4);
	if (!kstr || bpf_get_first_key(map_fd, kbin, klen) < 0)
		goto err_get;

	if (base64_encode(kbin, klen, kstr, klen*4))
		rets = kstr;
err_get:
	if (kbin) free(kbin);
	if (!rets && kstr) free(kstr);
	return rets;
}

char *bpf_remote_get_next_key(int map_fd, char *kstr, int klen)
{
	void *kbin, *next_kbin;
	char *next_kstr, *rets = NULL;
	int ret;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_update;

	next_kbin = (void *)malloc(klen);
	if (!next_kbin)
		goto err_update;

	next_kstr = (char *)malloc(klen * 4);

	if (!next_kstr ||
		!base64_decode(kstr, kbin, klen) ||
		(bpf_get_next_key(map_fd, kbin, next_kbin) < 0))
		goto err_update;

	if (base64_encode(next_kbin, klen, next_kstr, klen*4))
		rets = (char *)next_kstr;

err_update:
	if (kbin) free(kbin);
	if (next_kbin) free(next_kbin);
	if (!rets && next_kstr) free(next_kstr);
	return rets;
}

int main(int argc, char **argv)
{
	char line_buf[LINEBUF_SIZE];
	char *cmd, *lineptr, *argstr, *tok;
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

		printf("START_BPFD_OUTPUT\n");
		fflush(stdout);

		if (!cmd)
			goto invalid_command;

		if (!strcmp(cmd, "GET_AVAIL_FILTER_FUNCS")) {

			if (cat_tracefs_file(argstr, "available_filter_functions") < 0)
				goto invalid_command;

		} else if (!strcmp(cmd, "GET_KPROBES_BLACKLIST")) {

			if (cat_tracefs_file(argstr, "../kprobes/blacklist") < 0)
				goto invalid_command;

		} else if (!strcmp(cmd, "GET_TRACE_EVENTS_CATEGORIES")) {

			if (get_trace_events_categories(argstr) < 0)
				goto invalid_command;
	
		} else if (!strcmp(cmd, "GET_TRACE_EVENTS")) {
			int len;
			char *category, *tracefs;

			PARSE_FIRST_STR(tracefs);
			PARSE_STR(category);

			if (get_trace_events(tracefs, category) < 0)
				goto invalid_command;

		} else if (!strcmp(cmd, "BPF_PROG_LOAD")) {

			int len, prog_len, type;
			char *license, *bin_data;
			unsigned int kern_version;
			/*
			 * Command format: BPF_PROG_LOAD type prog_len license kern_version binary_data
			 * Prototype of lib call:
			 * int bpf_prog_load(enum bpf_prog_type prog_type,
			 * const struct bpf_insn *insns, int prog_len,
			 * const char *license, unsigned kern_version, char *log_buf, unsigned log_buf_size)
			*/
			PARSE_FIRST_INT(type);
			PARSE_INT(prog_len);
			PARSE_STR(license);
			PARSE_UINT(kern_version);
			PARSE_STR(bin_data);

			bpf_prog_load_handle(type, bin_data, prog_len, license, kern_version);

		} else if (!strcmp(cmd, "BPF_ATTACH_KPROBE")) {
			int len, ret, prog_fd, group_fd, pid, cpu, type;
			char *ev_name, *fn_name;
			/*
			 * void * bpf_attach_kprobe(int progfd, enum bpf_probe_attach_type attach_type, const char *ev_name,
			 *							const char *fn_name, pid_t pid, int cpu, int group_fd,
			 *							perf_reader_cb cb, void *cb_cookie)
			 */

			PARSE_FIRST_INT(prog_fd);
			PARSE_INT(type);
			PARSE_STR(ev_name);
			PARSE_STR(fn_name);
			PARSE_INT(pid);
			PARSE_INT(cpu);
			PARSE_INT(group_fd);

			/*
			 * TODO: We're leaking a struct perf_reader here, we should free it somewhere.
			 */
			if (!bpf_attach_kprobe(prog_fd, type, ev_name, fn_name, pid, cpu, group_fd, NULL, NULL))
				ret = -1;
			else
				ret = prog_fd;

			printf("bpf_attach_kprobe: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_ATTACH_TRACEPOINT")) {
			int len, ret, prog_fd, group_fd, pid, cpu;
			char *tpname, *category;
			/*
			 * void * bpf_attach_tracepoint(int progfd, const char *tp_category,
			 *		const char *tp_name, int pid, int cpu,
			 *		int group_fd, perf_reader_cb cb, void *cb_cookie)
			 */

			PARSE_FIRST_INT(prog_fd);
			PARSE_STR(category);
			PARSE_STR(tpname);
			PARSE_INT(pid);
			PARSE_INT(cpu);
			PARSE_INT(group_fd);

			/*
			 * TODO: We're leaking a struct perf_reader here, we should free it somewhere.
			 */
			if (!bpf_attach_tracepoint(prog_fd, category, tpname, pid, cpu, group_fd, NULL, NULL))
				ret = -1;
			else
				ret = prog_fd;

			printf("bpf_attach_tracepoint: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_CREATE_MAP")) {
			/*
			 * Command format: BPF_CREATE_MAP map_type, table.key_size, table.leaf_size, table.max_entries, table.flags);
			 * Prototype of lib call:
			 * int bpf_create_map(enum bpf_map_type map_type, int key_size, int value_size, int max_entries, int map_flags)
			 */

			int ret, type, len, key_size, value_size, max_entries, map_flags;

			PARSE_FIRST_INT(type);
			PARSE_INT(key_size);
			PARSE_INT(value_size);
			PARSE_INT(max_entries);
			PARSE_INT(map_flags);

			ret = bpf_create_map((enum bpf_map_type)type, key_size, value_size, max_entries, map_flags);
			printf("bpf_create_map: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_OPEN_PERF_BUFFER")) {
			int pid, cpu, page_cnt, ret;

			PARSE_FIRST_INT(pid);
			PARSE_INT(cpu);
			PARSE_INT(page_cnt);

			ret = bpf_remote_open_perf_buffer(pid, cpu, page_cnt);
			printf("bpf_open_perf_buffer: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_UPDATE_ELEM")) {
			int map_fd, klen, llen, ret;
			unsigned long long flags;
			char *tok, *kstr, *lstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_STR(kstr);
			PARSE_INT(klen);
			PARSE_STR(lstr);
			PARSE_INT(llen);
			PARSE_ULL(flags);

			ret = bpf_remote_update_elem(map_fd, kstr, klen, lstr, llen, flags);
			printf("bpf_update_elem: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_LOOKUP_ELEM")) {
			int map_fd, klen, llen;
			char *tok, *kstr, *lstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_STR(kstr);
			PARSE_INT(klen);
			PARSE_INT(llen);

			lstr = bpf_remote_lookup_elem(map_fd, kstr, klen, llen);
			if (!lstr)
				printf("bpf_lookup_elem: ret=%d\n", -1);
			else
				printf("%s\n", lstr);
			if (lstr) free(lstr);

		} else if (!strcmp(cmd, "BPF_GET_FIRST_KEY")) {
			int map_fd, klen;
			char *tok, *kstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_INT(klen);

			kstr = bpf_remote_get_first_key(map_fd, klen);
			if (!kstr)
				printf("bpf_get_first_key: ret=%d\n", -1);
			else
				printf("%s\n", kstr);
			if (kstr) free(kstr);

		} else if (!strcmp(cmd, "BPF_GET_NEXT_KEY")) {
			int map_fd, klen;
			char *tok, *kstr, *next_kstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_STR(kstr);
			PARSE_INT(klen);

			next_kstr = bpf_remote_get_next_key(map_fd, kstr, klen);
			if (!next_kstr)
				printf("bpf_get_next_key: ret=%d\n", -1);
			else
				printf("%s\n", next_kstr);
			if (next_kstr) free(next_kstr);

		} else if (!strcmp(cmd, "PERF_READER_POLL")) {
			int len, *fds, i, timeout, ret;

			PARSE_FIRST_INT(timeout);
			PARSE_INT(len);

			fds = (void *)malloc(len);
			if (!fds)
				printf("perf_reader_poll: ret=%d\n", -ENOMEM);

			for (i = 0; i < len; i++) {
				PARSE_INT(fds[i]);
			}

			ret = remote_perf_reader_poll(fds, len, timeout);
			if (ret < 0)
				printf("perf_reader_poll: ret=%d\n", ret);
		} else {

invalid_command:
			printf("Command not recognized\n");
		}

		printf("END_BPFD_OUTPUT\n");
		fflush(stdout);
	}
	return 0;
}
