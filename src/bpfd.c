/*
 * BPFd (Berkeley Packet Filter daemon)
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
 int bpf_prog_load(enum bpf_prog_type prog_type, const char *name,
 const struct bpf_insn *insns, int prog_len,
 const char *license, unsigned kern_version,
 char *log_buf, unsigned log_buf_size)
 */
int bpf_prog_load_handle(int type, char *name, char *bin_b64, int prog_len, char *license,
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

	/* TODO: logging disabled for now, add mechanism in future */
	ret = bpf_prog_load((enum bpf_prog_type)type, name, insns, prog_len,
			(const char *)license, kern_version, 0, NULL, 0);

	printf("bpf_prog_load: ret=%d\n", ret);
	return ret;
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

char *bpf_remote_get_first_key_dump_all(int map_fd, int klen, int llen)
{
	void *kbin, *lbin, *next_kbin = NULL, *tmp;
	int ret, dump_buf_len = 4096, dump_used = 1;
	char *dump_buf, *kstr, *lstr, *rets = NULL;

	/* length of base64 buffer with newlines considered */
	#define KSTR_SIZE ((klen * 2) + 2)
	#define LSTR_SIZE ((llen * 2) + 2)

	dump_buf = (char *)malloc(dump_buf_len);
	kbin = (void *)malloc(klen);
	lbin = (void *)malloc(llen);
	kstr = (char *)malloc(KSTR_SIZE);
	lstr = (char *)malloc(LSTR_SIZE);

	if (!dump_buf || !kbin || !lbin || !lstr || !kstr)
		goto err_get;

	if (bpf_get_first_key(map_fd, kbin, klen) < 0)
		goto get_done;

	dump_buf[0] = 0;

	do {
		next_kbin = (void *)malloc(klen);
		if (!next_kbin) goto err_get;

		if (bpf_lookup_elem(map_fd, kbin, lbin) < 0)
			goto err_get;

		if (!base64_encode(kbin, klen, kstr, KSTR_SIZE)
			|| !base64_encode(lbin, llen, lstr, LSTR_SIZE))
			goto err_get;

		if (dump_buf_len - dump_used < (LSTR_SIZE + KSTR_SIZE)) {
			dump_buf_len *= 2;
			dump_buf = (char *)realloc(dump_buf, dump_buf_len);
		}

		strcat(kstr, "\n");
		strcat(lstr, "\n");
		strncat(dump_buf, kstr, dump_buf_len);
		strncat(dump_buf, lstr, dump_buf_len);
		dump_used += (KSTR_SIZE + LSTR_SIZE);

		ret = bpf_get_next_key(map_fd, kbin, next_kbin);

		tmp = kbin;
		kbin = next_kbin;
		next_kbin = NULL;
		free(tmp);
	} while (ret >= 0);

	rets = dump_buf;
	goto get_done;

err_get:
	printf("bpf_remote_get_first_key_dump_all: error condition\n");
	if (dump_buf) free(dump_buf);
get_done:
	if (kbin) free(kbin);
	if (lbin) free(lbin);
	if (kstr) free(kstr);
	if (lstr) free(lstr);
	if (next_kbin) free(next_kbin);
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

int bpf_remote_delete_elem(int map_fd, char *kstr, int klen)
{
	void *kbin;
	int ret = -ENOMEM;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_update;

	ret = -1;
	if (!base64_decode(kstr, kbin, klen))
		goto err_update;

	ret = bpf_delete_elem(map_fd, kbin);

err_update:
	if (kbin) free(kbin);
	return ret;
}

/*
 * Clear a map by iterating over keys.
 * Return delete error code if any deletes or allocs fail
 * else return how many keys were iterated and deleted.
 */
int bpf_clear_map(int map_fd, int klen)
{
	void *kbin, *next_kbin = NULL, *tmp = NULL;
	int count = 0, ret = -ENOMEM;

	kbin = (void *)malloc(klen);
	if (!kbin)
		goto err_clear;

	if (bpf_get_first_key(map_fd, kbin, klen) < 0) {
		ret = 0;
		goto err_clear;
	}

	do {
		next_kbin = (void *)malloc(klen);
		if (!next_kbin) {
			ret = -ENOMEM;
			goto err_clear;
		}

		ret = bpf_delete_elem(map_fd, kbin);
		if (ret < 0)
			goto err_clear;
		count++;

		ret = bpf_get_next_key(map_fd, kbin, next_kbin);

		tmp = kbin;
		kbin = next_kbin;
		next_kbin = NULL;
		free(tmp);
	} while (ret >= 0);

	ret = count;
err_clear:
	if (kbin) free(kbin);
	if (next_kbin) free(next_kbin);
	return ret;
}

int main(int argc, char **argv)
{
	char line_buf[LINEBUF_SIZE];
	char *cmd, *lineptr, *argstr, *tok, *kvers_str = NULL;
	int len, c, kvers = -1;

	opterr = 0;
	while ((c = getopt (argc, argv, "k:")) != -1)
		switch (c)
		{
			case 'k':
				kvers_str = optarg;
				break;
			case '?':
				if (optopt == 'k')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr,"Unknown option character `\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}

	if (kvers_str)
		kvers = atoi(kvers_str);

	printf("STARTED_BPFD\n");

	while (fgets(line_buf, LINEBUF_SIZE, stdin)) {
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

		if (!cmd)
			break;

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
			char *license, *bin_data, *name;
			unsigned int kern_version, kvdummy;
			/*
			 * Command format: BPF_PROG_LOAD type prog_len license kern_version binary_data
			 * Prototype of lib call:
			 * int bpf_prog_load(enum bpf_prog_type prog_type,
			 * const struct bpf_insn *insns, int prog_len,
			 * const char *license, unsigned kern_version, char *log_buf, unsigned log_buf_size)
			*/
			PARSE_FIRST_INT(type);
			PARSE_STR(name);
			PARSE_INT(prog_len);
			PARSE_STR(license);
			if (kvers != -1) {
				kern_version = kvers;
				PARSE_UINT(kvdummy);  /* skip field */
			} else {
				PARSE_UINT(kern_version);
			}
			PARSE_STR(bin_data);

			if (!strcmp(name, "__none__"))
				name = NULL;
			bpf_prog_load_handle(type, name, bin_data, prog_len, license, kern_version);

		} else if (!strcmp(cmd, "BPF_ATTACH_KPROBE")) {
			int len, ret, prog_fd, type;
			char *ev_name, *fn_name;

			PARSE_FIRST_INT(prog_fd);
			PARSE_INT(type);
			PARSE_STR(ev_name);
			PARSE_STR(fn_name);

			/*
			 * TODO: We're leaking a struct perf_reader here, we should free it somewhere.
			 */
			if (!bpf_attach_kprobe(prog_fd, type, ev_name, fn_name, NULL, NULL))
				ret = -1;
			else
				ret = prog_fd;

			printf("bpf_attach_kprobe: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_DETACH_KPROBE")) {
			int len, ret;
			char *evname;

			PARSE_FIRST_STR(evname);
			ret = bpf_detach_kprobe(evname);
			printf("bpf_detach_kprobe: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_ATTACH_UPROBE")) {
			int len, ret, prog_fd, type, pid;
			char *ev_name, *binary_path;
			uint64_t offset;

			PARSE_FIRST_INT(prog_fd);
			PARSE_INT(type);
			PARSE_STR(ev_name);
			PARSE_STR(binary_path);
			PARSE_UINT64(offset);
			PARSE_INT(pid);

			/*
			 * TODO: We're leaking a struct perf_reader here, we should free it somewhere.
			 */
			if (!bpf_attach_uprobe(prog_fd, type, ev_name, binary_path, offset, pid, NULL, NULL))
				ret = -1;
			else
				ret = prog_fd;

			printf("bpf_attach_uprobe: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_DETACH_UPROBE")) {
			int len, ret;
			char *evname;

			PARSE_FIRST_STR(evname);
			ret = bpf_detach_uprobe(evname);
			printf("bpf_detach_uprobe: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_ATTACH_TRACEPOINT")) {
			int len, ret, prog_fd;
			char *tpname, *category;
			/*
			 * void * bpf_attach_tracepoint(int progfd, const char *tp_category,
			 *		const char *tp_name, perf_reader_cb cb, void *cb_cookie)
			 */

			PARSE_FIRST_INT(prog_fd);
			PARSE_STR(category);
			PARSE_STR(tpname);

			/*
			 * TODO: We're leaking a struct perf_reader here, we should free it somewhere.
			 */
			if (!bpf_attach_tracepoint(prog_fd, category, tpname, NULL, NULL))
				ret = -1;
			else
				ret = prog_fd;

			printf("bpf_attach_tracepoint: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_CREATE_MAP")) {
			/*
				int bpf_create_map(enum bpf_map_type map_type, const char *name,
                   int key_size, int value_size, int max_entries,
                   int map_flags);
			 */

			int ret, type, len, key_size, value_size, max_entries, map_flags;
			char *name;

			PARSE_FIRST_INT(type);
			PARSE_STR(name);
			PARSE_INT(key_size);
			PARSE_INT(value_size);
			PARSE_INT(max_entries);
			PARSE_INT(map_flags);

			if (!strcmp(name, "__none__"))
				name = NULL;
			ret = bpf_create_map((enum bpf_map_type)type, name, key_size, value_size, max_entries, map_flags);
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
			int map_fd, klen, llen, dump_all;
			char *tok, *kstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_INT(klen);
			PARSE_INT(llen);
			PARSE_INT(dump_all);

			if (dump_all)
				kstr = bpf_remote_get_first_key_dump_all(map_fd, klen, llen);
			else
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

		} else if (!strcmp(cmd, "BPF_DELETE_ELEM")) {
			int map_fd, klen, ret;
			char *tok, *kstr;

			PARSE_FIRST_INT(map_fd);
			PARSE_STR(kstr);
			PARSE_INT(klen);

			ret = bpf_remote_delete_elem(map_fd, kstr, klen);
			printf("bpf_delete_elem: ret=%d\n", ret);

		} else if (!strcmp(cmd, "BPF_CLEAR_MAP")) {
			int map_fd, klen, ret;

			PARSE_FIRST_INT(map_fd);
			PARSE_INT(klen);

			ret = bpf_clear_map(map_fd, klen);
			printf("bpf_clear_map: ret=%d\n", ret);

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
