/*
 * BPFd (Berkeley Packet Filter daemon)
 * Support for perf readers.
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

/*
 * This file's functionality should be properly abstracted
 * within libbpf.c and perf_reader.c. For now, duplicate the
 * struct here
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
#include "perf_reader.h"
#include "bpfd.h"

#define MAX_READERS 1024

struct perf_reader {
  perf_reader_cb cb;
  perf_reader_raw_cb raw_cb;
  perf_reader_lost_cb lost_cb;
  void *cb_cookie; // to be returned in the cb
  void *buf; // for keeping segmented data
  size_t buf_size;
  void *base;
  int page_size;
  int page_cnt;
  int fd;
  uint32_t type;
  uint64_t sample_type;
};

struct perf_reader *remote_readers[MAX_READERS];

void remote_raw_reader_cb(void *cookie, void *raw, int size)
{
	struct perf_reader *reader = cookie;
	char *raw_str;

	raw_str = malloc(size * 4);

	if (!base64_encode(raw, size, raw_str, size*4))
		printf("raw_cb: b64 encode failed for reader fd=%d\n",
			   reader->fd);

	printf("%d %d %s\n", reader->fd, size, raw_str);

	free(raw_str);
}

void remote_lost_reader_cb(void *ptr, uint64_t lost)
{
}

int bpf_remote_open_perf_buffer(int pid, int cpu, int page_cnt)
{
	struct perf_reader *reader;

	reader = bpf_open_perf_buffer(remote_raw_reader_cb, remote_lost_reader_cb,
								  NULL, pid, cpu, page_cnt);
	if (!reader)
		return -1;

	reader->cb_cookie = reader;
	remote_readers[reader->fd] = reader;
	return reader->fd;
}

int remote_perf_reader_poll(int *fds, int len, int timeout)
{
	struct perf_reader **readers;
	int i, ret;

	readers = (struct perf_reader **)malloc(len * sizeof(void *));

	for (i = 0; i < len; i++)
		readers[i] = remote_readers[fds[i]];

	ret = perf_reader_poll(len, readers, timeout);

	free(readers);

	return ret;
}
