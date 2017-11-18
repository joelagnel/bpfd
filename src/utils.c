/*
 * BPFd (Berkeley Packet Filter daemon)
 * Common utility/helper functions.
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
#include "utils.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

/* Read a file on the local fs to stdout */
int cat_file(char *path) {
	char buf[4096];
	int len, fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("Open failed, ignoring\n");
		return fd;
	}

	while ((len = read(fd, &buf, 4096)) > 0)
		write(1, buf, len);

	close(fd);

	return 0;

}

/* Read a tracefs file to stdout */
int cat_tracefs_file(char *tracefs, char *fn) {
	char tracef[100];

	tracef[0] = 0;
	strcat(tracef, tracefs);
	strcat(tracef, "/");
	strcat(tracef, fn);

	return cat_file(tracef);
}

int cat_dir(char *path, int dirs_only)
{
	DIR *dp;
	struct dirent *ep;

	dp = opendir(path);
	if (!dp)
		return -1;

	while (ep = readdir(dp)) {
		struct stat st;

		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;

		if (dirs_only) {
			if (fstatat(dirfd(dp), ep->d_name, &st, 0) < 0)
				continue;

			if (!S_ISDIR(st.st_mode))
				continue;
		}

		printf("%s\n", ep->d_name);
	}
	closedir (dp);

	return 0;
}
