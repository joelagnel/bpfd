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

int cat_file(char *path);
int cat_tracefs_file(char *tracefs, char *fn);
int cat_dir(char *path, int dirs_only);
