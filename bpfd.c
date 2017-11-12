#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define LINEBUF_SIZE  100
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

	printf("START TRACEFS READ: %s\n", tracef);
	fflush(stdout);

	while ((len = read(fd, &buf, 4096)) > 0)
		write(1, buf, len);

	close(fd);

	printf("END TRACEFS READ: %s\n", tracef);
	return 0;

}

int main(int argc, char **argv)
{
	char line_buf[LINEBUF_SIZE];
	char *cmd, *lineptr, *argstr;
	int len, fd;

	while (fgets(line_buf, LINEBUF_SIZE, stdin)) {
		int fd;
		line_buf[strcspn(line_buf, "\n")] = 0;
		line_buf[strcspn(line_buf, "\r\n")] = 0;

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
				continue;
		}
		else
			printf("Command not recognized\n");

		fflush(stdout);
	}
	return 0;
}
