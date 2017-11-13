#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#define LINEBUF_SIZE  100
#define LINE_TOKENS   10

int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);
size_t base64_decode( char *source, unsigned char *target, size_t targetlen);

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

void test_base64(char *file) {
	struct stat st;
	char *fileout, *encoded, *filebuf;
	size_t size;
	int ret;
	FILE *fp;
	char *target;

	stat(file, &st);
	size = st.st_size;

	fileout = (char *)malloc(strlen(file) + 1 + 4);
	fileout[0] = 0;
	strcat(fileout, file);
	strcat(fileout, ".b64dec");

	printf("Encoding and then decoding %s into %s, filesize is %d\n", file, fileout, size);

	encoded = (char *)malloc((size * 4) + 1);
	encoded[(size * 4)] = 0;

	filebuf = (char *)malloc(size);
	fp = fopen(file, "rb");
	fread(filebuf, size, 1, fp);

	ret = base64_encode(filebuf, size, encoded, size*4);

	printf("encoded len: %d\n", strlen(encoded));

	printf("encoded stat: %s\n", encoded);

	target = (char *)malloc(size);

	ret = base64_decode(encoded, target, size);

	fp = fopen(fileout, "wb");

	printf("fp=%p ret=%d fileout=%s\n", (void *)fp, ret, fileout);

	fwrite(target, size, 1, fp);

	fclose(fp);
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
