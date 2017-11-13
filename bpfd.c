#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#define LINEBUF_SIZE  2000000
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

	printf("Encoding and then decoding %s into %s, filesize is %d\n", file, fileout, (int)size);

	encoded = (char *)malloc((size * 4) + 1);
	encoded[(size * 4)] = 0;

	filebuf = (char *)malloc(size);
	fp = fopen(file, "rb");
	fread(filebuf, size, 1, fp);

	ret = base64_encode(filebuf, size, encoded, size*4);

	printf("encoded len: %d\n", (int)strlen(encoded));

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
				goto invalid_command;
		} else if (cmd && !strcmp(cmd, "BPF_PROG_LOAD")) {
			int len, prog_len;
			char *tok, *license, *bin_data, *type;
			unsigned int kern_version;
			/* Command format: BPF_PROG_LOAD type prog_len license kern_version binary_data
			 *
			 * Prototype of lib call:
			int bpf_prog_load(enum bpf_prog_type prog_type,
					const struct bpf_insn *insns, int prog_len,
					const char *license, unsigned kern_version,
					char *log_buf, unsigned log_buf_size)
			*/
			len = strlen(argstr);
			tok = strtok(argstr, " ");
			if (strlen(tok) == len)
				goto invalid_command;

			type = tok;

			tok = strtok(NULL, " ");
			if (!tok)
				goto invalid_command;
			if (!sscanf(tok, "%d ", &prog_len))
				goto invalid_command;

			tok = strtok(NULL, " ");
			if (!tok)
				goto invalid_command;
			license = tok;

			tok = strtok(NULL, " ");
			if (!tok)
				goto invalid_command;
			if (!sscanf(tok, "%u ", &kern_version))
				goto invalid_command;

			tok = strtok(NULL, " ");
			if (!tok)
				goto invalid_command;
			bin_data = tok;

			printf("BPF_PROG_LOAD: %s %d %s %u %s\n", type, prog_len, license, kern_version, bin_data);
		} else {
invalid_command:
			printf("Command not recognized\n");
		}

		fflush(stdout);
	}
	return 0;
}
