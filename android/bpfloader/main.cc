#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libbpf.h>

#define BCC_OBJ_DIR "/home/joelaf/tmp/system/etc/bpf/"
using namespace android::bpf;

int main(void)
{
	DIR *dir;
	struct dirent *ent;

	if ((dir = opendir(BCC_OBJ_DIR)) != NULL) {
		while ((ent = readdir(dir)) != NULL) {
			int len = strlen(ent->d_name);
			if (len < 2 ||
			    ent->d_name[len-2] != '.' ||
			    ent->d_name[len-1] != 'o')
				continue;

			int prog_len = strlen(BCC_OBJ_DIR) + strlen(ent->d_name) + 1;
			char *prog_path = (char *)malloc(prog_len);
			prog_path[0] = 0;

			strncat(prog_path, BCC_OBJ_DIR, prog_len);
			strncat(prog_path, ent->d_name, prog_len);

			int ret = load_prog(prog_path);

			if (ret) {
				printf("Error loading BPF program %s\n", ent->d_name);
				return ret;
			}
		}
		closedir(dir);
	} else {
		/* could not open directory */
		return -EXIT_FAILURE;
	}

	return 0;
}
