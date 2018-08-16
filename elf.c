#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/elf.h>
#include <unistd.h>

#define assert(cond) if (!cond) {						\
	char line[20];										\
	if (errno == 0) errno = -1;							\
	sprintf(line, "Error at function: %s line:%d file: %s", \
			__func__, __LINE__, __FILE__);				\
	perror(line); exit(0);								\
}

Elf64_Ehdr read_elf_header(char *elfpath)
{
	Elf64_Ehdr eh;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);
	assert(fread(&eh, sizeof(eh), 1, elf_file) == 1);
	fclose(elf_file);
	return eh;
}

/* Reads all section header tables into an Shdr array */
Elf64_Shdr *read_section_headers_all(char *elfpath, int *entries)
{
	Elf64_Ehdr eh;
	Elf64_Shdr *sh_table;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	eh = read_elf_header(elfpath);

	/* Read offset of shdr table */
	assert(fseek(elf_file, eh.e_shoff, SEEK_SET) == 0);

	/* Read shdr table */
	sh_table = (Elf64_Shdr *)malloc(sizeof(*sh_table) * eh.e_shnum);
	assert(fseek(elf_file, eh.e_shoff, SEEK_SET) == 0);
	assert(fread((void *)sh_table, eh.e_shentsize, eh.e_shnum, elf_file)
			== eh.e_shnum);

	fclose(elf_file);

	*entries = eh.e_shentsize;
	return sh_table;
}

/* Read a section by its index - for ex to get sec hdr strtab blob */
void *read_section_by_id(char *elfpath, int id, int *bytes)
{
	Elf64_Shdr *sh_table;
	Elf64_Off shoff;
	int entries;
	FILE *elf_file;
	char *section;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	sh_table = read_section_headers_all(elfpath, &entries);

	section = (char *)malloc(sh_table[id].sh_size);
	assert(fseek(elf_file, sh_table[id].sh_offset, SEEK_SET) == 0);
	assert(fread(section, sh_table[id].sh_size, 1, elf_file) == 1);
	*bytes = sh_table[id].sh_size;

	free(sh_table);
	fclose(elf_file);

	return (void *)section;
}

/* Read whole section header string table */
char *read_section_header_strtab(char *elfpath, int *bytes)
{
	Elf64_Ehdr eh;
	FILE *elf_file;
	char *strtab;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	eh = read_elf_header(elfpath);
	strtab = (char *)read_section_by_id(elfpath, eh.e_shstrndx, bytes);

	fclose(elf_file);
	return strtab;
}

/* Reads a full section by name - example to get the GPL license */
void *read_section_by_name(char *name, char *elfpath, int *bytes)
{
	char *sec_strtab;
	char *data = NULL;
	int n_sh_table;
	Elf64_Shdr *sh_table;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);
	sh_table = read_section_headers_all(elfpath, &n_sh_table);
	sec_strtab = read_section_header_strtab(elfpath, bytes);

	for(int i = 0; i < n_sh_table; i++) {
		char *secname = sec_strtab + sh_table[i].sh_name;
		if (!secname)
			continue;

		if (!strcmp(secname, name)) {
			data = (char *)malloc(sh_table[i].sh_size);
			assert(fseek(elf_file, sh_table[i].sh_offset, SEEK_SET) == 0);
			assert(fread(data, sh_table[i].sh_size, 1, elf_file) == 1);
			*bytes = sh_table[i].sh_size;
			goto done;
		}
	}

done:
	free(sh_table);
	free(sec_strtab);
	fclose(elf_file);
	return data;
}

int main()
{
	char *license;
	char elfpath[] = "tracex2_kern.o";
	int bytes;

	license = read_section_by_name("license", elfpath, &bytes);
	printf("License: %s\n", license);
	return 0;
}

/* vim: set ts=4 sw=4: */
