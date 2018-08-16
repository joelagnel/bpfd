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

int main()
{
	Elf64_Ehdr eh;
	Elf64_Shdr *sh_table, shstrtab;
	Elf64_Off shoff;
	FILE *elf_file;
	int n_shdrs, idx_shstr, i, n;
	char *section_strtab;
	char *license;

	elf_file = fopen("tracex2_kern.o", "r");
	assert(!!elf_file);

	/* Read ehdr */
	assert(fread(&eh, sizeof(eh), 1, elf_file) == 1);

	/* Read offset of shdr table */
	assert(fseek(elf_file, eh.e_shoff, SEEK_SET) == 0);
	printf("\nSection Header offset\t= 0x%08lx\n", eh.e_shoff);

	/* Read shdr table */
	n_shdrs = eh.e_shnum;
	sh_table = (Elf64_Shdr *)malloc(sizeof(*sh_table) * n_shdrs);
	assert(fseek(elf_file, eh.e_shoff, SEEK_SET) == 0);
	assert(fread((void *)sh_table, eh.e_shentsize, eh.e_shnum, elf_file)
			== eh.e_shnum);

	/* Read section header of section header string table */
	idx_shstr = eh.e_shstrndx;
	shstrtab = sh_table[idx_shstr];
	assert(shstrtab.sh_type == SHT_STRTAB);

	/* Read section header string table */
	section_strtab = (char *)malloc(shstrtab.sh_size);
	assert(fseek(elf_file, shstrtab.sh_offset, SEEK_SET) == 0);
	assert(fread(section_strtab, shstrtab.sh_size, 1, elf_file) == 1);

	/* Find license */
	for(int i = 0; i < eh.e_shnum; i++) {
		char *secname = section_strtab + sh_table[i].sh_name;
		if (!secname)
			continue;

		if (!strcmp(secname, "license")) {
			license = (char *)malloc(sh_table[i].sh_size);
			assert(fseek(elf_file, sh_table[i].sh_offset, SEEK_SET) == 0);
			assert(fread(license, sh_table[i].sh_size, 1, elf_file) == 1);
			printf("License found: %s\n", license);
		}
	}

	/*
	for(int i = 0; i < eh.e_shnum; i++)
		printf("sh %d: off: %lx nameid:%s \n", i, sh_table[i].sh_offset,
				section_strtab + sh_table[i].sh_name);
	*/

	return 0;
}

/* vim: set ts=4 sw=4: */
