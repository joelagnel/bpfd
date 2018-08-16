#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/elf.h>
#include <unistd.h>

#define assert(cond) if (!cond) {						\
	char line[20];										\
	if (errno == 0) errno = -1;							\
	sprintf(line, "Error at function: %s line:%d file: %s", \
			__func__, __LINE__, __FILE__);				\
	perror(line); exit(0);								\
}

enum code_type {
	TRACEPOINT,
	KPROBE
};

struct code_section {
	enum code_type type;
	char *name;
	void *data;
	int data_len;
	void *rel_data;
	int rel_data_len;

	/* sections added as discovered */
	struct code_section *next;
};

Elf64_Ehdr read_elf64_header(char *elfpath)
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
Elf64_Shdr *read_section64_headers_all(char *elfpath, int *entries)
{
	Elf64_Ehdr eh;
	Elf64_Shdr *sh_table;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	eh = read_elf64_header(elfpath);

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
void *read_section64_by_id(char *elfpath, int id, int *bytes)
{
	Elf64_Shdr *sh_table;
	Elf64_Off shoff;
	int entries;
	FILE *elf_file;
	char *section;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	sh_table = read_section64_headers_all(elfpath, &entries);

	section = (char *)malloc(sh_table[id].sh_size);
	assert(fseek(elf_file, sh_table[id].sh_offset, SEEK_SET) == 0);
	assert(fread(section, sh_table[id].sh_size, 1, elf_file) == 1);
	*bytes = sh_table[id].sh_size;

	free(sh_table);
	fclose(elf_file);

	return (void *)section;
}

/* Read whole section header string table */
char *read_section64_header_strtab(char *elfpath, int *bytes)
{
	Elf64_Ehdr eh;
	FILE *elf_file;
	char *strtab;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);

	eh = read_elf64_header(elfpath);
	strtab = (char *)read_section64_by_id(elfpath, eh.e_shstrndx, bytes);

	fclose(elf_file);
	return strtab;
}

/* Get name from ID */
char *get_section64_name_from_nameoff(char *elfpath, int name_off)
{
	char *sec_strtab, *name, *ret;
	int bytes;

	sec_strtab = read_section64_header_strtab(elfpath, &bytes);

	if (name_off >= bytes)
		return NULL;

	name = sec_strtab + name_off;
	ret = (char *)malloc(strlen(name) + 1);
	memcpy(ret, name, strlen(name) + 1);

	free(sec_strtab);
	return ret;
}

/* Reads a full section by name - example to get the GPL license */
void *read_section64_by_name(char *name, char *elfpath, int *bytes)
{
	char *sec_strtab;
	char *data = NULL;
	int n_sh_table;
	Elf64_Shdr *sh_table;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);
	sh_table = read_section64_headers_all(elfpath, &n_sh_table);
	sec_strtab = read_section64_header_strtab(elfpath, bytes);

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

int _startswith(const char *a, const char *b)
{
   if(strncmp(a, b, strlen(b)) == 0) return 1;
   return 0;
}

/* Read a section by its index - for ex to get sec hdr strtab blob */
struct code_section *read_code_sections(char *elfpath)
{
	Elf64_Shdr *sh_table;
	int entries;
	struct code_section *cs_ret = NULL;

	sh_table = read_section64_headers_all(elfpath, &entries);

	for (int i = 0; i < entries; i++) {
		char *name = get_section64_name_from_nameoff(elfpath, sh_table[i].sh_name);
		int bytes;
		struct code_section *cs = NULL;

		if (name && (_startswith(name, "kprobe/") ||
					 _startswith(name, "tracepoint/"))) {

			cs = (struct code_section *)calloc(1, sizeof(*cs));

			cs->type = (_startswith(name, "kprobe/")) ? KPROBE : TRACEPOINT;
			cs->name = name;
			cs->data = read_section64_by_id(elfpath, i, &bytes);
			cs->data_len = bytes;
		} else if (name) {
			free(name);
		}

		name = NULL;
		/* Check for rel section */
		if (cs && cs->data && i < entries - 1) {
			name = get_section64_name_from_nameoff(elfpath, sh_table[i+1].sh_name);

			if (name && (cs->type == KPROBE && _startswith(name, ".relkprobe/") ||
						 cs->type == TRACEPOINT &&_startswith(name, ".reltracepoint/"))) {
				cs->rel_data = read_section64_by_id(elfpath, i+1, &bytes);
				cs->rel_data_len = bytes;
			}
		} else if (name) {
			free(name);
		}

		if (cs) {
			cs->next = cs_ret;
			cs_ret = cs;
		}
	}

	free(sh_table);
	return cs_ret;
}

void deslash(char *s)
{
	if (!s)
		return;

	for (int i = 0; i < strlen(s); i++) {
		if (s[i] == '/')
			s[i] = '_';
	}
}

int main()
{
	char *license;
	char elfpath[] = "tracex2_kern.o";
	int bytes;
	struct code_section *cs;

	license = read_section64_by_name("license", elfpath, &bytes);
	printf("License: %s\n", license);

	/* dump all code and rel sections */
	cs = read_code_sections(elfpath);


	while (cs) {
		char fname[20];
		FILE *f;

		strcpy(fname, "code_");
		strcat(fname, cs->name);
		deslash(fname);

		f = fopen(fname, "w+");
		fwrite(cs->data, cs->data_len, 1, f);

		strcpy(fname, "rel_");
		strcat(fname, cs->name);
		deslash(fname);

		f = fopen(fname, "w+");
		fwrite(cs->rel_data, cs->rel_data_len, 1, f);

		cs = cs->next;
	}

	return 0;
}

/* vim: set ts=4 sw=4: */
