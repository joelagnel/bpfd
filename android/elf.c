#include <linux/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <linux/elf.h>
#include <unistd.h>

#include "libbpf.h"
#define assert(cond) if (!(cond)) {						\
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

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
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

/* Get name from offset in strtab */
char *get_sym64_name(char *elfpath, int name_off)
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

void *read_section64_by_type(char *elfpath, int type, int *bytes)
{
	char *data = NULL;
	int n_sh_table;
	Elf64_Shdr *sh_table;
	FILE *elf_file;

	elf_file = fopen(elfpath, "r");
	assert(!!elf_file);
	sh_table = read_section64_headers_all(elfpath, &n_sh_table);

	for(int i = 0; i < n_sh_table; i++) {
		if (sh_table[i].sh_type != type)
			continue;

		data = (char *)malloc(sh_table[i].sh_size);
		assert(fseek(elf_file, sh_table[i].sh_offset, SEEK_SET) == 0);
		assert(fread(data, sh_table[i].sh_size, 1, elf_file) == 1);
		*bytes = sh_table[i].sh_size;
		break;
	}

	free(sh_table);
	fclose(elf_file);
	return data;
}

int sym64_compare(const void *a1, const void *b1)
{
	Elf64_Sym *a, *b;

	a = (Elf64_Sym *)a1;
	b = (Elf64_Sym *)b1;

	return (a->st_value - b->st_value);
}

Elf64_Sym *read_sym64_tab(char *elfpath, int *bytes)
{
	Elf64_Sym *data;

	data = read_section64_by_type(elfpath, SHT_SYMTAB, bytes);
	if (!data)
		return data;

	qsort(data, *bytes / sizeof(*data), sizeof(*data), sym64_compare);
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
		char *name = get_sym64_name(elfpath, sh_table[i].sh_name);
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
			name = get_sym64_name(elfpath, sh_table[i+1].sh_name);

			if (name && ((cs->type == KPROBE && _startswith(name, ".relkprobe/"))||
				     (cs->type == TRACEPOINT &&_startswith(name, ".reltracepoint/")))) {
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

char **get_map_names(char *elfpath, int *n)
{
	Elf64_Sym *symtab;
	Elf64_Shdr *sh_table;
	int bytes, entries, maps_idx = -1, nmaps = 0, j = 0;
	char **names;

	symtab = read_sym64_tab(elfpath, &bytes);

	/* Get index of maps section */
	sh_table = read_section64_headers_all(elfpath, &entries);
	for (int i = 0; i < entries; i++) {
		if (!strncmp(get_sym64_name(elfpath, sh_table[i].sh_name),
					"maps", 4)) {
			maps_idx = i;
			break;
		}
	}
	if (maps_idx == -1)
		return NULL;

	/* Count number of maps */
	for (int i = 0; i < bytes / sizeof(*symtab); i++)
		if (symtab[i].st_shndx == maps_idx)
			nmaps++;

	names = (char **)calloc(nmaps, sizeof(char *));
	for (int i = 0; i < bytes / sizeof(*symtab); i++)
		if (symtab[i].st_shndx == maps_idx)
			names[j++] = get_sym64_name(elfpath, symtab[i].st_name);

	*n = nmaps;
	return names;
}

int *create_maps(char *elfpath, int *n)
{
	int bytes, *map_fds;
	struct bpf_map_def *md = NULL;
	char **map_names = NULL;

	md = read_section64_by_name("maps", elfpath, &bytes);
	if (!md)
		return NULL;

	map_names = get_map_names(elfpath, n);
	if (!map_names)
		return NULL;

	map_fds = (int *)malloc(*n * sizeof(int));
	assert(map_fds);

	for (int i = 0; i < *n; i++)
	{
		int fd;
		fd = bpf_create_map(md[i].type, map_names[i],
				md[i].key_size, md[i].value_size,
				md[i].max_entries, md[i].map_flags);
		map_fds[i] = fd;
		printf("map %d is %s with fd %d\n", i, map_names[i], fd);
	}

	free(map_names);
	free(md);
	return map_fds;
}
int main()
{
	char *license;
	char elfpath[] = "tracex2_kern.o";
	struct code_section *cs;
	int n, bytes;
	int *map_fds;

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

	map_fds = create_maps(elfpath, &n);

	for (int i = 0; i < n; i++)
		printf("fd: %d\n", map_fds[i]);


	return 0;
}





/* vim: set ts=4 sw=4: */
