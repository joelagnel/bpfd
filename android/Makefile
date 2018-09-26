CC ?= gcc
CXX ?= g++

bpfloader: libbpf.o perf_reader.o elf_loader.cc
	g++ $^ -o $@

clean:
	rm *.o bpfloader

