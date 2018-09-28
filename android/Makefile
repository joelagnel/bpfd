CC ?= gcc
CXX ?= g++

bpfloader: libbpf.h libbpf_bcc.o perf_reader.o loader.cc
	g++ $^ -o $@

clean:
	rm *.o bpfloader

