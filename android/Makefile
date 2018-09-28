CC ?= gcc
CXX ?= g++

bpfloader: bpfmap.h libbpf.o perf_reader.o loader.cc
	g++ $^ -o $@

clean:
	rm *.o bpfloader

