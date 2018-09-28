CC ?= gcc
CXX ?= g++
CFLAGS = -fPIC
CXXFLAGS = -fPIC

libbpf.so: libbpf.h libbpf_bcc.o perf_reader.o loader.o
	g++ $^ -shared -o $@

clean:
	rm *.o bpfloader libbpf.so
