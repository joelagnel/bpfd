CC ?= gcc
CXX ?= g++
CFLAGS = -fPIC
CXXFLAGS = -fPIC

libbpf.so: libbpf.h libbpf_bcc.o perf_reader.o loader.o
	g++ $^ -shared -o $@

tis: libbpf.so tis.cc
	g++ -o tis tis.cc libbpf.so

clean:
	rm *.o bpfloader libbpf.so tis >/dev/null 2>&1 || true
