CC = clang
CXX = clang++
CFLAGS = -fPIC -Werror -Wpointer-arith -Wsign-compare -Wunused-parameter -Wformat -Wunused-label -Wunused-variable -Wsometimes-uninitialized
CXXFLAGS = -fPIC -std=c++11 -stdlib=libc++ -Werror -Wpointer-arith -Wsign-compare -Wunused-parameter -Wformat -Wunused-label -Wunused-variable -Wsometimes-uninitialized

libbpf.so: libbpf_core.o perf_reader.o loader.o
	clang++ $^ -shared -o $@

tis: libbpf.so tis.cc
	clang++ -o tis tis.cc libbpf.so

clean:
	rm *.o bpfloader libbpf.so tis >/dev/null 2>&1 || true
