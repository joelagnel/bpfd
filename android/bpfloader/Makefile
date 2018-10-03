CC = clang
CXX = clang++
CFLAGS = -fPIC -Werror -Wpointer-arith -Wsign-compare -Wunused-parameter -Wformat -Wunused-label -Wunused-variable -Wsometimes-uninitialized
CXXFLAGS = -fPIC -std=c++11 -stdlib=libc++ -Werror -Wpointer-arith -Wsign-compare -Wunused-parameter -Wformat -Wunused-label -Wunused-variable -Wsometimes-uninitialized

bpfloader: main.cc
	clang++ $(CXXFLAGS) ../libbpf.so -I ../ $^ -o $@

clean:
	rm *.o bpfloader >/dev/null 2>&1 || true
