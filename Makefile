BPFD_SRCS       := src/bpfd.c src/base64.c src/utils.c
LIBBPF_SRC      := src/lib/bpf/libbpf.c
PERF_READER_SRC := src/lib/bpf/perf_reader.c
INCLUDE := -I/home/joelaf/repo/linux-mainline/usr/include/ -I./src/lib/bpf/compat/

CFLAGS := $(INCLUDE) -L./build/
# CC := aarch64-linux-gnu-gcc-4.9

all: build/bpfd

build/libbpf.o: $(LIBBPF_SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

build/perf_reader.o: $(PERF_READER_SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

build/libbpf_bpfd.so: build/libbpf.o build/perf_reader.o
	mkdir -p build
	$(CC) $(CFLAGS) -shared -o $@ $^

build/bpfd: $(BPFD_SRCS) build/libbpf_bpfd.so
	mkdir -p build
	$(CC) $(CFLAGS) -c -o build/utils.o src/utils.c
	$(CC) $(CFLAGS) -c -o build/base64.o src/base64.c
	$(CC) $(CFLAGS) -c -o build/bpfd.o src/bpfd.c
	$(CC) $(CFLAGS) build/base64.o build/utils.o build/bpfd.o -lbpf_bpfd -o $@

clean:
	rm -rf build
