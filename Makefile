all: libbpf.o

BPFD_SRC        := bpfd.c
LIBBPF_SRC      := lib/bpf/libbpf.c
PERF_READER_SRC := lib/bpf/perf_reader.c
INCLUDE := -I/home/joelaf/repo/linux-mainline/usr/include/ -I./lib/bpf/compat/

CFLAGS := $(INCLUDE) -L./
# CC := aarch64-linux-gnu-gcc-4.9

libbpf.o: $(LIBBPF_SRC)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

perf_reader.o: $(PERF_READER_SRC)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

libbpf_bpfd.so: libbpf.o perf_reader.o
	$(CC) $(CFLAGS) -shared -o $@ $^

bpfd: $(BPFD_SRC) base64.c libbpf_bpfd.so
	$(CC) $(CFLAGS) -c -o base64.o base64.c
	$(CC) $(CFLAGS) -c -o bpfd.o $(BPFD_SRC)
	$(CC) $(CFLAGS) base64.o bpfd.o -o $@ -lbpf_bpfd

all: bpfd

clean:
	rm -f bpfd *.o *.so
