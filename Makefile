all: libbpf.o

BPFD_SRC := bpfd.c
LIBBPF_SRC := lib/bpf/libbpf.c
INCLUDE := /home/joelaf/repo/linux-mainline/usr/include/

CFLAGS := -c -I$(INCLUDE)
# CC := aarch64-linux-gnu-gcc-4.9

libbpf.o: $(LIBBPF_SRC)
	$(CC) $(CFLAGS) -o $@ $^

bpfd: $(BPFD_SRC)
	$(CC) $(CFLAGS) -o $@ $^

all: bpfd libbpf.o

clean:
	rm -f bpfd *.o
