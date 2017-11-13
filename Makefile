all: libbpf.o

BPFD_SRC := bpfd.c
LIBBPF_SRC := lib/bpf/libbpf.c
INCLUDE := /home/joelaf/repo/linux-mainline/usr/include/

CFLAGS := -I$(INCLUDE) -L./
# CC := aarch64-linux-gnu-gcc-4.9

libbpf.o: $(LIBBPF_SRC)
	$(CC) $(CFLAGS) -fPIC -c -o $@ $^

libbpf_bpfd.so: libbpf.o
	$(CC) $(CFLAGS) -shared -o $@ $^

bpfd: $(BPFD_SRC) base64.c libbpf_bpfd.so
	$(CC) $(CFLAGS) -c -o base64.o base64.c
	$(CC) $(CFLAGS) -lbpf_bpfd base64.o -o $@ $(BPFD_SRC)

all: bpfd

clean:
	rm -f bpfd *.o *.so
