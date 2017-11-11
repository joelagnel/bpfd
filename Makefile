all: libbpf.o

BPF_SRC := lib/bpf/libbpf.c
INCLUDE := /home/joelaf/repo/linux-mainline/usr/include/

CFLAGS := -c -I$(INCLUDE)
# CC := aarch64-linux-gnu-gcc-4.9

libbpf.o: $(BPF_SRC)
	$(CC) $(CFLAGS) -o $@ $^
