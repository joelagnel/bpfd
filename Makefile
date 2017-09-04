all: libbpf.o

BPF_SRC := lib/bpf/libbpf.c
INCLUDE := /home/joelaf/repo/linux-mainline/usr/include/

CFLAGS := -c -I$(INCLUDE)
CC := aarch64-linux-gnu-gcc

libbpf.o: $(BPF_SRC)
	$(CC) $(CFLAGS) -o $@ $^
