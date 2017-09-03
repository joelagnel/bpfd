all: bpf.o

BPF_SRC := lib/bpf/bpf.c
INCLUDE := /home/joelaf/repo/linux-mainline/usr/include/

CFLAGS := -c -I$(INCLUDE)
CC := aarch64-linux-gnu-g++

bpf.o: $(BPF_SRC)
	$(CC) $(CFLAGS) -o $@ $^
