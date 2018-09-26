#!/bin/bash

# This is run from Android root

prebuilts/clang/host/linux-x86/clang-r328903/bin/clang --target=bpf -c -nostdlibinc -O2 -isystem bionic/libc/include -isystem bionic/libc/kernel/uapi -isystem bionic/libc/kernel/uapi/asm-arm64 -isystem bionic/libc/kernel/android/uapi -I system/netd/bpfloader -I system/netd/libbpf/include -Wall -Werror -MD -MF \
	out/soong/.intermediates/system/netd/bpfloader/bpf_kern.o/android_common/obj/system/netd/bpfloader/bpf_kern.o.d \
	-o out/soong/.intermediates/system/netd/bpfloader/bpf_kern.o/android_common/obj/system/netd/bpfloader/bpf_kern.o \
	system/netd/bpfloader/tracetimeinstate.c
