#!/bin/bash

export LD_LIBRARY_PATH=`pwd`
rm /sys/fs/bpf/map* >/dev/null 2&>1
rm /sys/fs/bpf/prog* >/dev/null 2&>1

./tis
