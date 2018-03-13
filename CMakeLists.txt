# Copyright (c) Jazel Canseco, 2018
# Licensed under the Apache License, Version 2.0 (the "License")
cmake_minimum_required(VERSION 2.8.7)

project(bpfd)

set(CMAKE_C_FLAGS "-static")
set(CMAKE_CXX_FLAGS "-static")

include_directories(src)
include_directories(bcc-deps)
include_directories(bcc-deps/compat)

add_library(bpfd-bpf bcc-deps/libbpf.c bcc-deps/perf_reader.c)

add_executable(bpfd src/bpfd.c src/base64.c src/remote_perf_reader.c src/utils.c)
target_link_libraries(bpfd bpfd-bpf)
