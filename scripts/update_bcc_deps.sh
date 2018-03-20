#!/bin/bash

# BPFd (Berkeley Packet Filter daemon)
#
# Copyright (C) 2018 Jazel Canseco <jcanseco@google.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script pulls the most up-to-date version of the BCC source files
# that BPFd depends on from the BCC fork at https://github.com/jcanseco/bcc
# and from the branch 'upstream_submit'.

# Usage: update_bcc_deps.sh

SCRIPT_DIR=$(cd $(dirname ${BASH_SOURCE[0]}) && pwd) # Gets the script's source dir no matter where the script is called from
BPFD_DIR=$(cd $SCRIPT_DIR && git rev-parse --show-toplevel) # Gets the BPFd root directory no matter where the script is placed within the BPFd tree
BCC_DEPS_DIR="${BPFD_DIR}/bcc-deps"

BCC_REPO_URL="https://github.com/jcanseco/bcc"
BRANCH="upstream_submit"
BCC_SRC_DIR="src/cc"

FILES=(
  compat/linux/bpf_common.h
  compat/linux/bpf.h
  compat/linux/virtual_bpf.h
  vendor/tinyformat.hpp
  bcc_elf.c
  bcc_elf.h
  bcc_perf_map.c
  bcc_perf_map.h
  bcc_proc.c
  bcc_proc.h
  bcc_syms.cc
  bcc_syms.h
  common.cc
  common.h
  file_desc.h
  libbpf.c
  libbpf.h
  ns_guard.cc
  ns_guard.h
  perf_reader.c
  perf_reader.h
  setns.h
  syms.h
)

failed_files=()

git clone $BCC_REPO_URL bcc_temp
cd bcc_temp
git checkout -b $BRANCH origin/$BRANCH
printf "\n"

for file in ${FILES[@]}; do
  cp -v $BCC_SRC_DIR/$file $BCC_DEPS_DIR/$file
  if [[ $? -ne 0 ]]; then
    failed_files+=($file)
  fi
done

cd ..
rm -rf bcc_temp

if [[ ${#failed_files[@]} -gt 0 ]]; then
  printf "\n[ERROR] Failed to copy the following files from the BCC repository:\n\n"
  for file in ${failed_files[@]}; do
    printf "\t$file\n"
  done
  exit 1
fi

printf "\n$(basename $0): Success.\n"
