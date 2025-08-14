#!/bin/bash
set -e

. ./toolchain-setup.sh

tar -xf m4-1.4.19.tar.xz
cd m4-1.4.19

CFLAGS="-O2 -std=gnu11" ./configure --prefix="${OUTPUT_DIR}"

make
# make check || echo "Some tests may fail - this is expected"
make install
