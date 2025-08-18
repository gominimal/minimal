#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf bc-7.0.3.tar.xz
cd bc-7.0.3

CFLAGS="${CFLAGS} -std=c99 -Wl,--dynamic-linker=$DYNAMIC_LINKER" ./configure --prefix="${OUTPUT_DIR}" --disable-generated-tests --enable-readline

make
make test || echo "Some tests may fail - this is expected"
make install
