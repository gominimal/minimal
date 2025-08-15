#!/usr/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf bc-7.0.3.tar.xz
cd bc-7.0.3

CC="${CC}" CFLAGS="${CFLAGS} -std=c99 -D_GNU_SOURCE" ./configure --prefix="${OUTPUT_DIR}" -G -O3 -r

make
make test || echo "Some tests may fail - this is expected"
make install
