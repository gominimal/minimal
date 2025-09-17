#!/bin/sh
set -e

tar xfo elfutils-0.192.tar.bz2
cd elfutils-0.192

./configure --prefix=/usr                \
            --disable-debuginfod         \
            --enable-libdebuginfod=dummy

make -j$(nproc)

make DESTDIR="$OUTPUT_DIR" install