#!/bin/sh
set -e

tar xfo libunistring-1.3.tar.xz
cd libunistring-1.3

./configure  --prefix=/usr           \
            --disable-static       \
            --docdir=/usr/share/doc/libunistring-1.3

make -j$(nproc)
make DESTDIR="$OUTPUT_DIR" install
