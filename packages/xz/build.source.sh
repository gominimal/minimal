#!/bin/sh
set -e

tar xf xz-5.8.1.tar.xz
cd xz-5.8.1

./configure --prefix=/usr     \
           --disable-static \
           --docdir=/usr/share/doc/xz-5.8.1

make -j$(nproc)
make check
make DESTDIR="$OUTPUT_DIR" install
