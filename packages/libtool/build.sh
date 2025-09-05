#!/bin/sh
set -e

tar xfo libtool-2.5.4.tar.xz
cd libtool-2.5.4

./configure --prefix=/usr

make -j$(nproc)
make check
make DESTDIR="$OUTPUT_DIR" install
