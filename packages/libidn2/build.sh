#!/bin/sh
set -e

tar xfo libidn2-2.3.8.tar.gz
cd libidn2-2.3.8

./configure --prefix=/usr --disable-static

make -j$(nproc)
make DESTDIR="$OUTPUT_DIR" install
