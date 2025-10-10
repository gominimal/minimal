#!/bin/sh
set -e

tar xfo strace-6.17.tar.xz
cd strace-6.17

./configure --prefix=/usr
make -j$(nproc)

make DESTDIR="$OUTPUT_DIR" install
