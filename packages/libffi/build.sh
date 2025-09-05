#!/bin/sh
set -e

tar xfo libffi-3.5.2.tar.gz
cd libffi-3.5.2

./configure  --prefix=/usr     \
            --disable-static \
            --with-gcc-arch=native

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
