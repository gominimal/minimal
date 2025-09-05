#!/bin/sh
set -e

tar xfo libxcrypt-4.4.38.tar.xz
cd libxcrypt-4.4.38

./configure --prefix=/usr \
            --enable-hashes=strong,glibc \
            --enable-obsolete-api=no \
            --disable-static \
            --disable-failure-tokens

make -j$(nproc)
make check
make DESTDIR="$OUTPUT_DIR" install
