#!/bin/sh
set -ex

tar xfo mpfr-4.2.2.tar.xz
cd mpfr-4.2.2

./configure  --prefix=/usr         \
            --disable-static     \
            --enable-thread-safe \
            --docdir=/usr/share/doc/mpfr-4.2.2

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
