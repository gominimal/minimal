#!/bin/sh
set -e

tar xfo flex-2.6.4.tar.gz
cd flex-2.6.4

./configure  CFLAGS="-g -O0"  --prefix=/usr \
            --docdir=/usr/share/doc/flex-2.6.4 \
            --disable-static

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install
