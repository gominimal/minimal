#!/bin/sh
set -e

tar xf flex-2.6.4.tar.gz
cd flex-2.6.4

./configure  CFLAGS="-g -O0"  --prefix=/usr \
            --docdir=/usr/share/doc/flex-2.6.4 \
            --disable-static

make

make DESTDIR=$OUTPUT_DIR install
