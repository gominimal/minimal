#!/bin/sh
set -e

tar xfo attr-2.5.2.tar.gz
cd attr-2.5.2

./configure  --prefix=/usr      \
            --disable-static  \
            --sysconfdir=/etc \
            --docdir=/usr/share/doc/attr-2.5.2

make -j$(nproc)
# make check # TODO
make DESTDIR="$OUTPUT_DIR" install
