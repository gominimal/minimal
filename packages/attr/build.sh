#!/bin/sh
set -e

cd attr-2.5.2

./configure  --prefix=/usr      \
            --disable-static  \
            --sysconfdir=/etc \
            --docdir=/usr/share/doc/attr-2.5.2

make -j$(nproc)
# make check # TODO
make DESTDIR="$OUTPUT_DIR" install
