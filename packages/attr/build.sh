#!/bin/sh
set -e

./configure  --prefix=/usr      \
            --disable-static    \
            --sysconfdir=/etc   \
            --docdir=/usr/share/doc/attr-2.5.2

make -j$(nproc)
# make check # TODO
make DESTDIR="$OUTPUT_DIR" install
