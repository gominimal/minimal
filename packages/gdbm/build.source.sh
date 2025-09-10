#!/bin/sh
set -e

tar xfo gdbm-1.26.tar.gz
cd gdbm-1.26

./configure --prefix=/usr \
            --disable-static \
            --enable-libgdbm-compat

make -j$(nproc)
make check
make DESTDIR="$OUTPUT_DIR" install