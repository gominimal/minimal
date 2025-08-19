#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf expect5.45.4.tar.gz
cd expect5.45.4

patch -Np1 -i ../expect-5.45.4-gcc15-1.patch

./configure --prefix="$OUTPUT_DIR/usr" \
            --with-tcl=/usr/lib \
            --enable-shared \
            --disable-rpath \
            --mandir=/usr/share/man \
            --with-tclinclude=/usr/include

make install
