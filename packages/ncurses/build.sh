#!/bin/sh
set -e

# Source shared toolchain setup
. ./toolchain-setup.sh

tar -xf ncurses-6.5.tar.gz
cd ncurses-6.5

./configure --prefix=/usr \
            --mandir=/usr/share/man \
            --with-shared \
            --without-debug \
            --without-normal \
            --with-cxx-shared \
            --enable-pc-files \
            --with-pkg-config-libdir=/usr/lib/pkgconfig \
            --disable-stripping

make
make DESTDIR="$OUTPUT_DIR" install
