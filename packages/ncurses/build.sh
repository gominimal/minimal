#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf ncurses-6.5.tar.gz
cd ncurses-6.5

# TODO fix C++ support
# TODO enable stripping
./configure --prefix=/usr \
            --mandir=/usr/share/man \
            --with-shared \
            --without-debug \
            --without-normal \
            --without-cxx \
            --without-cxx-binding \
            --enable-pc-files \
            --with-pkg-config-libdir=/usr/lib/pkgconfig \
            --disable-stripping

make
make DESTDIR="$OUTPUT_DIR" install
