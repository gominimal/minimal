#!/bin/sh
set -e

tar -xf ncurses-6.5.tar.gz
cd ncurses-6.5

# TODO fix C++ support
# TODO enable stripping
./configure --prefix=/usr \
            --mandir=/usr/share/man \
            --with-shared \
            --without-debug \
            --without-normal \
            --with-cxx-shared \
            --without-cxx-binding \
            --enable-pc-files \
            --with-pkg-config-libdir=/usr/lib/pkgconfig \
            --disable-stripping

make -j8
make DESTDIR="$OUTPUT_DIR" install
