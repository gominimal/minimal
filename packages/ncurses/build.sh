#!/bin/sh
set -e

tar xf ncurses-6.5-20250830.tgz
cd ncurses-6.5-20250830

./configure  --prefix=/usr            \
            --mandir=/usr/share/man \
            --with-shared           \
            --without-debug         \
            --without-normal        \
            --with-cxx-shared       \
            --enable-pc-files        \
            --with-pkg-config-libdir=/usr/lib/pkgconfig

make -j$(nproc)
make DESTDIR="$OUTPUT_DIR" install
