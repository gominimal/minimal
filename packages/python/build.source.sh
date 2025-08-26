#!/bin/sh

set -e

tar xf Python-3.13.7.tar.xz
cd Python-3.13.7

./configure  \
            --prefix=/usr          \
            --without-ensurepip \
            --disable-ipv6

            # --enable-shared \
            # --without-static-libpython \

echo -e "*disabled*\n_curses\n_curses_panel" >> Modules/Setup.local

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install
