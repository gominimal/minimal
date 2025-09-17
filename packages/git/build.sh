#!/bin/sh
set -e

tar xfo git-2.51.0.tar.xz
cd git-2.51.0

./configure --prefix=/usr                   \
            --with-gitconfig=/etc/gitconfig \
            --with-python=python3           \
            --with-libpcre2

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install