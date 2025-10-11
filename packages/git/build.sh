#!/bin/sh
set -e

./configure --prefix=/usr                   \
            --with-gitconfig=/etc/gitconfig \
            --with-python=python3           \
            --with-libpcre2

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
