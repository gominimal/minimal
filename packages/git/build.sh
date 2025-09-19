#!/bin/sh
set -e

tar xfo "git-${MINIMAL_ARG_VERSION}.tar.xz"
cd "git-${MINIMAL_ARG_VERSION}"

./configure --prefix=/usr                   \
            --with-gitconfig=/etc/gitconfig \
            --with-python=python3           \
            --with-libpcre2

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install