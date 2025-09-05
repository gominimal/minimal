#!/bin/sh
set -e

tar xf autoconf-2.72.tar.xz
cd autoconf-2.72

./configure --prefix=/usr

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
