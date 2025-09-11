#!/bin/sh
set -e

tar xf diffutils-3.12.tar.xz
cd diffutils-3.12

./configure --prefix=/usr

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
