#!/bin/sh
set -ex

tar xfo zlib-1.3.1.tar.gz
cd zlib-1.3.1

./configure --prefix=/usr

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
