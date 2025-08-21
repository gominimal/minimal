#!/bin/sh

set -e

tar xf gzip-1.14.tar.xz
cd gzip-1.14

./configure --prefix=/usr

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install

echo "Gzip build complete"
