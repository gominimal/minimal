#!/bin/sh
set -ex

tar xf zstd-1.5.6.tar.gz
cd zstd-1.5.6

make -j$(nproc) CC=gcc prefix=/usr

make prefix=/usr DESTDIR=$OUTPUT_DIR install

echo "Zstd build complete"
