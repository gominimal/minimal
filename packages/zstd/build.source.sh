#!/bin/sh

set -ex

tar xf zstd-1.5.6.tar.gz
cd zstd-1.5.6

make CC=gcc prefix=/usr

make CC=gcc prefix=/usr DESTDIR=$OUTPUT_DIR install

echo "Zstd build complete"