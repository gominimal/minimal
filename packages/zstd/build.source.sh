#!/bin/sh
set -ex

tar xf zstd-1.5.6.tar.gz
cd zstd-1.5.6

# /usr/bin/cc does not exist in the build environment
export CC=gcc

make -j$(nproc) prefix=/usr
make check
make prefix=/usr DESTDIR=$OUTPUT_DIR install
