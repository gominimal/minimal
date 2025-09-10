#!/bin/sh
set -e

tar xf lz4-1.10.0.tar.gz
cd lz4-1.10.0

export CC=gcc

make -j$(nproc) BUILD_STATIC=no PREFIX=/usr
make -j1 check
make BUILD_STATIC=no PREFIX=/usr DESTDIR=$OUTPUT_DIR install
