#!/bin/sh

set -e

tar xf lz4-1.10.0.tar.gz
cd lz4-1.10.0

make CC=gcc BUILD_STATIC=no PREFIX=/usr

make BUILD_STATIC=no PREFIX=/usr DESTDIR=$OUTPUT_DIR install

echo "LZ4 build complete"
