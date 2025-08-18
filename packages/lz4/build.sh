#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf lz4-1.10.0.tar.gz
cd lz4-1.10.0

make BUILD_STATIC=no PREFIX="$OUTPUT_DIR" install

echo "LZ4 build complete"