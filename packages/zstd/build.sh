#!/bin/bash

set -e

. ./toolchain-setup.sh

tar xf zstd-1.5.6.tar.gz
cd zstd-1.5.6

make install prefix="$OUTPUT_DIR"

echo "Zstd build complete"
