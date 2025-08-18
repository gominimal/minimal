#!/bin/sh

set -e

. ./toolchain-setup.sh

# Extract source
tar xf gzip-1.14.tar.xz
cd gzip-1.14

# Configure gzip following LFS instructions
./configure --prefix="$OUTPUT_DIR"

# Build
make -j$(nproc)

# Install
make install

echo "Gzip build complete"