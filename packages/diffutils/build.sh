#!/bin/sh

set -e

. ./toolchain-setup.sh

# Extract source
tar xf diffutils-3.12.tar.xz
cd diffutils-3.12

# Configure diffutils following LFS instructions
./configure --prefix="$OUTPUT_DIR"

# Build
make -j$(nproc)

# Install
make install

echo "Diffutils build complete"