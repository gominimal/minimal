#!/bin/sh

set -e

. ./toolchain-setup.sh

# Extract source
tar xf tar-1.35.tar.xz
cd tar-1.35

# Configure tar following LFS instructions
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="$OUTPUT_DIR"

# Build
make -j$(nproc)

# Install
make install
# Skip HTML docs if makeinfo is not available
make -C doc install-html docdir="$OUTPUT_DIR/share/doc/tar-1.35" || true

echo "Tar build complete"