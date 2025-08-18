#!/bin/sh

set -e

. ./toolchain-setup.sh

# Extract source
tar xf gawk-5.3.2.tar.xz
cd gawk-5.3.2

# Remove extras from Makefile as per LFS instructions
sed -i 's/extras//' Makefile.in

# Configure gawk following LFS instructions
./configure --prefix="$OUTPUT_DIR"

# Build
make -j$(nproc)

# Install
rm -f "$OUTPUT_DIR/bin/gawk-5.3.2"
make install

# Create awk symlink as per LFS
ln -sv gawk.1 "$OUTPUT_DIR/share/man/man1/awk.1"

echo "Gawk build complete"