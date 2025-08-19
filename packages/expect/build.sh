#!/bin/sh
set -e

# Source shared toolchain setup
. ./toolchain-setup.sh

# Extract source
tar -xf expect5.45.4.tar.gz
cd expect5.45.4

# Configure with LFS settings
./configure --prefix=/usr \
            --with-tcl=/usr/lib \
            --enable-shared \
            --mandir=/usr/share/man \
            --with-tclinclude=/usr/include \
            --disable-rpath

# Build
make

# Install
make DESTDIR="$OUTPUT_DIR" install

# Create expected symlink for the library as per LFS instructions
cd "$OUTPUT_DIR/usr/lib"
ln -svf expect5.45.4/libexpect5.45.4.so .