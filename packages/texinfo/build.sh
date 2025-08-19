#!/bin/sh
set -e

# Source shared toolchain setup
. ./toolchain-setup.sh

# Extract source
tar -xf texinfo-7.2.tar.xz
cd texinfo-7.2

# Fix Perl warning as per LFS instructions
sed 's/! $output_file eq/$output_file ne/' -i tp/Texinfo/Convert/*.pm

# Configure with LFS settings
./configure --prefix=/usr

# Build
make

# Install to output directory
make DESTDIR="$OUTPUT_DIR" install