#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf sed-4.9.tar.xz
cd sed-4.9

./configure --prefix="$OUTPUT_DIR"

make

make install

# Note: Skipping 'make html' as makeinfo (from Texinfo) is not available

echo "Sed build complete"