#!/usr/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf bison-3.8.2.tar.xz
cd bison-3.8.2

./configure --prefix="${OUTPUT_DIR}" \
            --docdir="${OUTPUT_DIR}/share/doc/bison-3.8.2"

make

echo "Skipping tests to save time during initial packaging"
# make check

make install
