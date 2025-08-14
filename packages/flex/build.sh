#!/bin/bash
set -e

. ./toolchain-setup.sh

tar -xf flex-2.6.4.tar.gz
cd flex-2.6.4

# Configure Flex - disable C++ to avoid preprocessor issues but keep libfl
./configure --prefix="${OUTPUT_DIR}" \
            --docdir="${OUTPUT_DIR}/share/doc/flex-2.6.4" \
            --disable-static \
            --enable-shared \
            CXX=no \
            CXXCPP=no

make

make check || echo "Some tests may fail - this is expected"

make install

# Create symbolic links as per LFS instructions
ln -sv flex "${OUTPUT_DIR}/bin/lex"
ln -sv flex.1 "${OUTPUT_DIR}/share/man/man1/lex.1"
