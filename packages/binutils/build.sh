#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf binutils-2.45.tar.xz
cd binutils-2.45

mkdir -v build
cd build

# Configure with LFS settings  
# Disable gprofng since it requires C++ and causes build issues
../configure --prefix=/usr \
             --sysconfdir=/etc \
             --enable-ld=default \
             --enable-plugins \
             --enable-shared \
             --disable-werror \
             --enable-64-bit-bfd \
             --enable-new-dtags \
             --with-system-zlib \
             --enable-default-hash-style=gnu \
             --disable-gprofng

make tooldir=/usr
make tooldir=/usr install

rm -fv "$OUTPUT_DIR/usr/lib/lib"{bfd,ctf,ctf-nobfd,opcodes,sframe}.a
