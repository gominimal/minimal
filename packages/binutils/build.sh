#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf binutils-2.45.tar.xz
cd binutils-2.45

mkdir -v build
cd build

../configure --prefix="$OUTPUT_DIR/usr"         \
             --sysconfdir=/etc   \
             --enable-ld=default \
             --enable-plugins    \
             --enable-shared     \
             --disable-werror    \
             --enable-64-bit-bfd \
             --enable-new-dtags  \
             --with-system-zlib  \
             --enable-default-hash-style=gnu

make tooldir="$OUTPUT_DIR/usr"
make tooldir=/usr install
