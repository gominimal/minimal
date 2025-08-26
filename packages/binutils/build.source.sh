#!/bin/sh
set -e

tar -xf binutils-2.45.tar.xz
cd binutils-2.45

mkdir -v build
cd build

../configure --prefix=/usr         \
             --sysconfdir=/etc   \
             --disable-nls \
             --enable-gprofng=no \
             --disable-werror    \
             --enable-new-dtags  \
             --enable-default-hash-style=gnu
             
# TODO 
# --with-system-zlib
# --enable-ld=default
# --enable-plugins
# --enable-shared
# --enable-64-bit-bfd

make -j$(nproc) tooldir=/usr

make -k check

make tooldir=/usr DESTDIR=$OUTPUT_DIR install
