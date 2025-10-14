#!/bin/sh
set -e

cd binutils-2.45

mkdir -v build
cd build

# TODO
# --enable-nls

../configure  --prefix=/usr        \
             --sysconfdir=/etc   \
             --enable-ld=default \
             --enable-plugins    \
             --enable-shared     \
             --disable-werror    \
             --disable-nls       \
             --enable-new-dtags  \
             --with-system-zlib  \
             --enable-default-hash-style=gnu

make -j$(nproc) tooldir=/usr
# make -k check # TODO
make tooldir=/usr DESTDIR=$OUTPUT_DIR install
