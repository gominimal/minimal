#!/bin/sh
set -e

cd binutils-2.45/

mkdir -v build || true
cd       build

export PATH="/home/bweeks/x-tools/x86_64-minimal-linux-gnu/bin:$PATH"
# LFS_TGT=x86_64-minimal-linux-gnu
    # --build=$(../config.guess) \
    # --host=$LFS_TGT            \
../configure                   \
    --prefix=/usr              \
    --disable-nls              \
    --disable-shared           \
    --enable-gprofng=no        \
    --disable-werror           \
    --enable-64-bit-bfd        \
    --enable-new-dtags         \
    --enable-default-hash-style=gnu \
    --enable-static-link

make -j8
make clean
make -j8 LDFLAGS=-all-static

make DESTDIR=/home/bweeks/minpkgs/packages/binutils/prebuilt/ install
