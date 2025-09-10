#!/usr/bin/bash
set -ex

tar xf gcc-15.2.0.tar.xz
cd gcc-15.2.0

mkdir -v build
cd build

../libgcc/configure --prefix=/usr

make -j$(nproc)
DESTDIR=$OUTPUT_DIR make install
