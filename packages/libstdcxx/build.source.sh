#!/usr/bin/bash
set -ex

tar xf gcc-15.2.0.tar.xz
cd gcc-15.2.0

mkdir -v build
cd build

../libstdc++-v3/configure --prefix=/usr --disable-multilib --enable-libstdcxx-threads

make -j$(nproc)
DESTDIR=$OUTPUT_DIR make install
