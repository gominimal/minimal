#!/bin/sh
set -e

tar xfo automake-1.17.tar.xz
cd automake-1.17

./configure --prefix=/usr

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install
