#!/bin/sh
set -e

tar xfo cmake-4.1.1.tar.gz
cd cmake-4.1.1

mkdir -v build
cd build


../bootstrap --prefix=/usr

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
