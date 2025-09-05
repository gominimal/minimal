#!/bin/sh
set -e

tar xf m4-1.4.20.tar.xz
cd m4-1.4.20

./configure --prefix="/usr"
make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
