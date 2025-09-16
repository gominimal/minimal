#!/bin/sh
set -e

tar xfo file-5.46.tar.gz
cd file-5.46

./configure --prefix=/usr

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
