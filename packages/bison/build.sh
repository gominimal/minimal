#!/bin/sh
set -e

tar -xf bison-3.8.2.tar.xz
cd bison-3.8.2

./configure --prefix=/usr --docdir=/usr/share/doc/bison-3.8.2

make -j$(nproc)
# make check # TODO
make DESTDIR=$OUTPUT_DIR install
