#!/bin/sh
set -e

tar xfo gawk-5.3.2.tar.xz
cd gawk-5.3.2

sed -i 's/extras//' Makefile.in

./configure --prefix=/usr

make -j$(nproc)
# TODO
# make check
make DESTDIR=$OUTPUT_DIR install
