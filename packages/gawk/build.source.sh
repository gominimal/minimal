#!/bin/sh
set -e

tar xfo gawk-5.3.2.tar.xz
cd gawk-5.3.2

sed -i 's/extras//' Makefile.in

./configure --prefix=/usr

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install

echo "Gawk build complete"
