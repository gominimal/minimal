#!/bin/sh
set -ex

echo "hello"

tar -xf patch-2.8.tar.xz
cd patch-2.8

./configure --prefix=/usr

make
make check
make DESTDIR="$OUTPUT_DIR" install
