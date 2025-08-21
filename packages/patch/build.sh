#!/bin/sh
set -e

tar -xf patch-2.8.tar.xz
cd patch-2.8

./configure --prefix=/usr

make
make DESTDIR="$OUTPUT_DIR" install
