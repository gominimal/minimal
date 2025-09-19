#!/bin/sh
set -e

tar xfo icu4c-77_1-src.tgz
cd icu/source

./configure --prefix=/usr

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install