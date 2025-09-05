#!/bin/sh
set -e

tar xfo bc-7.0.3.tar.xz
cd bc-7.0.3

CC="gcc -std=c99" ./configure --prefix=/usr --disable-generated-tests --enable-readline

make -j$(nproc)
make test
make DESTDIR=$OUTPUT_DIR install
