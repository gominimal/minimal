#!/bin/sh
set -e

tar -xf bc-7.0.3.tar.xz
cd bc-7.0.3

CC="gcc -std=c99" ./configure --prefix=/usr --disable-generated-tests --enable-readline

make

make DESTDIR=$OUTPUT_DIR install
