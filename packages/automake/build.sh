#!/bin/sh
set -e

tar xf automake-1.17.tar.xz
cd automake-1.17

./configure --prefix=/usr

make

make DESTDIR=$OUTPUT_DIR install
