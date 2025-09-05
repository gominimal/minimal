#!/bin/sh
set -e

tar xfo dejagnu-1.6.3.tar.gz
cd dejagnu-1.6.3

mkdir -v build
cd       build

../configure --prefix=/usr
make check
make DESTDIR=$OUTPUT_DIR install
