#!/bin/sh
set -ex

tar xfo mpc-1.3.1.tar.gz
cd mpc-1.3.1

./configure  --prefix=/usr      \
            --disable-static  \
            --docdir=/usr/share/doc/mpc-1.3.1

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
