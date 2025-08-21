#!/bin/sh
set -ex

tar xf mpc-1.3.1.tar.gz
cd mpc-1.3.1

./configure --prefix=/usr     \
            --disable-static  \
            --docdir=/usr/share/doc/mpc-1.3.1

make -j8

make DESTDIR=$OUTPUT_DIR install