#!/bin/sh
set -ex

tar xfo gmp-6.3.0.tar.xz
cd gmp-6.3.0

sed -i '/long long t1;/,+1s/()/(...)/' configure

./configure  --prefix=/usr     \
            --enable-cxx     \
            --disable-static \
            --docdir=/usr/share/doc/gmp-6.3.0
            
make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
