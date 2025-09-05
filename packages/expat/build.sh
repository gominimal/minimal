#!/bin/sh
set -e

tar xfo expat-2.7.1.tar.xz
cd expat-2.7.1

./configure --prefix="/usr" \
            --disable-static \
            --docdir="/usr/share/doc/expat-2.7.1"

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
