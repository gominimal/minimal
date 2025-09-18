#!/bin/sh
set -e

tar xfo procps-ng-4.0.5.tar.xz
cd procps-ng-4.0.5

./configure --prefix=/usr                           \
            --docdir=/usr/share/doc/procps-ng-4.0.5 \
            --disable-static                        \
            --disable-kill                          \
            --enable-watch8bit

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
