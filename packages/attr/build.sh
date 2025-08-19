#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf attr-2.5.2.tar.gz
cd attr-2.5.2

./configure --prefix=/usr \
            --disable-static \
            --sysconfdir=/etc \
            --docdir=/usr/share/doc/attr-2.5.2

make
make DESTDIR="$OUTPUT_DIR" install
