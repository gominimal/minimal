#!/bin/sh
set -e

tar -xf attr-2.5.2.tar.gz --no-same-owner --no-same-permissions
cd attr-2.5.2

./configure --prefix=/usr \
            --disable-static \
            --sysconfdir=/etc \
            --docdir=/usr/share/doc/attr-2.5.2

make
make DESTDIR="$OUTPUT_DIR" install
