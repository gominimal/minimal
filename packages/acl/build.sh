#!/bin/sh
set -e

tar xfo acl-2.3.2.tar.xz
cd acl-2.3.2

./configure --prefix=/usr \
            --disable-static \
            --docdir=/usr/share/doc/acl-2.3.2

make -j$(nproc)

make DESTDIR="$OUTPUT_DIR" install
