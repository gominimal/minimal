#!/bin/sh

set -e

tar xf pkgconf-2.5.1.tar.xz
cd pkgconf-2.5.1

./configure --prefix=/usr \
            --disable-static \
            --docdir="/usr/share/doc/pkgconf-2.5.1"

make
make DESTDIR=$OUTPUT_DIR install

echo "Pkgconf build complete"
