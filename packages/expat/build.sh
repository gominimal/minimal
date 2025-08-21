#!/bin/sh

set -e

tar xf expat-2.7.1.tar.xz
cd expat-2.7.1

./configure --prefix="/usr" \
            --disable-static \
            --docdir="/usr/share/doc/expat-2.7.1"

make

make DESTDIR=$OUTPUT_DIR install

echo "Expat build complete"
