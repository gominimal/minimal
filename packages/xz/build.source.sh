#!/bin/sh

set -e

tar xf xz-5.8.1.tar
cd xz-5.8.1

./configure --prefix="$OUTPUT_DIR/usr" \
            --disable-static \
            --docdir="$OUTPUT_DIR/share/doc/xz-5.8.1"

make
make install

echo "Xz build complete"
