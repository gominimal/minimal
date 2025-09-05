#!/bin/sh
set -e

tar xfo gettext-0.26.tar.xz
cd gettext-0.26

./configure  --prefix=/usr     \
            --disable-static \
            --docdir=/usr/share/doc/gettext-0.26

make -j$(nproc)
make check
make DESTDIR="$OUTPUT_DIR" install
chmod -v 0755 "$OUTPUT_DIR/usr/lib/preloadable_libintl.so"
