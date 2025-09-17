#!/bin/sh
set -e

tar xfo nano-8.6.tar.xz
cd nano-8.6

./configure --prefix=/usr     \
            --sysconfdir=/etc \
            --enable-utf8     \
            --docdir=/usr/share/doc/nano-8.6
make -j$(nproc)

make DESTDIR="$OUTPUT_DIR" install
install -v -m644 doc/{nano.html,sample.nanorc} $OUTPUT_DIR/usr/share/doc/nano-8.6