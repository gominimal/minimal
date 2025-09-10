#!/bin/sh
set -ex

tar xf curl-8.15.0.tar.xz
cd curl-8.15.0

./configure  --prefix=/usr     \
            --disable-static \
            --with-openssl   \
            --with-ca-path=/etc/ssl/certs

make -j$(nproc)
DESTDIR=$OUTPUT_DIR make install
