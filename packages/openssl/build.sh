#!/bin/sh
set -e

tar xfo openssl-3.5.2.tar.gz
cd openssl-3.5.2

./config  --prefix=/usr          \
         --openssldir=/etc/ssl \
         --libdir=lib          \
         shared                \
         zlib-dynamic

make -j$(nproc)
# HARNESS_JOBS=$(nproc) make test
sed -i '/INSTALL_LIBS/s/libcrypto.a libssl.a//' Makefile
make DESTDIR="$OUTPUT_DIR" MANSUFFIX=ssl install
