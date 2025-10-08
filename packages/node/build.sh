#!/bin/sh
set -e

export CC=gcc

tar xfo "node-v${MINIMAL_ARG_VERSION}.tar.xz"
cd "node-v${MINIMAL_ARG_VERSION}"

./configure --prefix=/usr --with-intl=system-icu --shared-openssl --shared-zlib --shared-sqlite --shared-libuv

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
