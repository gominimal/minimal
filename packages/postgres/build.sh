#!/bin/sh
set -e

tar xfo "postgresql-${MINIMAL_ARG_VERSION}.tar.gz"
cd "postgresql-${MINIMAL_ARG_VERSION}"

./configure --prefix=/usr                       \
            --with-openssl                      \
            --with-zstd

# TODO: --with-lz4 once we package lz4

make -j$(nproc)
# make check # Needs user lookup to function
make DESTDIR=$OUTPUT_DIR install
