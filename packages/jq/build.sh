#!/bin/sh
set -e

tar xfo "jq-${MINIMAL_ARG_VERSION}.tar.gz"
cd "jq-${MINIMAL_ARG_VERSION}"

./configure --prefix=/usr                   \
            --with-oniguruma=builtin

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
