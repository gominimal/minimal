#!/bin/sh
set -e

ls -lah
cd "jq-${MINIMAL_ARG_VERSION}"

./configure --prefix=/usr                   \
            --with-oniguruma=builtin

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
