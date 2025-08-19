#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf coreutils-9.7.tar.xz
cd coreutils-9.7

./configure \
    --prefix="$OUTPUT_DIR/usr" \
    --enable-no-install-program=kill,uptime

make
make install

# TODO: FHS compliance

echo "Coreutils build complete"
