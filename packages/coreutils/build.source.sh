#!/bin/sh

set -e

tar xf coreutils-9.7.tar.xz
cd coreutils-9.7

./configure \
    --prefix=/usr \
    --enable-no-install-program=kill,uptime

make

make DESTDIR=$OUTPUT_DIR install

echo "Coreutils build complete"
