#!/bin/sh
set -e

tar xf coreutils-9.7.tar.xz
cd coreutils-9.7

FORCE_UNSAFE_CONFIGURE=1 ./configure \
    --prefix=/usr \
    --enable-no-install-program=kill,uptime

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
