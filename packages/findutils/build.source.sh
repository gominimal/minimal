#!/bin/sh
set -e

tar -xf findutils-4.10.0.tar.xz
cd findutils-4.10.0

./configure --prefix=/usr --localstatedir=/var/lib/locate

make -j$(nproc)
# TODO "locate: 'failed to drop group privileges': Operation not permitted"
# make check
make DESTDIR=$OUTPUT_DIR install
