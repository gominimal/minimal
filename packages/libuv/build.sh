#!/bin/sh
set -e

tar xfo "libuv-${MINIMAL_ARG_VERSION}.tar.gz"
cd "libuv-${MINIMAL_ARG_VERSION}"

./autogen.sh
./configure --prefix=/usr --disable-static

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
