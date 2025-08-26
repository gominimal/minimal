#!/bin/sh
set -e

tar xfo tar-1.35.tar.xz
cd tar-1.35

FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install

echo "Tar build complete"
