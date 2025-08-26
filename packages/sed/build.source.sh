#!/bin/sh

set -e

tar xf sed-4.9.tar.xz
cd sed-4.9

./configure --prefix="/usr"

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install

echo "Sed build complete"
