#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf tar-1.35.tar.xz
cd tar-1.35

./configure --prefix="$OUTPUT_DIR/usr"

make
make install

echo "Tar build complete"
