#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf diffutils-3.12.tar.xz
cd diffutils-3.12

./configure --prefix="$OUTPUT_DIR/usr"

make
make install

echo "Diffutils build complete"
