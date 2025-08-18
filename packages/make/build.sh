#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf make-4.4.1.tar.gz
cd make-4.4.1

./configure --prefix="$OUTPUT_DIR"

make

make install

echo "Make build complete"