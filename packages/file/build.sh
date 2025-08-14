#!/bin/bash

set -e

. ./toolchain-setup.sh

tar xf file-5.46.tar.gz
cd file-5.46

./configure --prefix="$OUTPUT_DIR"

make
make install

echo "File build complete"
