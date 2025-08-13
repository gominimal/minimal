#!/bin/bash

set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar xf xz-5.8.1.tar.xz
cd xz-5.8.1

./configure --prefix="$OUTPUT_DIR" \
            --disable-static \
            --docdir="$OUTPUT_DIR/share/doc/xz-5.8.1"

make
make install

echo "Xz build complete"
