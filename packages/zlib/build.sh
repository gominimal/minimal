#!/usr/bin/bash

set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar xf zlib-1.3.1.tar.gz
cd zlib-1.3.1

./configure --prefix="$OUTPUT_DIR"
make
make check
make install

rm -fv /usr/lib/libz.a
echo "Zlib installation complete"
