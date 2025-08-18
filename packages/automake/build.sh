#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf automake-1.17.tar.xz
cd automake-1.17

export PERL="perl"

./configure --prefix="$OUTPUT_DIR"

make

make install

echo "Automake build complete"