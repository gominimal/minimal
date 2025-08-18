#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf autoconf-2.72.tar.xz
cd autoconf-2.72

export PERL="perl"

./configure --prefix="$OUTPUT_DIR"

make

make install

echo "Autoconf build complete"