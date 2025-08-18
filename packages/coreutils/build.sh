#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf coreutils-9.7.tar.xz
cd coreutils-9.7

patch -Np1 -i ../coreutils-9.7-upstream_fix-1.patch
patch -Np1 -i ../coreutils-9.7-i18n-1.patch

./configure \
    --prefix="$OUTPUT_DIR" \
    --enable-no-install-program=kill,uptime

make
make install

mkdir -p "$OUTPUT_DIR/lib/coreutils"
mv "$OUTPUT_DIR/libexec/coreutils/libstdbuf.so" "$OUTPUT_DIR/lib/coreutils/"

echo "Coreutils build complete"
