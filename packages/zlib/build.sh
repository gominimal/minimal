#!/bin/sh

set -ex

. "${SCRIPTS_DIR}/toolchain-setup.sh"

export CFLAGS="-O2"
export CXXFLAGS="-O2"

echo "PATH: $PATH"
echo "Checking for compiler:"
which x86_64-buildroot-linux-gnu-gcc || echo "Compiler not found in PATH"
ls -la /home/bweeks/minpkgs/toolchains/x86_64-buildroot-linux-gnu/bin/ | head -5

tar xf zlib-1.3.1.tar.gz
cd zlib-1.3.1

./configure --prefix="$OUTPUT_DIR"
make
make check
make install

rm -fv /usr/lib/libz.a
echo "Zlib installation complete"
