#!/bin/bash

set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar xf zstd-1.5.6.tar.gz
cd zstd-1.5.6

make prefix="$OUTPUT_DIR"
make install prefix="$OUTPUT_DIR"

echo "Zstd build complete"
