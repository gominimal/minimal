#!/bin/bash
set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar -xf bison-3.8.2.tar.xz
cd bison-3.8.2

# Configure Bison following LFS instructions
./configure --prefix="${OUTPUT_DIR}" \
            --docdir="${OUTPUT_DIR}/share/doc/bison-3.8.2"

make

# Skip tests for now to speed up initial packaging
echo "Skipping tests to save time during initial packaging"
# make check

make install