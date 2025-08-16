#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf grep-3.12.tar.xz
cd grep-3.12

sed -i "s/echo/#echo/" src/egrep.sh

./configure --prefix="$OUTPUT_DIR"

make

# Optional: Run tests (uncomment if needed)
# make check

make install

echo "Grep installation complete"
