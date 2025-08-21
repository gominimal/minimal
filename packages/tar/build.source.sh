#!/bin/sh

set -e

tar xf tar-1.35.tar.xz
cd tar-1.35

./configure --prefix="/usr"

make
make DESTDIR=$OUTPUT_DIR install

echo "Tar build complete"
