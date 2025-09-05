#!/bin/sh
set -e

tar xf grep-3.12.tar.xz
cd grep-3.12

sed -i "s/echo/#echo/" src/egrep.sh



./configure --prefix="/usr"

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
