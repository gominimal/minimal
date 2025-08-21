#!/bin/sh

set -e

tar xf grep-3.12.tar.xz
cd grep-3.12

sed -i "s/echo/#echo/" src/egrep.sh

./configure --prefix="/usr"

make

make DESTDIR=$OUTPUT_DIR install

echo "Grep installation complete"
