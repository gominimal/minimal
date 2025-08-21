#!/bin/sh

set -e

tar xf file-5.46.tar.gz
cd file-5.46

./configure --prefix=/usr

make
make DESTDIR=$OUTPUT_DIR install

echo "File build complete"
