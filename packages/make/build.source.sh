#!/bin/sh

set -e

tar xf make-4.4.1.tar.gz
cd make-4.4.1

./configure --prefix=/usr

make

make DESTDIR=$OUTPUT_DIR install

echo "Make build complete"
