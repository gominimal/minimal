#!/bin/sh
set -e

tar xf libffi-3.5.2.tar.gz
cd libffi-3.5.2

./configure --prefix=/usr

make

make DESTDIR=$OUTPUT_DIR install
