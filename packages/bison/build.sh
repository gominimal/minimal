#!/bin/sh
set -e

tar -xf bison-3.8.2.tar.xz
cd bison-3.8.2

./configure --prefix="/usr" 

make -j$(nprocs)

make DESTDIR=$OUTPUT_DIR install
