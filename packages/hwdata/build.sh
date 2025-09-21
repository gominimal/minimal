#!/bin/sh
set -e

tar xfo hwdata-0.399.tar.gz
cd hwdata-0.399

./configure --prefix=/usr --disable-blacklist

make DESTDIR=$OUTPUT_DIR        \
     install

