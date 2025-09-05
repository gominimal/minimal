#!/bin/sh
set -e

tar xfo less-679.tar.gz
cd less-679

./configure --prefix=/usr --sysconfdir=/etc

make -j$(nproc)
make DESTDIR="$OUTPUT_DIR" install