#!/bin/sh
set -e

tar xfo bash-5.3.tar.gz
cd bash-5.3

./configure --prefix=/usr \
            --without-bash-malloc \
            --docdir=/usr/share/doc/bash-5.3 \
            --with-installed-readline

make -j$(nproc)
# TODO make tests
make DESTDIR=$OUTPUT_DIR install

mkdir -p $OUTPUT_DIR/bin
ln -sf $OUTPUT_DIR/usr/bin/bash $OUTPUT_DIR/bin/bash
ln -sf $OUTPUT_DIR/usr/bin/bash $OUTPUT_DIR/bin/sh
ln -sf $OUTPUT_DIR/usr/bin/bash $OUTPUT_DIR/usr/bin/sh
