#!/bin/sh
set -e

tar xf bash-5.3.tar.gz
cd bash-5.3

./configure --prefix=/usr \
            --without-bash-malloc \
            --docdir=/usr/share/doc/bash-5.3 \
            --disable-readline

# TODO
# --with-installed-readline 

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install

# Create bin/sh symlink
mkdir -p $OUTPUT_DIR/bin
ln -sf ../usr/bin/bash $OUTPUT_DIR/bin/sh
ln -sf ../usr/bin/bash $OUTPUT_DIR/usr/bin/sh
