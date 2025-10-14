#!/bin/sh
set -e

cd bash-5.3

./configure --prefix=/usr \
            --without-bash-malloc \
            --docdir=/usr/share/doc/bash-5.3 \
            --with-installed-readline

make -j$(nproc)
# TODO make tests
make DESTDIR=$OUTPUT_DIR install

# Create sh symlink in /usr/bin
ln -sf bash $OUTPUT_DIR/usr/bin/sh
