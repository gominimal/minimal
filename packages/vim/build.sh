#!/bin/sh
set -e

tar xfo vim-9.1.1629.tar.gz
cd vim-9.1.1629

./configure --prefix=/usr        \
            --with-features=huge \
            --enable-gui=no      \
            --without-x          \
            --with-tlib=ncursesw

make -j$(nproc)
make DESTDIR=$OUTPUT_DIR install
