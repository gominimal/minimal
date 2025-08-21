#!/bin/sh

set -e

tar xf readline-8.3.tar.gz
cd readline-8.3

sed -i '/MV.*old/d' Makefile.in
sed -i '/{OLDSUFF}/c:' support/shlib-install

sed -i 's/-Wl,-rpath,[^ ]*//' support/shobj-conf

./configure --prefix=/usr \
            --disable-static \
            --with-curses \
            --docdir="/usr/share/doc/readline-8.3"

make SHLIB_LIBS="-lncursesw"
make DESTDIR=$OUTPUT_DIR install

echo "Readline build complete"
