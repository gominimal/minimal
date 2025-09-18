#!/bin/sh
set -e

tar xfo inetutils-2.6.tar.xz
cd inetutils-2.6

./configure --prefix=/usr        \
            --bindir=/usr/bin    \
            --localstatedir=/var \
            --disable-logger     \
            --disable-whois      \
            --disable-rcp        \
            --disable-rexec      \
            --disable-rlogin     \
            --disable-rsh        \
            --disable-servers

make -j$(nproc)
make check
make DESTDIR=$OUTPUT_DIR install
