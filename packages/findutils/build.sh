#!/bin/sh
set -e

tar -xf findutils-4.10.0.tar.xz
cd findutils-4.10.0

./configure --prefix=/usr --localstatedir=/var/lib/locate

make

make DESTDIR=$OUTPUT_DIR install
