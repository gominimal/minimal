#!/bin/sh
set -ex

tar xfo libpsl-0.21.5.tar.gz
cd libpsl-0.21.5

mkdir build
cd    build

meson setup --prefix=/usr --buildtype=release

ninja
# TODO
# ninja test
DESTDIR=$OUTPUT_DIR ninja install
