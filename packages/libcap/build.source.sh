#!/bin/sh
set -e

tar xfo libcap-2.76.tar.xz
cd libcap-2.76

sed -i '/install -m.*STA/d' libcap/Makefile

make prefix=/usr lib=lib

make prefix=/usr lib=lib DESTDIR="$OUTPUT_DIR" install
