#!/bin/sh
set -e

tar xfo libcap-2.76.tar.xz
cd libcap-2.76

sed -i '/install -m.*STA/d' libcap/Makefile

# TODO: Remove once /usr/bin/bash shows up in the bash build-spec output
sed -i 's#/bin/bash#/usr/bin/bash#g' progs/mkcapshdoc.sh

make prefix=/usr lib=lib

make prefix=/usr lib=lib DESTDIR="$OUTPUT_DIR" install
