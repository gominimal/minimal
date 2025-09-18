#!/bin/sh
set -ex

tar xf linux-6.12.43.tar.xz
cd linux-6.12.43

make headers
cp -rv usr/include $OUTPUT_DIR/usr
