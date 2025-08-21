#!/bin/sh
set -e

tar -xf texinfo-7.2.tar.xz
cd texinfo-7.2

sed 's/! $output_file eq/$output_file ne/' -i tp/Texinfo/Convert/*.pm

./configure --prefix=/usr

make

make DESTDIR="$OUTPUT_DIR" install
