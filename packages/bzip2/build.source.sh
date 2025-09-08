#!/bin/sh
set -e

tar xfo bzip2-1.0.8.tar.gz
cd bzip2-1.0.8

sed -i 's@\(ln -s -f \)$(PREFIX)/bin/@\1@' Makefile
sed -i "s@(PREFIX)/man@(PREFIX)/share/man@g" Makefile

make -f Makefile-libbz2_so
make clean

make -j$(nproc)
make PREFIX="$OUTPUT_DIR/usr" install

cp -av libbz2.so.* "$OUTPUT_DIR/usr/lib/"
ln -sv libbz2.so.1.0.8 "$OUTPUT_DIR/usr/lib/libbz2.so"

cp -v bzip2-shared "$OUTPUT_DIR/usr/bin/bzip2"
for i in "$OUTPUT_DIR/usr/bin/"{bzcat,bunzip2}; do
  ln -sfv bzip2 $i
done
