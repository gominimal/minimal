#!/bin/sh

set -e

tar xf bzip2-1.0.8.tar.gz
cd bzip2-1.0.8

sed -i 's@\(ln -s -f \)$(PREFIX)/bin/@\1@' Makefile
sed -i "s@(PREFIX)/man@(PREFIX)/share/man@g" Makefile

make -f Makefile-libbz2_so
make clean
make
PREFIX="$OUTPUT_DIR/usr"
make PREFIX="$PREFIX" install

cp -av libbz2.so.* "$PREFIX/lib/"
ln -sv libbz2.so.1.0.8 "$PREFIX/lib/libbz2.so"

cp -v bzip2-shared "$PREFIX/bin/bzip2"
ln -sfv bzip2 "$PREFIX/bin/bzcat"
ln -sfv bzip2 "$PREFIX/bin/bunzip2"
rm -fv "$PREFIX/lib/libbz2.a"

echo "Bzip2 build complete"
