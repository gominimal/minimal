#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf bzip2-1.0.8.tar.gz
cd bzip2-1.0.8

sed -i 's@\(ln -s -f \)$(PREFIX)/bin/@\1@' Makefile
sed -i "s@(PREFIX)/man@(PREFIX)/share/man@g" Makefile

make -f Makefile-libbz2_so CC="${CC}" CFLAGS="${CFLAGS} -fPIC" LDFLAGS="${LDFLAGS}" 
make clean
make CC="${CC}" AR="${AR}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}"
make PREFIX="$OUTPUT_DIR" install

cp -av libbz2.so.* "$OUTPUT_DIR/lib/"
ln -sv libbz2.so.1.0.8 "$OUTPUT_DIR/lib/libbz2.so"
cp -v bzip2-shared "$OUTPUT_DIR/bin/bzip2"
for i in "$OUTPUT_DIR"/bin/{bzcat,bunzip2}; do
  ln -sfv bzip2 "$i"
done
rm -fv "$OUTPUT_DIR/lib/libbz2.a"

echo "Bzip2 build complete"
