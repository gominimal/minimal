#!/bin/sh

set -e

tar xf glibc-2.42.tar.xz
cd glibc-2.42

mkdir -v build
cd build

../configure --prefix=/usr                   \
             --disable-werror                \
             --disable-nscd                  \
             libc_cv_slibdir=/usr/lib        \
             --enable-kernel=5.4

# TODO
# --enable-stack-protector=strong

make -j 8

make DESTDIR=$OUTPUT_DIR install

# Create lib64 symlink for x86_64 ABI compliance
mkdir -p $OUTPUT_DIR/lib64
ln -sf ../usr/lib/ld-linux-x86-64.so.2 $OUTPUT_DIR/lib64/ld-linux-x86-64.so.2
