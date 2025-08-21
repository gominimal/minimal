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
             --enable-stack-protector=strong \
             --enable-kernel=5.4

make -j 8

make DESTDIR=/home/bweeks/minpkgs/packages/glibc/prebuilt install
