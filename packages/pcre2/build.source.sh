#!/bin/sh
set -e

tar xfo pcre2-10.46.tar.bz2
cd pcre2-10.46

# TODO
# --enable-pcre2test-libreadline 

./configure  --prefix=/usr                        \
            --docdir=/usr/share/doc/pcre2-10.45 \
            --enable-unicode                    \
            --enable-jit                        \
            --enable-pcre2-16                   \
            --enable-pcre2-32                   \
            --enable-pcre2grep-libz             \
            --enable-pcre2grep-libbz2           \
            --disable-static

make -j$(nproc)
# make check
make DESTDIR=$OUTPUT_DIR install
