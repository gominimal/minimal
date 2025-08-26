#!/usr/bin/bash
set -e

tar xfo gcc-15.2.0.tar.xz
cd gcc-15.2.0

# tar xfo gcc-14.3.0.tar.xz
# cd gcc-14.3.0

case $(uname -m) in
  x86_64)
    sed -e '/m64=/s/lib64/lib/' \
        -i.orig gcc/config/i386/t-linux64
  ;;
esac

mkdir -v build
cd build

../configure \
             --prefix=/usr             \
             --enable-languages=c,c++ \
             --disable-multilib       \
             --disable-fixincludes     \
             --disable-lto            \
             --disable-nls            \
             --disable-bootstrap      \

# TODO
# --with-system-zlib 
# --enable-default-pie
# --enable-default-ssp
# --enable-lto
# --enable-nls

make -j$(nproc)

make DESTDIR=$OUTPUT_DIR install
