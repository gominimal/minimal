#!/usr/bin/bash
set -e

tar xfo gcc-15.2.0.tar.xz
cd gcc-15.2.0

case $(uname -m) in
  x86_64)
    sed -e '/m64=/s/lib64/lib/' \
        -i.orig gcc/config/i386/t-linux64
  ;;
esac

mkdir -v build
cd build

# TODO
# --enable-host-pie
# --enable-nls

../configure \
             --prefix=/usr             \
             --enable-languages=c,c++ \
             --enable-default-pie     \
             --enable-default-ssp     \
             --disable-multilib       \
             --disable-bootstrap      \
             --disable-fixincludes     \
             --with-system-zlib       \
             --disable-nls

make -j$(nproc)
# TODO make -k check
make DESTDIR=$OUTPUT_DIR install

# TODO
# ln -sf $OUTPUT_DIR/usr/bin/gcc $OUTPUT_DIR/usr/bin/cc
