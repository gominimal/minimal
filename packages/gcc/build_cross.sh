#!/bin/sh
set -e

# tar -xf gcc-15.2.0.tar.xz
cd gcc-15.2.0

# tar -xf ../mpfr-4.2.2.tar.xz
# mv -v mpfr-4.2.2 mpfr
# tar -xf ../gmp-6.3.0.tar.xz
# mv -v gmp-6.3.0 gmp
# tar -xf ../mpc-1.3.1.tar.gz
# mv -v mpc-1.3.1 mpc

case $(uname -m) in
  x86_64)
    sed -e '/m64=/s/lib64/lib/' \
        -i.orig gcc/config/i386/t-linux64
  ;;
esac

mkdir -v build || true
cd       build

    # --enable-default-pie       \
    # --enable-default-ssp       \

# export PATH="/home/bweeks/x-tools/x86_64-minimal-linux-gnu/bin:$PATH"
../configure                        \
    --prefix=/usr                   \
    --disable-nls                  \
    --disable-multilib             \
    --disable-libatomic            \
    --disable-libgomp              \
    --disable-libquadmath          \
    --disable-libsanitizer         \
    --disable-libssp               \
    --disable-libvtv               \
    --enable-languages=c,c++       \
    --disable-bootstrap            \
    --disable-host-shared          \
    --with-stage1-ldflags="-static" \
    LDFLAGS="-static"

make -j8

make DESTDIR=/home/bweeks/minpkgs/packages/gcc/prebuilt install
