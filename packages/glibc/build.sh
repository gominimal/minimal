#!/usr/bin/sh
set -e

. ./toolchain-setup.sh

# Get the sysroot path from the compiler
SYSROOT="$(${CC} -print-sysroot)"
echo "Using sysroot: ${SYSROOT}"

# Set environment variables to enforce sysroot isolation (glibc requires optimization)
export CFLAGS="-O2 --sysroot=${SYSROOT} -isystem ${SYSROOT}/usr/include"
export CXXFLAGS="-O2 --sysroot=${SYSROOT} -isystem ${SYSROOT}/usr/include"
export CPPFLAGS="-isystem ${SYSROOT}/usr/include"
export LDFLAGS="--sysroot=${SYSROOT} -L${SYSROOT}/lib -L${SYSROOT}/usr/lib"

# Prevent glibc from using host system paths
export libc_cv_forced_unwind=yes
export libc_cv_c_cleanup=yes
export libc_cv_ctors_header=yes
export libc_cv_gcc_builtin_expect=yes

tar xf glibc-2.42.tar.xz
cd glibc-2.42

patch -Np1 -i ../glibc-2.42-fhs-1.patch

mkdir build
cd build

# Configure glibc with sysroot awareness and isolation
../configure --prefix="${OUTPUT_DIR}"         \
            --host=x86_64-unknown-linux-gnu   \
            --build=$(../scripts/config.guess) \
            --with-sysroot="${SYSROOT}"       \
            --with-headers="${SYSROOT}/usr/include" \
            --disable-werror                \
            --disable-nscd                  \
            --disable-sanity-checks         \
            --enable-kernel=5.4             \
            --enable-stack-protector=strong \
            libc_cv_slibdir="${OUTPUT_DIR}/lib" \
            libc_cv_rtlddir="${OUTPUT_DIR}/lib" \
            libc_cv_localedir="${OUTPUT_DIR}/share/locale" \
            libc_cv_rootsbindir="${OUTPUT_DIR}/sbin"

make
make install 
