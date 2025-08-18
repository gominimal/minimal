#!/bin/sh

set -e

. ./toolchain-setup.sh

tar xf perl-5.42.0.tar.xz
cd perl-5.42.0

export CFLAGS="$CFLAGS -std=gnu99"

export ccflags="$CFLAGS"
export ldflags="-lm --sysroot=$TOOLCHAIN_SYSROOT -Wl,--dynamic-linker=$DYNAMIC_LINKER -Wl,-rpath=$TOOLCHAIN_SYSROOT/lib64"
export lddlflags="-lm --sysroot=$TOOLCHAIN_SYSROOT"

./Configure -des \
             -D cc=$CC \
             -D cpp=$CXX \
             -D ld=$LD \
             -D ccflags="$ccflags" \
             -D ldflags="$ldflags" \
             -D lddlflags="-shared $lddlflags" \
             -D sysroot=$TOOLCHAIN_SYSROOT \
             -D prefix="$OUTPUT_DIR" \
             -D vendorprefix="$OUTPUT_DIR" \
             -D privlib="$OUTPUT_DIR/lib/perl5/5.42/core_perl" \
             -D archlib="$OUTPUT_DIR/lib/perl5/5.42/core_perl" \
             -D sitelib="$OUTPUT_DIR/lib/perl5/5.42/site_perl" \
             -D sitearch="$OUTPUT_DIR/lib/perl5/5.42/site_perl" \
             -D vendorlib="$OUTPUT_DIR/lib/perl5/5.42/vendor_perl" \
             -D vendorarch="$OUTPUT_DIR/lib/perl5/5.42/vendor_perl" \
             -D man1dir="$OUTPUT_DIR/share/man/man1" \
             -D man3dir="$OUTPUT_DIR/share/man/man3" \
             -D pager="/usr/bin/less -isR" \
             -D useshrplib \
             -D usethreads \
             -U usenm

make
make install

echo "Perl build complete"
