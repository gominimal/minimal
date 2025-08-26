#!/bin/sh
set -e

tar xfo perl-5.42.0.tar.xz
cd perl-5.42.0

sh Configure -des                                           \
             -D cc=gcc                                     \
             -D prefix=/usr                                 \
             -D vendorprefix=/usr                           \
             -D privlib=/usr/lib/perl5/5.42/core_perl      \
             -D archlib=/usr/lib/perl5/5.42/core_perl      \
             -D sitelib=/usr/lib/perl5/5.42/site_perl      \
             -D sitearch=/usr/lib/perl5/5.42/site_perl     \
             -D vendorlib=/usr/lib/perl5/5.42/vendor_perl  \
             -D vendorarch=/usr/lib/perl5/5.42/vendor_perl \
             -D man1dir=/usr/share/man/man1                \
             -D man3dir=/usr/share/man/man3                \
             -D pager="/usr/bin/less -isR"                 \
             -D useshrplib                                 \
             -D usethreads

make -j$(nprocs)
make DESTDIR=$OUTPUT_DIR install

echo "Perl build complete"
