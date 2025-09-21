#!/bin/sh
set -e

tar xfo pciutils-3.14.0.tar.gz
cd pciutils-3.14.0

# Avoid conflict with hwdata package
sed -r '/INSTALL/{/PCI_IDS|update-pciids /d; s/update-pciids.8//}' \
    -i Makefile

make PREFIX=/usr                \
     SHAREDIR=/usr/share/hwdata \
     SHARED=yes                 \
     CC=gcc                     \
     -j$(nproc)

make PREFIX=/usr                \
     SHAREDIR=/usr/share/hwdata \
     SHARED=yes                 \
     DESTDIR=$OUTPUT_DIR        \
     install install-lib

chmod -v 755 $OUTPUT_DIR/usr/lib/libpci.so
