#!/bin/sh
set -e

# Source shared toolchain setup
. ./toolchain-setup.sh

# Extract source
tar -xf attr-2.5.2.tar.gz
cd attr-2.5.2

# Configure with LFS settings
./configure --prefix=/usr \
            --disable-static \
            --sysconfdir=/etc \
            --docdir=/usr/share/doc/attr-2.5.2

# Build
make

# Install to output directory
make DESTDIR="$OUTPUT_DIR" install