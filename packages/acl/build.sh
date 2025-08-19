#!/bin/sh
set -e

# Source shared toolchain setup
. ./toolchain-setup.sh

# Extract source
tar -xf acl-2.3.2.tar.xz
cd acl-2.3.2

# Configure with LFS settings
./configure --prefix=/usr \
            --disable-static \
            --docdir=/usr/share/doc/acl-2.3.2

# Build
make

# Install to output directory
make DESTDIR="$OUTPUT_DIR" install
