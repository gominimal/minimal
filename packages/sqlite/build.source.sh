#!/bin/sh
set -e

# Extract archive
tar xfo sqlite-autoconf-3500400.tar.gz
cd sqlite-autoconf-3500400

# Configure with standard options
./configure --prefix=/usr          \
            --disable-static       \
            --enable-fts4          \
            --enable-fts5          \
            --enable-rtree

# Build with parallel make
make -j$(nproc)

# Install to output directory
make DESTDIR="$OUTPUT_DIR" install