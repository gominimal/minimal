#!/bin/sh
set -e

tar xfo sqlite-autoconf-3500400.tar.gz
cd sqlite-autoconf-3500400

export CFLAGS="-DSQLITE_ENABLE_COLUMN_METADATA"
./configure  --prefix=/usr         \
            --disable-static       \
            --enable-fts4          \
            --enable-fts5          \
            --enable-rtree         \
            --enable-session

make -j$(nproc)

make DESTDIR="$OUTPUT_DIR" install
