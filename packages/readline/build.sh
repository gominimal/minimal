#!/bin/bash

set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar xf readline-8.3.tar.gz
cd readline-8.3

# Configure readline - following LFS 12.2 instructions
sed -i '/MV.*old/d' Makefile.in
sed -i '/{OLDSUFF}/c:' support/shlib-install

sed -i 's/-Wl,-rpath,[^ ]*//' support/shobj-conf

./configure --prefix="$OUTPUT_DIR" \
            --disable-static \
            --with-curses \
            --enable-bracketed-paste-default \
            --docdir="$OUTPUT_DIR/share/doc/readline-8.3"

make
make install

# Create symlinks for compatibility
if [ ! -e "$OUTPUT_DIR/lib/libreadline.so" ]; then
    ln -sfv libreadline.so.8 "$OUTPUT_DIR/lib/libreadline.so"
fi

if [ ! -e "$OUTPUT_DIR/lib/libhistory.so" ]; then
    ln -sfv libhistory.so.8 "$OUTPUT_DIR/lib/libhistory.so"
fi

echo "Readline build complete"
