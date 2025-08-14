#!/bin/bash
set -e

. ./toolchain-setup.sh

tar -xf expect5.45.4.tar.gz
cd expect5.45.4

TCL_LIB_PATH="/home/bweeks/minpkgs/minimal-out/lib"
TCL_INCLUDE_PATH="/home/bweeks/minpkgs/minimal-out/include"

./configure --prefix="${OUTPUT_DIR}" \
            --with-tcl="${TCL_LIB_PATH}" \
            --with-tclinclude="${TCL_INCLUDE_PATH}" \
            --enable-shared \
            --disable-rpath \
            --mandir="${OUTPUT_DIR}/share/man"
make install

# Create symbolic link as per LFS instructions
ln -svf expect5.45.4/libexpect5.45.4.so "${OUTPUT_DIR}/lib/"
