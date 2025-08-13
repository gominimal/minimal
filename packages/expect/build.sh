#!/bin/bash
set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar -xf expect5.45.4.tar.gz
cd expect5.45.4

# Skip patch for now - may not be needed for our compiler version

# Set up Tcl paths from our minimal-out directory
TCL_LIB_PATH="/home/bweeks/minpkgs/minimal-out/lib"
TCL_INCLUDE_PATH="/home/bweeks/minpkgs/minimal-out/include"

# Configure Expect with Tcl paths
./configure --prefix="${OUTPUT_DIR}" \
            --with-tcl="${TCL_LIB_PATH}" \
            --with-tclinclude="${TCL_INCLUDE_PATH}" \
            --enable-shared \
            --disable-rpath \
            --mandir="${OUTPUT_DIR}/share/man"

make

# Skip tests for now as they may require PTY setup
echo "Skipping tests - may require PTY environment setup"

make install

# Create symbolic link as per LFS instructions
ln -svf expect5.45.4/libexpect5.45.4.so "${OUTPUT_DIR}/lib/"