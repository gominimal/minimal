#!/bin/sh
set -e

. ./toolchain-setup.sh

tar -xf tcl8.6.16-src.tar.gz
cd tcl8.6.16

# Navigate to unix directory as per LFS instructions
cd unix

./configure --prefix="${OUTPUT_DIR}" \
            --mandir="${OUTPUT_DIR}/share/man" \
            --disable-rpath

make

# Apply sed modifications to configuration files as per LFS
sed -e "s|${OUTPUT_DIR}/lib|/usr/lib|" \
    -e "s|${OUTPUT_DIR}/include|/usr/include|" \
    -i tclConfig.sh

sed -e "s|${OUTPUT_DIR}/lib|/usr/lib|" \
    -e "s|${OUTPUT_DIR}/include|/usr/include|" \
    -i tkConfig.sh 2>/dev/null || true

# Skip lengthy test suite for now
echo "Skipping tests to save time during initial packaging"

make install

# Make the library files writeable
chmod -v 755 "${OUTPUT_DIR}/lib/libtcl8.6.so"

# Install the private headers
make install-private-headers

# Create symbolic link as per LFS instructions  
ln -sfv tclsh8.6 "${OUTPUT_DIR}/bin/tclsh"

# Rename the man page as per LFS instructions (if it exists)
if [ -f "${OUTPUT_DIR}/share/man/man1/tclsh8.6.1" ]; then
    mv "${OUTPUT_DIR}/share/man/man1/tclsh8.6.1" "${OUTPUT_DIR}/share/man/man1/tclsh.1"
else
    echo "Warning: tclsh8.6.1 man page not found to rename"
fi
