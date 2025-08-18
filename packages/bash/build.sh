#!/bin/sh

set -e

. ./toolchain-setup.sh

# Set up paths for finding readline
export CPPFLAGS="-I$TMPDIR/readline/include"
export LDFLAGS="$LDFLAGS -L$TMPDIR/readline/lib -Wl,-rpath,$TMPDIR/readline/lib"

# Extract source
tar xf bash-5.3.tar.gz
cd bash-5.3

# Configure bash following LFS instructions
./configure --prefix="$OUTPUT_DIR" \
            --without-bash-malloc \
            --with-installed-readline \
            --docdir="$OUTPUT_DIR/share/doc/bash-5.3"

# Build
make -j$(nproc)

# Install
make install

# Create sh symlink as per LFS
ln -sv bash "$OUTPUT_DIR/bin/sh"

echo "Bash build complete"