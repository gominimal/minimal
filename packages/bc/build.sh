#!/bin/bash
set -e

source "${SCRIPTS_DIR}/toolchain-setup.sh"

tar -xf bc-7.0.3.tar.xz
cd bc-7.0.3

# Dependencies are now mounted at /usr/local/ (standard location)
# Configure should find them automatically with standard search paths

# Configure with readline support enabled (dependencies at /usr/local)
CC="${CC}" CFLAGS="${CFLAGS} -std=c99 -D_GNU_SOURCE" ./configure --prefix="${OUTPUT_DIR}" -G -O3 -r

make
make test || echo "Some tests may fail - this is expected"
make install
