#!/bin/sh
set -e
cd btop-1.4.5

# Disable GPU paths at compile time
make -j"$(nproc)" GPU_SUPPORT=false
make DESTDIR="${OUTPUT_DIR}" PREFIX="/usr" install
