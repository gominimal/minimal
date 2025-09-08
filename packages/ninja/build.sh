#!/bin/sh
set -e

tar xf ninja-1.13.1.tar.gz
cd ninja-1.13.1

python3 configure.py --bootstrap --verbose

mkdir -v -p $OUTPUT_DIR/usr/bin
install -vm755 ninja $OUTPUT_DIR/usr/bin/
