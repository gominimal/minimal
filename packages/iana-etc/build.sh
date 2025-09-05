#!/bin/sh
set -e

tar xf iana-etc-20250618.tar.gz
cd iana-etc-20250618

mkdir -p "$OUTPUT_DIR/etc"
cp services protocols "$OUTPUT_DIR/etc/"
