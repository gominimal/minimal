#!/bin/sh
set -ex

mkdir -p $OUTPUT_DIR/usr/bin
cp prebuilt/usr/bin/make $OUTPUT_DIR/usr/bin/make
chmod +x $OUTPUT_DIR/usr/bin/make