#!/bin/sh
set -ex

mkdir -p $OUTPUT_DIR/usr/bin
cp output/bin/make $OUTPUT_DIR/usr/bin/make
