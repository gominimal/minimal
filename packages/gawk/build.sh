#!/bin/sh
set -e

# Copy prebuilt files to output directory
cp -r prebuilt/* $OUTPUT_DIR/

echo "Gawk prebuilt files copied"
