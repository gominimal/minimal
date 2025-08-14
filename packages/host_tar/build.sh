#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/tar "${OUTPUT_DIR}/bin/"
echo "Successfully copied tar to ${OUTPUT_DIR}/bin/"
