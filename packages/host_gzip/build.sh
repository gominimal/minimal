#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/gzip "${OUTPUT_DIR}/bin/"
echo "Successfully copied gzip to ${OUTPUT_DIR}/bin/"
