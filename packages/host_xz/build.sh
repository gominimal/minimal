#!/usr/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/xz "${OUTPUT_DIR}/bin/"
echo "Successfully copied xz to ${OUTPUT_DIR}/bin/"
