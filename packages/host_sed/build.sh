#!/usr/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/sed "${OUTPUT_DIR}/bin/"
echo "Successfully copied sed to ${OUTPUT_DIR}/bin/"
