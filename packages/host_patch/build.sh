#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/patch "${OUTPUT_DIR}/bin/"
echo "Successfully copied make to ${OUTPUT_DIR}/bin/"
