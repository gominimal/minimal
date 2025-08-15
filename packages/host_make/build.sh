#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/usr/bin"
cp /usr/bin/make "${OUTPUT_DIR}/usr/bin/"
echo "Successfully copied make to ${OUTPUT_DIR}/usr/bin/"
