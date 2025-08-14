#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/bzip2 "${OUTPUT_DIR}/bin/"
echo "Successfully copied bzip2 to ${OUTPUT_DIR}/bin/"
