#!/bin/sh

set -euo pipefail

# Create output directory
mkdir -p "${OUTPUT_DIR}/bin"

# Copy gzip binary to the output directory
cp /usr/bin/gzip "${OUTPUT_DIR}/bin/"

echo "Successfully copied gzip to ${OUTPUT_DIR}/bin/"