#!/bin/sh

set -euo pipefail

# Create output directory
mkdir -p "${OUTPUT_DIR}/bin"

# Copy tar binary to the output directory
cp /usr/bin/tar "${OUTPUT_DIR}/bin/"

echo "Successfully copied tar to ${OUTPUT_DIR}/bin/"