#!/bin/sh

set -euo pipefail

# Create output directory
mkdir -p "${OUTPUT_DIR}/bin"

# Copy sed binary to the output directory
cp /usr/bin/sed "${OUTPUT_DIR}/bin/"

echo "Successfully copied sed to ${OUTPUT_DIR}/bin/"