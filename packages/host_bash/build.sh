#!/bin/sh

set -euo pipefail

# Create output directory
mkdir -p "${OUTPUT_DIR}/bin"

# Copy bash binary to the output directory  
cp /usr/bin/bash "${OUTPUT_DIR}/bin/"

# Create symlink from sh to bash (relative symlink)
cd "${OUTPUT_DIR}/bin"
ln -sf bash sh

echo "Successfully copied bash and created sh symlink to ${OUTPUT_DIR}/bin/"