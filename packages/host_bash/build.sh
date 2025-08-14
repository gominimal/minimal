#!/usr/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp /usr/bin/bash "${OUTPUT_DIR}/bin/"
cd "${OUTPUT_DIR}/bin"
ln -sf bash sh
echo "Successfully copied bash and created sh symlink to ${OUTPUT_DIR}/bin/"
