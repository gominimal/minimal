#!/usr/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/usr/bin"
cp -Lv /usr/bin/bash "${OUTPUT_DIR}/usr/bin/"

cd "${OUTPUT_DIR}/usr/bin"
ln -sf bash sh
echo "Successfully copied bash and created sh symlink to ${OUTPUT_DIR}/bin/"
