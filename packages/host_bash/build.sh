#!/usr/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"
cp -Lv /usr/bin/bash "${OUTPUT_DIR}/bin/"

# mkdir -p "${OUTPUT_DIR}/lib/x86_64-linux-gnu"
# cp -Lv /usr/lib/x86_64-linux-gnu/libtinfo.so.* "${OUTPUT_DIR}/lib/x86_64-linux-gnu/"

cd "${OUTPUT_DIR}/bin"
ln -sf bash sh
echo "Successfully copied bash and created sh symlink to ${OUTPUT_DIR}/bin/"
