#!/bin/bash
set -euo pipefail

mkdir -p "${OUTPUT_DIR}"/{bin,lib}
cp /usr/bin/python3 "${OUTPUT_DIR}/bin/"
cp -R /usr/lib/python3.13 "${OUTPUT_DIR}/lib/"
echo "Successfully copied python3 to ${OUTPUT_DIR}/bin/"
