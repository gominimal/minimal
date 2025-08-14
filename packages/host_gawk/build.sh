#!/opt/minimal/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"

cp /usr/bin/gawk "${OUTPUT_DIR}/bin/"
ln -s gawk "${OUTPUT_DIR}/bin/awk"

echo "Successfully copied gawk to ${OUTPUT_DIR}/bin/"
