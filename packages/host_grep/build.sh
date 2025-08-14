#!/bin/sh

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"

cp /usr/bin/grep "${OUTPUT_DIR}/bin/"
cp /usr/bin/egrep "${OUTPUT_DIR}/bin/"

echo "Successfully copied grep to ${OUTPUT_DIR}/bin/"
