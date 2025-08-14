#!/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"

cp /usr/bin/diff "${OUTPUT_DIR}/bin/"

echo "Successfully copied diffutils to ${OUTPUT_DIR}/bin/"
