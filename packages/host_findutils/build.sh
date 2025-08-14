#!/bin/bash

set -euo pipefail

mkdir -p "${OUTPUT_DIR}/bin"

cp /usr/bin/find "${OUTPUT_DIR}/bin/"

echo "Successfully copied findutils to ${OUTPUT_DIR}/bin/"
