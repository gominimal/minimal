#!/bin/bash

# Build all packages in the packages/ directory

set -e

PACKAGES_DIR="packages"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Building all packages..."

# Get all package directories and randomize the order
pkg_dirs=()
for pkg_dir in "$PACKAGES_DIR"/*; do
    if [ -d "$pkg_dir" ]; then
        pkg_dirs+=("$pkg_dir")
    fi
done

# Randomize the array using shuf
readarray -t randomized_dirs < <(printf '%s\n' "${pkg_dirs[@]}" | shuf)

for pkg_dir in "${randomized_dirs[@]}"; do
    pkg_name=$(basename "$pkg_dir")
    echo "Building package: $pkg_name"
    cargo run --release -- build --package "$pkg_name"
    echo "Completed: $pkg_name"
    echo "---"
done

echo "All packages built!"
