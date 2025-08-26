#!/bin/bash

# Build all packages in the packages/ directory using --source flag

set -e

PACKAGES_DIR="packages"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Building all packages from source..."

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
    
    # Check if build.source.ncl exists
    if [ -f "$pkg_dir/build.source.ncl" ]; then
        echo "Building package from source: $pkg_name"
        cargo run --release -- build --package "$pkg_name" --source
        echo "Completed: $pkg_name"
        echo "---"
    else
        echo "Skipping $pkg_name (no build.source.ncl)"
    fi
done

echo "All packages built from source!"