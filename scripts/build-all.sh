#!/bin/bash

# Build all packages in the packages/ directory

set -e

PACKAGES_DIR="packages"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

echo "Building all packages..."

for pkg_dir in "$PACKAGES_DIR"/*; do
    if [ -d "$pkg_dir" ]; then
        pkg_name=$(basename "$pkg_dir")
        echo "Building package: $pkg_name"
        cargo run -- build --package "$pkg_name"
        echo "Completed: $pkg_name"
        echo "---"
    fi
done

echo "All packages built!"
