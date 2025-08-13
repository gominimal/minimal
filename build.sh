#!/usr/bin/bash
set -euo pipefail

# Static toolchain build script
# This copies the pre-built cross-compilation toolchain to the output directory
# No compilation or dependencies required - this is pure asset copying

echo "Copying pre-built toolchain to output directory..."
echo "Current directory: $(pwd)"
echo "Available files:"
ls -la

# Copy the entire toolchain directory structure
if [ ! -d "toolchain" ]; then
    echo "Error: toolchain directory not found"
    exit 1
fi

# Copy all toolchain files to the output
cp -r toolchain/* "$OUTPUT_DIR/"

# Verify key toolchain components exist
if [ ! -f "$OUTPUT_DIR/bin/x86_64-unknown-linux-gnu-gcc" ]; then
    echo "Warning: GCC not found in expected location"
fi

if [ ! -d "$OUTPUT_DIR/x86_64-unknown-linux-gnu/sysroot" ]; then
    echo "Warning: Sysroot not found in expected location"
fi

echo "Toolchain copied successfully to $OUTPUT_DIR"
echo "Available tools:"
ls -la "$OUTPUT_DIR/bin/" | head -10 || true
