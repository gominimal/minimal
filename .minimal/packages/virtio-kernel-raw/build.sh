#!/bin/bash
# Decompress the upstream virtio-linux kernel to a raw Image. virtio-linux is a
# build_dep, so its vmlinuz output (gzip-compressed aarch64 Image) is present in
# the sandbox at /usr/share/virtio-linux/vmlinuz. libkrun loads the raw Image
# via KRUN_KERNEL_FORMAT_RAW with no decompress step.
set -euo pipefail

OUT="$OUTPUT_DIR/usr/share/virtio-linux"
mkdir -p "$OUT"
gunzip -c /usr/share/virtio-linux/vmlinuz > "$OUT/Image"
