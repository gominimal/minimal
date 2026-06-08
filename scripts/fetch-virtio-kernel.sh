#!/bin/sh
# Materialize the raw virtio kernel Image using the `minimal` CLI built from THIS
# repo's sources, against the repo's own `.minimal/minimal.toml` (which pins the
# upstream commit and declares the `virtio-kernel` raw-file output, backed by the
# upstream `virtio-kernel-raw` package). No promoted CLI download, no scratch
# project: the kernel is pulled from the public build cache keyed by the pinned
# `locked_commit`, so this is a cache fetch, not a kernel compile.
#
# The output is an uncompressed Image (virtio-kernel-raw decompresses upstream's
# Image.gz at build time), so minvmd loads it with KRUN_KERNEL_FORMAT_RAW and
# skips libkrun's in-VMM gzip decompress (~77 ms, over half of boot-to-READY).
#
# Linux-only: package materialization runs the build pipeline natively on Linux.
# On macOS the CLI runs inside a VM and only the project dir syncs to the host;
# use the local dev flow in crates/minvmd/README.md instead.
#
# Requires: a Rust toolchain + protoc on the host (the CI job installs them).
#
# Usage: scripts/fetch-virtio-kernel.sh <dest-vmlinuz-path> [arch]
#   arch defaults to aarch64 (the self-hosted macOS CI runner is Apple Silicon).
set -eu

DEST="${1:?usage: fetch-virtio-kernel.sh <dest-vmlinuz-path> [arch]}"
ARCH="${2:-aarch64}"

case "$(uname -s)" in
  Linux) ;;
  *) echo "fetch-virtio-kernel.sh is Linux-only (got $(uname -s)); see crates/minvmd/README.md" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build the CLI from source (debug: this drives a cache fetch, so CLI CPU is not
# the bottleneck and a debug build compiles faster). Do NOT run `minimal update`
# — it would rewrite the tracked locked_commit and could resolve to an uncached
# commit, forcing a real kernel build. The pinned commit is authoritative.
cargo build -p minimal
MINIMAL="$ROOT/target/debug/minimal"

mkdir -p "$(dirname "$DEST")"
"$MINIMAL" materialize --output "$DEST" --arch "$ARCH" virtio-kernel
echo "fetched kernel -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes, uncompressed)"
