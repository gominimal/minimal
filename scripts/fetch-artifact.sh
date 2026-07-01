#!/bin/sh
# Materialize a minimal output (e.g. the guest kernel or rootfs) using the
# `minimal` CLI built from THIS repo's sources, against the repo's own
# `.minimal/minimal.toml` (which pins the upstream commit and declares the
# outputs, backed by upstream packages).
#
# This is a cache fetch, not a build: the output is pulled from the public
# artifact cache keyed by the pinned `locked_commit`, so a prebuilt aarch64
# artifact pulls fine on an x86_64 Linux runner (no native arm64 build, no
# self-hosted runner). Do NOT run `minimal update` — it would rewrite the
# tracked locked_commit and could resolve to an uncached commit, forcing a real
# (and, cross-arch, impossible) build. The pinned commit is authoritative.
#
# Linux-only: package materialization runs the build pipeline natively on Linux.
# On macOS the CLI runs inside a VM and only the project dir syncs to the host;
# use the local dev flow in crates/minvmd/README.md instead.
#
# Requires: a Rust toolchain + protoc on the host (the CI job installs them).
#
# Usage: scripts/fetch-artifact.sh <output-name> <dest-path> [arch]
#   arch defaults to aarch64 (the boot runner is Apple Silicon).
set -eu

OUTPUT="${1:?usage: fetch-artifact.sh <output-name> <dest-path> [arch]}"
DEST="${2:?usage: fetch-artifact.sh <output-name> <dest-path> [arch]}"
ARCH="${3:-aarch64}"

case "$(uname -s)" in
  Linux) ;;
  *) echo "fetch-artifact.sh is Linux-only (got $(uname -s)); see crates/minvmd/README.md" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build the CLI from source (debug: this drives a cache fetch, so CLI CPU is not
# the bottleneck). Incremental, so a second invocation in the same job is cheap.
cargo build -p mip
MIP="$ROOT/target/debug/mip"

mkdir -p "$(dirname "$DEST")"
"$MIP" materialize --output "$DEST" --arch "$ARCH" "$OUTPUT"
echo "fetched $OUTPUT -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
