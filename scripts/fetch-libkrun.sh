#!/usr/bin/env bash
# Materialize the upstream `libkrun` package into a link/runtime PREFIX so a
# Linux/KVM host can build and boot minvmd's guest microVM without compiling
# libkrun (and its kernel-bundling libkrunfw) from source.
#
# `minimal materialize` emits the `libkrun` OCI image declared in
# .minimal/minimal.toml (libkrun.so plus its runtime closure, which includes
# libkrunfw.so.5). Like scripts/fetch-artifact.sh this is a CACHE FETCH keyed by
# the pinned upstream `locked_commit`, not a from-source build — so it pulls the
# prebuilt artifact instead of recompiling a kernel. Do NOT run `minimal update`.
#
# We extract only libkrun.so* and libkrunfw.so* into PREFIX. The package's glibc
# / libgcc layers are deliberately left behind: minvmd links against the host
# glibc, so exposing the package's copy via LD_LIBRARY_PATH would shadow it and
# break the host binary.
#
# Afterwards the caller sets, for BOTH building and running minvmd:
#   LIBKRUN_PREFIX="$PREFIX"   # minvmd build.rs link-search dir (+ rpath)
#   LD_LIBRARY_PATH="$PREFIX"  # runtime: libkrun.so -> libkrunfw.so.5
#
# Linux-only (package materialization runs the build pipeline natively on Linux).
# Requires: a Rust toolchain + protoc + jq on the host (the CI job installs them).
#
# Usage: scripts/fetch-libkrun.sh <prefix-dir> [arch]
#   arch defaults to aarch64 (matches scripts/fetch-artifact.sh).
set -euo pipefail

PREFIX="${1:?usage: fetch-libkrun.sh <prefix-dir> [arch]}"
ARCH="${2:-aarch64}"

case "$(uname -s)" in
  Linux) ;;
  *) echo "fetch-libkrun.sh is Linux-only (got $(uname -s)); see crates/minvmd/README.md" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Build the CLI from source (debug: this drives a cache fetch, so CLI CPU is not
# the bottleneck). Incremental, so a second invocation in the same job is cheap.
cargo build -p minimal
MINIMAL="$ROOT/target/debug/minimal"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Materialize the libkrun OCI image (cache fetch keyed by the pinned commit).
IMG="$WORK/libkrun-oci.tar"
"$MINIMAL" materialize --output "$IMG" --arch "$ARCH" libkrun

# Unpack the OCI layout and replay its layers (in manifest order) into a rootfs.
# The image is a standard OCI archive: index.json -> manifest blob -> gzipped
# layer blobs, each a tar of one package's files (symlinks preserved).
LAYOUT="$WORK/layout"
ROOTFS="$WORK/rootfs"
mkdir -p "$LAYOUT" "$ROOTFS"
tar xf "$IMG" -C "$LAYOUT"

manifest_digest="$(jq -r '.manifests[0].digest' "$LAYOUT/index.json" | sed 's/^sha256://')"
mapfile -t layers < <(
  jq -r '.layers[].digest' "$LAYOUT/blobs/sha256/$manifest_digest" | sed 's/^sha256://'
)
for layer in "${layers[@]}"; do
  tar xzf "$LAYOUT/blobs/sha256/$layer" -C "$ROOTFS"
done

# Copy just the libkrun + libkrunfw shared objects (cp -a preserves the soname
# symlink chains); leave the rest of the closure behind so it can't shadow host
# libs at link or run time.
mkdir -p "$PREFIX"
cp -a "$ROOTFS"/usr/lib/libkrun.so* "$PREFIX"/
cp -a "$ROOTFS"/usr/lib/libkrunfw.so* "$PREFIX"/

echo "fetch-libkrun: staged libkrun + libkrunfw into $PREFIX"
ls -l "$PREFIX"/libkrun.so* "$PREFIX"/libkrunfw.so*
