#!/usr/bin/env bash
# Build libkrunfw + libkrun from source into a relocatable PREFIX, so a
# Linux/KVM host with no packaged libkrun can still boot minvmd's guest microVM.
#
# Pins the versions minvmd requires:
#   - libkrunfw v5.5.0  — bundles linux-6.12.91 as the guest kernel firmware.
#   - libkrun   v1.19.0 — KVM backend, built with BLK=1 so virtio-blk /
#     `krun_add_disk2` is exported (minvmd attaches the rootfs as /dev/vda).
#     `blk` is NOT a default libkrun feature, so without BLK=1 minvmd fails to
#     link (`undefined reference to krun_add_disk2`).
#
# libkrun < 1.19.0 has a vsock TX-chain bug, so the pin is a hard floor.
#
# Idempotent: if $PREFIX already exports libkrun.so (e.g. a CI cache restored
# it), this is a no-op. The expensive part is libkrunfw, which compiles a kernel.
#
# Build dependencies (Debian/Ubuntu) — install before calling:
#   build-essential flex bison bc libelf-dev libssl-dev python3 \
#   python3-pyelftools cpio clang libclang-dev pkg-config patchelf git
# plus a Rust toolchain (cargo) on PATH.
#
# Usage: scripts/build-libkrun.sh <prefix-dir>
#   Afterwards the caller sets, for BOTH building and running minvmd:
#     LIBKRUN_PREFIX="$PREFIX/lib64"   # minvmd build.rs link-search dir
#     LD_LIBRARY_PATH="$PREFIX/lib64"  # runtime: libkrun.so -> libkrunfw.so.5
set -euo pipefail

PREFIX="${1:?usage: build-libkrun.sh <prefix-dir>}"
LIBKRUNFW_TAG="v5.5.0"
LIBKRUN_TAG="v1.19.0"

mkdir -p "$PREFIX"
PREFIX="$(cd "$PREFIX" && pwd)" # absolutise

# Gate the skip on a version stamp, not mere file presence: a restored prefix
# (or a local reuse) built from different pins must be rebuilt, not silently
# accepted.
STAMP_FILE="$PREFIX/lib64/.minvmd-libkrun-build-stamp"
EXPECTED_STAMP="libkrunfw=${LIBKRUNFW_TAG};libkrun=${LIBKRUN_TAG}"

if [ -e "$PREFIX/lib64/libkrun.so" ]; then
  if [ -f "$STAMP_FILE" ] && [ "$(cat "$STAMP_FILE")" = "$EXPECTED_STAMP" ]; then
    echo "build-libkrun: pinned libkrun ($EXPECTED_STAMP) already in $PREFIX/lib64 — skipping build"
    exit 0
  fi
  echo "build-libkrun: existing libkrun found but version stamp missing/mismatched; rebuilding"
fi

JOBS="$(nproc)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── libkrunfw: guest kernel firmware (compiles a Linux kernel) ────────────────
# NOTE: run with `cd` + an explicit `-j`, NOT `make -C` and NOT an exported
# MAKEFLAGS. libkrunfw's Makefile forwards `$(MAKEFLAGS)` verbatim into the
# kernel's recursive make; `-C` turns on print-directory mode, which injects a
# bare `w` token into MAKEFLAGS that the kernel make then treats as a goal
# (`make w` → "No rule to make target 'w'"). A plain in-dir `make -jN` forwards
# a clean MAKEFLAGS and parallelises the kernel build correctly.
git clone --depth 1 --branch "$LIBKRUNFW_TAG" \
  https://github.com/containers/libkrunfw "$WORK/libkrunfw"
( cd "$WORK/libkrunfw" && make -j"$JOBS" )
( cd "$WORK/libkrunfw" && make install PREFIX="$PREFIX" )

# ── libkrun: KVM backend (BLK=1 for virtio-blk / krun_add_disk2) ──────────────
git clone --depth 1 --branch "$LIBKRUN_TAG" \
  https://github.com/containers/libkrun "$WORK/libkrun"
# Let the libkrun build's final link resolve the libkrunfw we just installed.
export LIBRARY_PATH="$PREFIX/lib64${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$PREFIX/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
( cd "$WORK/libkrun" && make BLK=1 -j"$JOBS" )
( cd "$WORK/libkrun" && make BLK=1 install PREFIX="$PREFIX" )

printf '%s\n' "$EXPECTED_STAMP" > "$STAMP_FILE"
echo "build-libkrun: installed libkrun $LIBKRUN_TAG + libkrunfw $LIBKRUNFW_TAG into $PREFIX/lib64"
ls -l "$PREFIX/lib64"/libkrun.so* "$PREFIX/lib64"/libkrunfw.so*
