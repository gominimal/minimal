#!/bin/sh
# Build the Stage-2 guest initramfs: cross-compile minimald to a static aarch64
# binary and pack it as the initramfs `/init` in a newc cpio. The kernel runs
# `/init` (= minimald) as pid-1; minimald mounts the generic guest rootfs
# (/dev/vda) and chroots into it. No minimald is baked into the rootfs.
#
# Uses `cross` (Docker) for the musl toolchain. Linux host with Docker.
#
# Usage: scripts/build-initramfs.sh <dest-cpio> [rust-target]
set -eu

DEST="${1:?usage: build-initramfs.sh <dest-cpio> [rust-target]}"
TARGET="${2:-aarch64-unknown-linux-musl}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

command -v cross >/dev/null || cargo install cross --locked
# The `initramfs` profile drops the release LTO + codegen-units=1 (which the
# guest binary doesn't need) to compile much faster.
cross build -p minimald --profile initramfs --target "$TARGET"
BIN="$ROOT/target/$TARGET/initramfs/minimald"
[ -x "$BIN" ] || { echo "minimald not built at $BIN" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/newroot"
cp "$BIN" "$STAGE/init"
chmod +x "$STAGE/init"
mkdir -p "$(dirname "$DEST")"
( cd "$STAGE" && find . | cpio -o -H newc ) > "$DEST"
echo "built initramfs -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
