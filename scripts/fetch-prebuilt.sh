#!/usr/bin/env bash
# Fetch a prebuilt guest artifact straight from the public artifact cache — no
# toolchain, no shim, no graph evaluation.
#
# Resolution goes through the per-commit package map buildbot publishes next to
# the cache (build-servers crates/buildbot/src/commit_index.rs): for the pkgs
# commit pinned in .minimal/minimal.toml,
#
#   https://cache.minimal.farm/github.com/gominimal/pkgs/<commit>.map.json
#
# maps arch -> package name -> {spec_hash, sha256}, and the artifact itself is
# the content-addressed zstd tarball https://cache.minimal.farm/<sha256>.zst.
# The map only exists for commits built since the writer landed; a 404 means
# the pinned commit predates it — bump locked_commit.
#
# What we extract per artifact (paths per .minimal/minimal.toml [outputs]):
#   kernel  package virtio-kernel-raw  -> usr/share/virtio-linux/Image      (file)
#   rootfs  package microvm-rootfs     -> usr/share/microvm-rootfs/rootfs.img (file)
#   krun    packages libkrun+libkrunfw -> usr/lib/libkrun*.so*, flattened into
#           the destination PREFIX dir (Linux hosts; macOS links Homebrew's)
#
# Usage: scripts/fetch-prebuilt.sh <kernel|rootfs|krun> <dest> [arch]
#   dest: file path for kernel/rootfs, prefix DIR for krun
#   arch: aarch64 (default) or x86_64 (host names; mapped to the index's
#         arm64/amd64 keys)
# Env:   MINIMAL_PKGS_COMMIT overrides the pinned commit.
set -euo pipefail

WHAT="${1:?usage: fetch-prebuilt.sh <kernel|rootfs|krun> <dest> [arch]}"
DEST="${2:?usage: fetch-prebuilt.sh <kernel|rootfs|krun> <dest> [arch]}"
ARCH="${3:-aarch64}"

CACHE_URL="${MINIMAL_CACHE_URL:-https://cache.minimal.farm}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

for tool in curl jq zstd tar; do
  command -v "$tool" >/dev/null 2>&1 || { echo "'$tool' not found — install it (macOS: brew install $tool)" >&2; exit 1; }
done

case "$ARCH" in
  aarch64|arm64) MAP_ARCH=arm64 ;;
  x86_64|amd64)  MAP_ARCH=amd64 ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

COMMIT="${MINIMAL_PKGS_COMMIT:-$(sed -n 's/^locked_commit *= *"\(.*\)"/\1/p' "$ROOT/.minimal/minimal.toml")}"
[ -n "$COMMIT" ] || { echo "no locked_commit in .minimal/minimal.toml and MINIMAL_PKGS_COMMIT unset" >&2; exit 1; }

case "$WHAT" in
  kernel) PKGS="virtio-kernel-raw" ;;
  rootfs) PKGS="microvm-rootfs" ;;
  krun)   PKGS="libkrun libkrunfw" ;;
  *) echo "unknown artifact '$WHAT' (kernel|rootfs|krun)" >&2; exit 1 ;;
esac

MAP_URL="$CACHE_URL/github.com/gominimal/pkgs/$COMMIT.map.json"
MAP="$(curl -sf --max-time 30 "$MAP_URL")" || {
  echo "no package map for pkgs commit $COMMIT ($MAP_URL)" >&2
  echo "the pinned commit likely predates the per-commit index; bump locked_commit in .minimal/minimal.toml" >&2
  exit 1
}

TMP="$(mktemp -d)"
PARTIAL=""
trap 'rm -rf "$TMP" ${PARTIAL:+"$PARTIAL"}' EXIT

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

for pkg in $PKGS; do
  sha256="$(jq -re --arg a "$MAP_ARCH" --arg p "$pkg" '.arches[$a][$p].sha256' <<<"$MAP")" || {
    echo "package '$pkg' not in the $MAP_ARCH index for commit $COMMIT" >&2; exit 1; }
  [[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "malformed sha256 for '$pkg' in the index: $sha256" >&2; exit 1; }
  curl -sf --max-time 300 "$CACHE_URL/$sha256.zst" -o "$TMP/$pkg.zst" || {
    echo "artifact fetch failed: $CACHE_URL/$sha256.zst ($pkg)" >&2; exit 1; }
  # The key is the content address — verify the bytes actually match it before
  # anything gets extracted.
  got="$(sha256_of "$TMP/$pkg.zst")"
  [ "$got" = "$sha256" ] || {
    echo "checksum mismatch for '$pkg': expected $sha256, got $got" >&2; exit 1; }
  mkdir -p "$TMP/$pkg"
  zstd -dc "$TMP/$pkg.zst" | tar -xf - -C "$TMP/$pkg"
done

# File artifacts publish atomically: write beside DEST, rename into place, so
# an interrupted run can't leave a partial file that later guards trust.
publish() {
  mkdir -p "$(dirname "$DEST")"
  PARTIAL="$DEST.partial"
  install -m 0644 "$1" "$PARTIAL"
  mv -f "$PARTIAL" "$DEST"
  PARTIAL=""
}

case "$WHAT" in
  kernel)
    publish "$TMP/virtio-kernel-raw/usr/share/virtio-linux/Image"
    ;;
  rootfs)
    publish "$TMP/microvm-rootfs/usr/share/microvm-rootfs/rootfs.img"
    ;;
  krun)
    # Only the libkrun/libkrunfw libs: the packages' libc closure would shadow
    # the host's via LD_LIBRARY_PATH and break host binaries.
    mkdir -p "$DEST"
    find "$TMP/libkrun/usr/lib" "$TMP/libkrunfw/usr/lib" \
      \( -name 'libkrun*.so*' -o -name 'libkrunfw*.so*' \) \
      -exec cp -P {} "$DEST/" \;
    ;;
esac

echo "fetched $WHAT (pkgs @${COMMIT:0:12}, $MAP_ARCH) -> $DEST"
