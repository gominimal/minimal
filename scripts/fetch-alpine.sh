#!/usr/bin/env bash
# fetch-alpine.sh — stage a pinned Alpine minirootfs for minvmd.
#
# Downloads the upstream Alpine minirootfs tarball for the host arch,
# verifies it against a pinned sha256, and extracts it to
# `${MINVMD_ROOTFS_CACHE:-~/.cache/minimal/minvmd/rootfs}/<version>/<arch>/`.
#
# Idempotent: a `.sha256.ok` marker is written on first successful extract;
# re-running detects the marker and skips re-download + re-extract.
#
# After a successful run, export:
#
#   export MINVMD_ROOTFS_PATH="$(scripts/fetch-alpine.sh --print-path)"
#
# To bump the pinned Alpine version, update ALPINE_VERSION and the per-arch
# SHA256 constants below; both are published at
# https://dl-cdn.alpinelinux.org/alpine/v<MAJOR.MINOR>/releases/<arch>/

set -euo pipefail

ALPINE_VERSION="3.21.7"
ALPINE_MAJOR_MINOR="${ALPINE_VERSION%.*}"

# sha256 of alpine-minirootfs-${ALPINE_VERSION}-<arch>.tar.gz from
# https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MAJOR_MINOR}/releases/<arch>/
# Plain vars + a case lookup (below) instead of an associative array so the
# script runs under macOS's system bash 3.2 (declare -A needs bash 4+).
PINNED_SHA256_aarch64="d1d1a3fae5f4d6146e9742790a47fcb116199622cfb8439f218a4d5fbe5000da"
PINNED_SHA256_x86_64="8cba1ea3e8b500ea986a313d8eecf3d5952a2a0d23a69117bb81c023d9ceac05"

print_path_only=0
if [[ "${1:-}" == "--print-path" ]]; then
    print_path_only=1
fi

case "$(uname -m)" in
    arm64 | aarch64) arch="aarch64"; expected_sha="$PINNED_SHA256_aarch64" ;;
    x86_64 | amd64) arch="x86_64"; expected_sha="$PINNED_SHA256_x86_64" ;;
    *) echo "fetch-alpine.sh: unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

cache_root="${MINVMD_ROOTFS_CACHE:-$HOME/.cache/minimal/minvmd/rootfs}"
arch_root="$cache_root/$ALPINE_VERSION/$arch"
marker="$arch_root/.sha256.ok"

if [[ "$print_path_only" -eq 1 ]]; then
    echo "$arch_root"
    exit 0
fi

if [[ -f "$marker" ]] && [[ "$(cat "$marker")" == "$expected_sha" ]]; then
    echo "fetch-alpine.sh: cache hit at $arch_root (sha256 matches)" >&2
    exit 0
fi

tarball="alpine-minirootfs-${ALPINE_VERSION}-${arch}.tar.gz"
url="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_MAJOR_MINOR}/releases/${arch}/${tarball}"

mkdir -p "$arch_root"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "fetch-alpine.sh: downloading $url" >&2
curl -fsSL "$url" -o "$tmpdir/$tarball"

actual_sha="$(shasum -a 256 "$tmpdir/$tarball" | awk '{print $1}')"
if [[ "$actual_sha" != "$expected_sha" ]]; then
    echo "fetch-alpine.sh: sha256 mismatch for $tarball" >&2
    echo "  expected: $expected_sha" >&2
    echo "  actual:   $actual_sha" >&2
    exit 1
fi

# Wipe a stale partial extract before re-populating.
if [[ -d "$arch_root" ]]; then
    find "$arch_root" -mindepth 1 -delete
fi
tar -xzf "$tmpdir/$tarball" -C "$arch_root"
echo "$expected_sha" > "$marker"

echo "fetch-alpine.sh: extracted Alpine ${ALPINE_VERSION} (${arch}) to $arch_root" >&2
