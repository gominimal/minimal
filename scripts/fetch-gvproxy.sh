#!/usr/bin/env bash
# Download the pinned gvproxy (gvisor-tap-vsock) release binary and verify its
# SHA-256 against vendor/gvproxy/gvproxy.lock. No build, no Go toolchain.
# minimald spawns this binary as the per-host switch.
#
# The asset defaults to the host platform's binary; pass an explicit asset name
# (2nd arg) to fetch a different platform's binary regardless of the host arch —
# the release job uses this to pack every platform's gvproxy from one runner.
#
# Usage: scripts/fetch-gvproxy.sh [dest-path] [asset]
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="${here}/../vendor/gvproxy/gvproxy.lock"
out="${1:-./gvproxy}"
asset="${2:-}"

ver="$(sed -n 's/^version=//p' "$lock")"
if [ -z "$asset" ]; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  asset=gvproxy-linux-amd64 ;;
    Linux-aarch64) asset=gvproxy-linux-arm64 ;;
    Darwin-*)      asset=gvproxy-darwin ;;
    *) echo "fetch-gvproxy: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
  esac
fi
want="$(sed -n "s/^${asset}=//p" "$lock")"
[ -n "$want" ] || { echo "fetch-gvproxy: no pinned digest for ${asset}" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# A binary already at the destination is kept only while it is the pinned one:
# after the lock moves, the copy an earlier run left behind is fetched again
# rather than run as if it were the new pin.
if [ -x "$out" ] && [ "$(sha256_of "$out")" = "$want" ]; then
  echo "fetch-gvproxy: ${asset} ${ver} already at ${out}"
  exit 0
fi

url="https://github.com/containers/gvisor-tap-vsock/releases/download/${ver}/${asset}"
echo "fetch-gvproxy: downloading ${url}"
# Fetched beside the destination and renamed over it, so a switch still running
# from the old copy keeps its own file.
tmp="${out}.fetch.$$"
trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"

got="$(sha256_of "$tmp")"
if [ "$got" != "$want" ]; then
  echo "fetch-gvproxy: SHA-256 mismatch for ${asset}" >&2
  echo "  got:  ${got}" >&2
  echo "  want: ${want}" >&2
  exit 1
fi
chmod +x "$tmp"
mv -f "$tmp" "$out"
echo "fetch-gvproxy: ${asset} ${ver} verified (${got})"
