#!/usr/bin/env bash
# Provide the pinned gvproxy (gvisor-tap-vsock) switch binary and verify its
# SHA-256 against vendor/gvproxy/gvproxy.lock. minimald spawns this binary as
# the per-host switch.
#
# The switch is built from the pinned source plus vendor/gvproxy/patches/ by
# scripts/build-gvproxy.sh, not downloaded: the upstream release leaves a
# withdrawn port's accepted connections open. The build is reproducible, so
# its result must match the lock's digest for the asset.
#
# The asset defaults to the host platform's binary; pass an explicit asset name
# (2nd arg) to build a different platform's binary regardless of the host arch —
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
# after the lock moves, the copy an earlier run left behind is built again
# rather than run as if it were the new pin.
if [ -x "$out" ] && [ "$(sha256_of "$out")" = "$want" ]; then
  echo "fetch-gvproxy: ${asset} ${ver} already at ${out}"
  exit 0
fi

echo "fetch-gvproxy: building ${asset} ${ver} from the pinned source"
# Built beside the destination and renamed over it, so a switch still running
# from the old copy keeps its own file.
tmp="${out}.fetch.$$"
trap 'rm -f "$tmp"' EXIT
"${here}/build-gvproxy.sh" "$tmp" "$asset"

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
