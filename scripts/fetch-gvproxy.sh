#!/usr/bin/env bash
# Download the pinned gvproxy (gvisor-tap-vsock) release binary for the host
# platform and verify its SHA-256 against vendor/gvproxy/gvproxy.lock.
# No build, no Go toolchain. minimald spawns this binary as the per-host switch.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="${here}/../vendor/gvproxy/gvproxy.lock"
out="${1:-./gvproxy}"

ver="$(sed -n 's/^version=//p' "$lock")"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)  asset=gvproxy-linux-amd64 ;;
  Linux-aarch64) asset=gvproxy-linux-arm64 ;;
  Darwin-*)      asset=gvproxy-darwin ;;
  *) echo "fetch-gvproxy: unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
want="$(sed -n "s/^${asset}=//p" "$lock")"
[ -n "$want" ] || { echo "fetch-gvproxy: no pinned digest for ${asset}" >&2; exit 1; }

url="https://github.com/containers/gvisor-tap-vsock/releases/download/${ver}/${asset}"
echo "fetch-gvproxy: downloading ${url}"
curl -fsSL "$url" -o "$out"

if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$out" | awk '{print $1}')"
else
  got="$(shasum -a 256 "$out" | awk '{print $1}')"
fi
if [ "$got" != "$want" ]; then
  echo "fetch-gvproxy: SHA-256 mismatch for ${asset}" >&2
  echo "  got:  ${got}" >&2
  echo "  want: ${want}" >&2
  rm -f "$out"; exit 1
fi
chmod +x "$out"
echo "fetch-gvproxy: ${asset} ${ver} verified (${got})"
