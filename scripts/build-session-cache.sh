#!/usr/bin/env bash
# Build a "seeded cache" ext4 image: a populated minimal cache containing the
# offline-compose closure for the session package set, so a guest minimald can
# compose a session sandbox with no network. minvmd attaches the image as a
# second block device (MINVMD_CACHE_PATH -> /dev/vdb) and minimald mounts it at
# the guest cache dir /run/minimal/cache.
#
# Mirrors scripts/build-initramfs.sh's "produce a guest artifact via Docker on
# macOS" pattern. The closure is built/fetched into an ISOLATED cache (fresh
# $HOME) so the image contains ONLY the closure, then packed with `mkfs.ext4 -d`
# (populates at creation; no loopback / mount needed).
#
# Usage: scripts/build-session-cache.sh <dest-image> [arch]
#   arch defaults to aarch64 (the guest arch). The image is arch-keyed: it must
#   match the guest VM's arch and the project's upstream pin.
set -euo pipefail

DEST="${1:?usage: build-session-cache.sh <dest-image> [arch]}"
ARCH="${2:-aarch64}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Session package set — keep in sync with crates/minimald/src/session_host.rs
# (`with_packages([...])`). These plus their transitive runtime/build deps are
# the offline closure.
PKGS="base bash socat coreutils claude-code"

# Upstream pin the guest projects use; must match .minimal/minimal.toml so the
# seeded built/ SpecHashes match what the guest compose looks up.
PIN="$(sed -n 's/^locked_commit = "\(.*\)"/\1/p' .minimal/minimal.toml | head -1)"
REPO="$(sed -n 's/^repo = "\(.*\)"/\1/p' .minimal/minimal.toml | head -1)"
[ -n "$PIN" ] && [ -n "$REPO" ] || { echo "could not read upstream pin from .minimal/minimal.toml" >&2; exit 1; }

RUST_MUSL="${ARCH}-unknown-linux-musl"
command -v cross >/dev/null || cargo install cross --locked

# 1. Cross-compile a static `minimal` for the container (runs in arm64 Linux).
echo ">> cross build minimal ($RUST_MUSL)"
cross build -p minimal --release --target "$RUST_MUSL"
MIN_BIN="$ROOT/target/$RUST_MUSL/release/minimal"
[ -x "$MIN_BIN" ] || { echo "minimal not built at $MIN_BIN" >&2; exit 1; }

# 2. Throwaway project carrying the upstream pin (minimal needs an upstream to
#    resolve the package names).
PROJ="$(mktemp -d)"
CACHEROOT=""
STAGE=""
trap 'rm -rf "$PROJ" "${CACHEROOT:-}" "${STAGE:-}" 2>/dev/null || true' EXIT
cat > "$PROJ/minimal.toml" <<EOF
[upstream]
repo = "$REPO"
branch = "main"
locked_commit = "$PIN"

[stack]
use = "rust"
EOF

# 3. Build/fetch the closure into an ISOLATED cache (fresh HOME) in a native
#    arm64 container with network. --privileged: sandbox2 needs (nested) userns
#    for any package not already in the remote cache. The bind-mounted HOME
#    captures the populated cache for us.
CACHEROOT="$(mktemp -d)"
# The container platform IS the target arch, so `minimal package` (which has no
# --arch flag) builds for it natively — no cross-arch flag needed.
echo ">> build closure [$PKGS] @ ${PIN:0:7} arch=$ARCH (isolated cache)"
docker run --rm --platform "linux/${ARCH/x86_64/amd64}" --privileged \
  -v "$MIN_BIN:/usr/local/bin/minimal:ro" \
  -v "$PROJ:/proj" \
  -v "$CACHEROOT:/cacheroot" \
  -e HOME=/cacheroot \
  -w /proj \
  debian:stable-slim \
  sh -euc '
    apt-get update -qq && apt-get install -y -qq git ca-certificates e2fsprogs >/dev/null 2>&1
    minimal package '"$PKGS"'
  '

CACHE="$CACHEROOT/.cache/minimal"
[ -d "$CACHE/built" ] || { echo "closure build produced no built/ in $CACHE" >&2; exit 1; }

# 4. Prune the captured cache to the offline-compose set (drop downloads/, idx/,
#    runtime state) and pack it into an ext4 image with mkfs.ext4 -d.
STAGE="$(mktemp -d)"
for d in built vcs lc stdlib; do
  [ -d "$CACHE/$d" ] && cp -a "$CACHE/$d" "$STAGE/$d"
done

SIZE_KB="$(du -sk "$STAGE" | cut -f1)"
IMG_MB=$(( (SIZE_KB / 1024) * 13 / 10 + 64 ))   # +30% slack, 64 MiB floor headroom
echo ">> packing ext4 (${IMG_MB} MiB) from $(du -sh "$STAGE" | cut -f1) staged cache"
mkdir -p "$(dirname "$DEST")"
rm -f "$DEST"
IMG_NAME="$(basename "$DEST")"
# Make an empty ext4, then loop-mount and `cp -a` the staged cache in: the
# kernel ext4 driver reproduces symlinks, hardlinks, and xattrs faithfully,
# unlike `mkfs.ext4 -d` populate-mode (which chokes on package-file xattrs).
# Native arm64 (avoid qemu-emulated mkfs segfaults); --privileged for loop mount.
docker run --rm --platform linux/arm64 --privileged \
  -v "$STAGE:/stage:ro" -v "$(dirname "$DEST"):/out" \
  debian:stable-slim \
  sh -euc '
    apt-get update -qq && apt-get install -y -qq e2fsprogs >/dev/null 2>&1
    truncate -s '"${IMG_MB}"'M "/out/'"$IMG_NAME"'"
    mkfs.ext4 -q -F "/out/'"$IMG_NAME"'"
    mkdir -p /mnt/img
    mount -o loop "/out/'"$IMG_NAME"'" /mnt/img
    cp -a /stage/. /mnt/img/
    sync
    umount /mnt/img
    echo "=== validate: built/ + vcs/state.json present ==="
    mount -o loop,ro "/out/'"$IMG_NAME"'" /mnt/img
    ls /mnt/img/built | head -3
    test -f /mnt/img/vcs/state.json && echo "VCS_STATE_OK"
    umount /mnt/img
  '

echo "built session cache -> $DEST ($(du -h "$DEST" | cut -f1))"
