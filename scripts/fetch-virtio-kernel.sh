#!/bin/sh
# Fetch the virtio-linux kernel (vmlinuz / Image.gz) from the minimal build
# cache. Pulls the prebuilt artifact from the public `minimal-staging-cache`
# via the promoted Linux `minimal` CLI (gs://minimal-shim) — no kernel build,
# no GCS credentials (the cache is public-read). The packaging `minimal` CLI is
# Linux-only, so this runs on a Linux runner and hands the kernel to the macOS
# boot job.
#
# Usage: scripts/fetch-virtio-kernel.sh <dest-vmlinuz-path> [arch]
#   arch defaults to aarch64 (the self-hosted macOS CI runner is Apple Silicon).
# Requires: Linux host with git, curl, ca-certificates, tar, zstd.
set -eu

DEST="${1:?usage: fetch-virtio-kernel.sh <dest-vmlinuz-path> [arch]}"
ARCH="${2:-aarch64}"
GCS_SHIM="https://storage.googleapis.com/minimal-shim"

# The CLI binary itself must match the runner's OS/arch; the kernel it pulls is
# selected separately via `--arch` below.
case "$(uname -m)" in
  x86_64 | amd64) CLI_PLATFORM="amd64-linux" ;;
  aarch64 | arm64) CLI_PLATFORM="arm64-linux" ;;
  *) echo "unsupported runner arch: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

CLI_SHA="$(curl -fsS "$GCS_SHIM/config/cli-${CLI_PLATFORM}.json" \
  | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$CLI_SHA" ] || { echo "could not resolve promoted CLI version for $CLI_PLATFORM" >&2; exit 1; }
echo "minimal CLI: ${CLI_PLATFORM} @ ${CLI_SHA}"

curl -fsS "$GCS_SHIM/archives/cli-${CLI_PLATFORM}-${CLI_SHA}.tar.zst" -o "$TMP/cli.tar.zst"
mkdir -p "$TMP/cli"
tar --zstd -xf "$TMP/cli.tar.zst" -C "$TMP/cli"
MINIMAL="$TMP/cli/bin/minimal"
chmod +x "$MINIMAL"

# Scratch project: upstream pkgs + a raw-file output that extracts the kernel
# from the virtio-linux package's outputs.
mkdir -p "$TMP/proj/.minimal"
cat > "$TMP/proj/.minimal/minimal.toml" <<'TOML'
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"

[stack]
use = "rust"

[outputs.virtio-kernel]
type = "raw-file"
packages = ["virtio-linux"]
path = "usr/share/virtio-linux/vmlinuz"
TOML

cd "$TMP/proj"
"$MINIMAL" update
mkdir -p "$(dirname "$DEST")"
"$MINIMAL" materialize --output "$DEST" --arch "$ARCH" virtio-kernel
echo "fetched kernel -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
