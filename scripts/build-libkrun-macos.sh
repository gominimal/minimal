#!/usr/bin/env bash
# Build the trimmed libkrun.dylib for macOS from source, at the commit pinned
# in vendor/libkrun/libkrun.lock, and stage it into PREFIX. This is the ONE
# libkrun macOS CI links/boots against and the release ships — CI exercises
# the exact dylib users receive, and no third-party bottle (the old slp/krun
# Homebrew tap) is in the supply chain.
#
# Trimmed build (this is exactly the Makefile's INIT_BLOB=0 config):
#   -p libkrun            scope to the libkrun crate, so the src/input &
#                         src/display workspace members (whose bindgen build
#                         scripts need libclang) are never built.
#   --no-default-features drop `init-blob`, whose build script cross-compiles
#                         a Linux init — the ONLY reason the Makefile needs
#                         lld + a Debian sysroot. minvmd supplies its own
#                         initramfs, so libkrun's bundled init is unused.
#   --features blk,net    blk = rootfs disk (krun_add_disk2/3), net =
#                         virtio-net. No gpu => no libepoxy/virglrenderer.
#                         Hypervisor.framework is linked by src/vmm/build.rs.
#
# The staged dylib's install name is set to @rpath/libkrun.1.dylib so anything
# linking it (minvmd) records a relocatable load command from the start — the
# shipped bin/../lib layout then needs only an rpath, not a load-command
# rewrite. Ad-hoc signed (arm64 macOS refuses to load an invalid signature);
# the release pipeline re-signs with Developer ID before shipping.
#
# Stages:
#   PREFIX/libkrun.1.dylib   the dylib (dyld resolves @rpath/libkrun.1.dylib)
#   PREFIX/libkrun.dylib     symlink for the build-time linker (-l krun)
#
# Requires: git, a Rust toolchain, Xcode CLT (codesign/otool/install_name_tool).
#
# Usage: scripts/build-libkrun-macos.sh <prefix-dir>
set -euo pipefail

PREFIX="${1:?usage: build-libkrun-macos.sh <prefix-dir>}"

case "$(uname -s)" in
  Darwin) ;;
  *) echo "build-libkrun-macos.sh is macOS-only (got $(uname -s))" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCK="$ROOT/vendor/libkrun/libkrun.lock"
VERSION="$(sed -n 's/^version=//p' "$LOCK")"
COMMIT="$(sed -n 's/^commit=//p' "$LOCK")"
if [ -z "$VERSION" ] || [ -z "$COMMIT" ]; then
  echo "::error::malformed $LOCK: need version= and commit= lines" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Fetch the pinned commit directly (not the tag): a moved or deleted tag can
# never change what we build, and GitHub serves arbitrary-sha fetches.
echo "fetching containers/libkrun @ $COMMIT ($VERSION)"
git -C "$WORK" init -q
git -C "$WORK" remote add origin https://github.com/containers/libkrun
git -C "$WORK" fetch -q --depth 1 origin "$COMMIT"
git -C "$WORK" checkout -q FETCH_HEAD
actual="$(git -C "$WORK" rev-parse HEAD)"
if [ "$actual" != "$COMMIT" ]; then
  echo "::error::fetched libkrun HEAD $actual != pinned commit $COMMIT" >&2
  exit 1
fi

echo "building trimmed libkrun (blk,net; no gpu, no init-blob)"
cargo build --release -p libkrun --no-default-features --features blk,net \
  --manifest-path "$WORK/Cargo.toml"
DYLIB="$WORK/target/release/libkrun.dylib"
test -f "$DYLIB" || { echo "::error::build produced no $DYLIB" >&2; exit 1; }

# A trimmed build must link only system libraries. Any /opt/homebrew or
# /usr/local reference means a dependency leaked (e.g. a stray GPU lib) and
# the dylib would fail to load on a machine without Homebrew.
otool -L "$DYLIB"
if otool -L "$DYLIB" | grep -E '/opt/homebrew|/usr/local'; then
  echo "::error::trimmed libkrun links a non-system dylib; see otool -L above" >&2
  exit 1
fi

# krun_add_disk3 (the /dev/vdb attach) needs libkrun >= 1.19.0 — assert the
# pin never silently regresses below the API surface minvmd uses.
if ! nm -gU "$DYLIB" | grep -q '_krun_add_disk3'; then
  echo "::error::built libkrun lacks krun_add_disk3 (need >= 1.19.0); check the pin in $LOCK" >&2
  exit 1
fi

# Relocatable install name + a valid (ad-hoc) signature, then stage.
install_name_tool -id @rpath/libkrun.1.dylib "$DYLIB"
codesign --sign - --force "$DYLIB"

mkdir -p "$PREFIX"
cp "$DYLIB" "$PREFIX/libkrun.1.dylib"
ln -sfn libkrun.1.dylib "$PREFIX/libkrun.dylib"
echo "staged libkrun $VERSION ($COMMIT) -> $PREFIX"
