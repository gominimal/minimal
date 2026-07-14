#!/bin/sh
# Build the Stage-2 guest initramfs: obtain a static minimald binary and pack it
# as the initramfs `/init` in a newc cpio. The kernel runs `/init` (= minimald)
# as pid-1; minimald mounts the generic guest rootfs (/dev/vda) and chroots into
# it. No minimald is baked into the rootfs.
#
# Set MINIMALD_BIN to an existing static minimald binary to pack it directly and
# skip compilation entirely (TARGET/FEATURES are ignored in this mode). The
# release pipeline uses this to reuse the exact minimald-linux-* binary it ships,
# instead of recompiling a separate one just for the initramfs.
#
# Otherwise minimald is compiled here. Toolchain selection (auto-detected): when
# the host arch matches the target arch and a native static-musl toolchain is
# present (the `*-linux-musl` rustup target plus a matching `*-linux-musl-gcc`
# linker), build natively — same-arch musl needs no container. Otherwise fall
# back to `cross` (Docker) for the musl toolchain. Set FORCE_CROSS=1 to always
# use `cross`.
#
# Set FEATURES to a comma-separated cargo feature list to compile the guest
# minimald with extra features (e.g. FEATURES=networking-proxy,networking-wg for
# the HTTPS reverse proxy and WireGuard mesh peer). Empty by default.
#
# Usage: scripts/build-initramfs.sh <dest-cpio> [rust-target]
set -eu

DEST="${1:?usage: build-initramfs.sh <dest-cpio> [rust-target]}"
TARGET="${2:-aarch64-unknown-linux-musl}"
FEATURES="${FEATURES:-}"
MINIMALD_BIN="${MINIMALD_BIN:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -n "$MINIMALD_BIN" ]; then
  # Prebuilt-binary mode: pack the supplied minimald as /init, no compilation.
  [ -x "$MINIMALD_BIN" ] || { echo "MINIMALD_BIN not an executable file: $MINIMALD_BIN" >&2; exit 1; }
  BIN="$MINIMALD_BIN"
  echo "build-initramfs: packing prebuilt minimald ($BIN)" >&2
else
  # Compile flags shared by both toolchains. The `initramfs` profile drops the
  # release LTO + codegen-units=1 (which the guest binary doesn't need) to
  # compile much faster.
  set -- build -p minimald --profile initramfs --target "$TARGET"
  [ -n "$FEATURES" ] && set -- "$@" --features "$FEATURES"

  HOST_ARCH="$(uname -m)"
  TARGET_ARCH="${TARGET%%-*}"
  MUSL_CC="${TARGET_ARCH}-linux-musl-gcc"

  if [ "${FORCE_CROSS:-0}" != "1" ] \
     && [ "$HOST_ARCH" = "$TARGET_ARCH" ] \
     && rustup target list --installed 2>/dev/null | grep -qx "$TARGET" \
     && command -v "$MUSL_CC" >/dev/null 2>&1; then
    # Native same-arch static-musl build. cargo derives the linker override var
    # from the target triple (uppercased, non-alphanumerics -> `_`); cc-rs (used
    # by ring's build script to compile its C/asm) reads `CC_<triple>` with the
    # triple lower-cased and dashes -> `_`. Set both so the musl toolchain is
    # used for the link *and* for any C compiled into the guest binary.
    LINKER_VAR="CARGO_TARGET_$(echo "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER"
    CC_VAR="CC_$(echo "$TARGET" | tr '-' '_')"
    echo "build-initramfs: native musl build ($TARGET, cc/linker $MUSL_CC)" >&2
    env "$LINKER_VAR=$MUSL_CC" "$CC_VAR=$MUSL_CC" cargo "$@"
  else
    echo "build-initramfs: cross build ($TARGET)" >&2
    command -v cross >/dev/null || cargo install cross --locked
    cross "$@"
  fi
  BIN="$ROOT/target/$TARGET/initramfs/minimald"
  [ -x "$BIN" ] || { echo "minimald not built at $BIN" >&2; exit 1; }
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/dev" "$STAGE/proc" "$STAGE/sys" "$STAGE/newroot"
cp "$BIN" "$STAGE/init"
chmod +x "$STAGE/init"
mkdir -p "$(dirname "$DEST")"
( cd "$STAGE" && find . | cpio -o -H newc ) > "$DEST"
echo "built initramfs -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
