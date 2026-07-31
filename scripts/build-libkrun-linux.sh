#!/usr/bin/env bash
# Build a STATIC libkrun (libkrun.a) for musl from source, at the commit pinned
# in vendor/libkrun/libkrun.lock plus every patch in vendor/libkrun/patches/,
# and stage it into PREFIX. The Linux twin of build-libkrun-macos.sh: same pin,
# same patch series, same trim — a different link model.
#
# Why static, and why this exists at all: minvmd is the only one of the four
# binaries that cannot ship to Linux users today, because it links libkrun.so
# and dlopens libkrunfw.so.5. Shipping that means ~29 MB of libraries plus
# RUNPATH machinery, a bin/lib sibling constraint, and a glibc floor on users'
# disks. Linked statically into a musl binary, minvmd becomes self-contained
# like min/mip/minimald — see gominimal/minimal#1065.
#
# libkrunfw is NOT needed and is deliberately absent. It exists only to carry a
# bundled guest kernel, which minvmd never uses (it supplies its own via
# ctx.set_kernel). That matters twice over here: a static musl binary CANNOT
# dlopen at all, so a real libkrunfw dependency would be fatal rather than
# merely wasteful; and dropping it removes a GPL-2 kernel blob from the shipped
# closure.
#
# Trimmed build (identical to the macOS script's, and to the Makefile's
# INIT_BLOB=0 config):
#   -p libkrun            scope to the libkrun crate, so the src/input &
#                         src/display workspace members (whose bindgen build
#                         scripts need libclang) are never built.
#   --no-default-features drop `init-blob`, whose build script cross-compiles a
#                         Linux init. minvmd supplies its own initramfs.
#   --features blk,net    blk = rootfs disk (krun_add_disk2/3), net =
#                         virtio-net. No gpu => no libepoxy/virglrenderer. The
#                         KVM backend is linked by src/vmm/build.rs.
#
# Usage: scripts/build-libkrun-linux.sh <prefix-dir> [target-triple]
# Requires: git, a Rust toolchain with the musl target, musl-gcc, GNU binutils
# (ld, nm, objcopy, ar). Cross-building additionally needs target-prefixed
# binutils (<arch>-linux-musl-* or <arch>-linux-gnu-*); the archive rewrite
# below refuses to run the host's on foreign objects.
set -euo pipefail

PREFIX="${1:?usage: build-libkrun-linux.sh <prefix-dir> [target-triple]}"

case "$(uname -s)" in
  Linux) ;;
  *) echo "build-libkrun-linux.sh is Linux-only (got $(uname -s))" >&2; exit 1 ;;
esac

# Default to this host's musl triple. CI passes the target explicitly, but
# still builds each arch on its own runner (amd64 on ubuntu-latest, arm64 on
# ubuntu-*-arm), so those runs are native. A genuine cross-build works only
# with target binutils installed — see the archive-rewrite section.
case "${2:-}" in
  "") case "$(uname -m)" in
        x86_64)  TARGET=x86_64-unknown-linux-musl ;;
        aarch64) TARGET=aarch64-unknown-linux-musl ;;
        *) echo "unsupported host arch $(uname -m); pass a target triple" >&2; exit 1 ;;
      esac ;;
  *) TARGET="$2" ;;
esac

case "$TARGET" in
  *-linux-musl) ;;
  *) echo "::error::target '$TARGET' is not a musl triple; this script builds the static musl libkrun" >&2; exit 1 ;;
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

# Apply the carried patches, in sorted order, on top of the verified commit.
# `git apply` exits non-zero on any rejected hunk and, without --reject, leaves
# the tree untouched — so a stale patch aborts the build instead of silently
# producing an unpatched archive.
PATCHES="$ROOT/vendor/libkrun/patches"
if [ -d "$PATCHES" ]; then
  for patch in "$PATCHES"/*.patch; do
    [ -e "$patch" ] || continue
    echo "applying $(basename "$patch")"
    if ! git -C "$WORK" apply --verbose "$patch"; then
      echo "::error::$(basename "$patch") does not apply to libkrun $COMMIT ($VERSION); rebase or drop it" >&2
      exit 1
    fi
  done
fi

# Upstream declares crate-type = ["cdylib", "lib"], so cargo emits no
# libkrun.a to link. Add `staticlib`. Done here rather than as a carried
# .patch because it is not an upstream fix — it is a property of how WE
# consume the crate, and a context-free sed survives a pin bump that would
# reject a line-anchored patch.
#
# `cdylib` stays in the list but is inert: musl targets are crt-static, so
# cargo produces no shared object for them.
LIBTOML="$WORK/src/libkrun/Cargo.toml"
grep -q '^crate-type = \["cdylib", "lib"\]$' "$LIBTOML" || {
  echo "::error::unexpected crate-type in $LIBTOML; the staticlib edit needs rebasing:" >&2
  grep -n 'crate-type' "$LIBTOML" >&2
  exit 1
}
sed -i 's/^crate-type = \["cdylib", "lib"\]$/crate-type = ["cdylib", "staticlib", "lib"]/' "$LIBTOML"

# Cross-linking to musl needs musl-gcc as the linker. A musl-native host (Alpine)
# builds its own triple and needs nothing; a glibc host with musl-tools does.
# Default it here — cargo's documented env form of `[target.<triple>] linker`,
# triple uppercased with dashes as underscores — so a standalone run works
# without the caller knowing. An explicit value always wins.
LINKER_VAR="CARGO_TARGET_$(printf '%s' "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER"
# `printenv`, not `eval` and not bash's ${!VAR}: the name is derived from
# $TARGET, which is only suffix-validated, so `eval` would re-parse
# caller-controlled text as shell syntax. `printenv` reads the variable without
# a second round of expansion, and unlike ${!VAR} it is not a bashism (a lone
# one here once made `sh scripts/build-libkrun-linux.sh` die with "bad
# substitution" on ash/dash). Absent variable => empty, hence the `|| true`.
linker_set="$(printenv "$LINKER_VAR" 2>/dev/null || true)"
if [ -z "$linker_set" ] && [ "$TARGET" != "$(rustc -vV | sed -n 's/^host: //p')" ]; then
  command -v musl-gcc >/dev/null || {
    echo "::error::$TARGET is not the host triple and musl-gcc is not installed (apt install musl-tools)" >&2
    exit 1
  }
  export "$LINKER_VAR=musl-gcc"
fi

echo "building static libkrun for $TARGET (blk,net; no gpu, no init-blob, no libkrunfw)"
# `cd "$WORK"` rather than --manifest-path: cargo resolves .cargo/config.toml
# from the CURRENT DIRECTORY, not from the manifest's directory. libkrun ships
# one, and at this pin it carries
#     [target.'cfg(target_env = "musl")']
#     rustflags = ["--cfg", "musl_v1_2_3"]
# which is load-bearing for a musl build. Running from the minimal repo root
# with --manifest-path (as build-libkrun-macos.sh used to) silently drops it.
#
# But rustup resolves rust-toolchain.toml from the CWD too, and leaving the repo
# would silently fall back to the DEFAULT toolchain — which is not the pinned
# one and, in CI, is not the toolchain `rustup target add` installed the musl
# target into (the build then dies with "can't find crate for `core`"). So
# resolve the pin HERE, where rust-toolchain.toml still applies, and carry it
# across the cd.
#
# This is a correctness requirement, not just convenience: libkrun.a is a Rust
# staticlib linked into a Rust binary, and Rust has no stable ABI. libkrun and
# minvmd must come out of the same rustc.
if command -v rustup >/dev/null 2>&1; then
  RUSTUP_TOOLCHAIN="$(cd "$ROOT" && rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)"
  [ -n "$RUSTUP_TOOLCHAIN" ] && export RUSTUP_TOOLCHAIN
  echo "building with toolchain ${RUSTUP_TOOLCHAIN:-<rustup default>}"
fi

# --locked: build exactly upstream's committed Cargo.lock — a silent re-resolve
# would undermine the pinned, reproducible-build guarantee.
(
  cd "$WORK"
  cargo build --release --locked --target "$TARGET" \
    -p libkrun --no-default-features --features blk,net
)

RAW="$WORK/target/$TARGET/release/libkrun.a"
test -f "$RAW" || { echo "::error::build produced no $RAW" >&2; exit 1; }

# --- Merge, then localize ------------------------------------------------
#
# libkrun.a carries libkrun plus its whole Rust dependency closure, including a
# copy of libstd. Linked as-is into minvmd — itself a Rust binary with its own
# libstd — the duplicate symbols collide. The fix is to reduce the archive to a
# single object that exports only libkrun's C API.
#
# ORDER IS LOAD-BEARING. objcopy over an archive rewrites each member
# independently, so a symbol defined in one member and referenced by another
# gets localized in the definition and becomes unresolvable from the reference.
# Merging first with `ld -r` makes every such reference intra-object, after
# which localization is safe.
# Binutils must match the TARGET's architecture, not the host's. Building
# natively (what CI does: an x86_64 runner for amd64, an arm64 runner for arm64)
# the plain names are correct. Cross-building, they are not: the host `ld -r`
# cannot merge objects of a foreign architecture, and the failure surfaces deep
# in the merge as "file format not recognized" rather than as the unsupported
# configuration it is. Prefer a target-prefixed toolchain when the arches
# differ, and say so plainly when none is installed.
TARGET_ARCH_BU="${TARGET%%-*}"
HOST_ARCH_BU="$(uname -m)"
BU_PREFIX=""
if [ "$TARGET_ARCH_BU" != "$HOST_ARCH_BU" ]; then
  for candidate in "${TARGET_ARCH_BU}-linux-musl-" "${TARGET_ARCH_BU}-linux-gnu-"; do
    if command -v "${candidate}ld" >/dev/null 2>&1; then
      BU_PREFIX="$candidate"
      break
    fi
  done
  [ -n "$BU_PREFIX" ] || {
    echo "::error::cross-building $TARGET on $HOST_ARCH_BU needs target binutils, but neither ${TARGET_ARCH_BU}-linux-musl-ld nor ${TARGET_ARCH_BU}-linux-gnu-ld is installed. Build $TARGET on a $TARGET_ARCH_BU host, or install the cross binutils." >&2
    exit 1
  }
  echo "cross-build: using ${BU_PREFIX}* binutils"
fi

echo "merging archive members into one relocatable object"
"${BU_PREFIX}ld" -r --whole-archive "$RAW" -o "$WORK/libkrun-merged.o"

# Keep exactly the public C API global; localize everything else. Derived from
# the object rather than hardcoded, so a pin that adds or removes an entry
# point needs no edit here.
# `{ grep || true; }`: grep exits 1 when nothing matches, and under `pipefail`
# that aborts the script right here — so the explanatory error below would never
# print and a symbol-free merge would fail with no diagnostic at all. Tolerate
# the no-match status and let the count check report it.
"${BU_PREFIX}nm" -g --defined-only "$WORK/libkrun-merged.o" \
  | awk '{print $NF}' | { grep '^krun_' || true; } | sort -u > "$WORK/keep.syms"
count="$(wc -l < "$WORK/keep.syms" | tr -d ' ')"
[ "$count" -gt 0 ] || { echo "::error::no krun_* symbols found in the merged object" >&2; exit 1; }
echo "keeping $count krun_* symbols global, localizing the rest"

"${BU_PREFIX}objcopy" --keep-global-symbols="$WORK/keep.syms" \
  "$WORK/libkrun-merged.o" "$WORK/libkrun-local.o"

rm -f "$WORK/libkrun.a"
"${BU_PREFIX}ar" crs "$WORK/libkrun.a" "$WORK/libkrun-local.o"

# Dump the final symbol table ONCE and assert against the file, never against a
# live pipe: under `set -o pipefail` a `grep -q` that exits on its first match
# SIGPIPEs `nm` mid-write, and the non-zero producer fails the whole pipeline —
# so a passing assertion reads as a failing one.
"${BU_PREFIX}nm" -g --defined-only "$WORK/libkrun.a" > "$WORK/final.syms"

# krun_add_disk3 (the /dev/vdb attach) needs libkrun >= 1.19.0 — assert the pin
# never silently regresses below the API surface minvmd uses. Mirrors the same
# check in build-libkrun-macos.sh and the setup-libkrun-linux composite.
if ! grep -q ' T krun_add_disk3$' "$WORK/final.syms"; then
  echo "::error::built libkrun lacks krun_add_disk3 (need >= 1.19.0); check the pin in $LOCK" >&2
  exit 1
fi

# Nothing outside the C API may still be global, or the symbol collision this
# whole pass exists to prevent is still live. Text/data/bss globals only
# (lowercase codes are already local, `U` is an undefined import).
leaked="$(awk '$2 ~ /^[A-TV-Z]$/ {print $NF}' "$WORK/final.syms" | grep -v '^krun_' | head -5 || true)"
if [ -n "$leaked" ]; then
  echo "::error::symbols outside the krun_* API are still global after localization:" >&2
  echo "$leaked" >&2
  exit 1
fi

# The other half of the isolation, and the one that is easy to lose silently:
# nothing Rust may be left UNDEFINED either. libkrun.a carries its own copy of
# libstd; if any Rust symbol is undefined here, the final link resolves it
# against MINVMD's libstd instead, coalescing two independent Rust runtimes
# into one binary — the fragility this pass is meant to rule out. A clean
# archive imports only C: musl libc plus the `_Unwind_*` ABI, which is shared
# on purpose (one unwinder per process is correct; two would be the bug).
#
# This is asserted rather than assumed because the failure is invisible at
# build time and only surfaces at VM boot, and because `ld -r` +
# `objcopy --keep-global-symbols` is binutils behaviour, not a stability
# contract — a toolchain upgrade is the plausible way it regresses.
"${BU_PREFIX}nm" -u "$WORK/libkrun.a" > "$WORK/undef.syms"
rust_undef="$(awk '{print $NF}' "$WORK/undef.syms" \
  | { grep -E '^(_ZN|_R[a-zA-Z0-9]|__rust|rust_eh_personality)' || true; } | head -5)"
if [ -n "$rust_undef" ]; then
  echo "::error::libkrun.a leaves Rust symbols undefined, so its libstd would coalesce with minvmd's:" >&2
  echo "$rust_undef" >&2
  exit 1
fi

mkdir -p "$PREFIX"
cp "$WORK/libkrun.a" "$PREFIX/libkrun.a"
echo "staged static libkrun $VERSION ($COMMIT, $TARGET) -> $PREFIX/libkrun.a"
