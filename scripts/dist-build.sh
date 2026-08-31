#!/usr/bin/env bash
#
# dist-build.sh — THE single build entrypoint for a shippable build.
#
# One command produces what the packaging files (AUR, Homebrew, nfpm) ship:
# the four release binaries for a target triple, built exactly the way the
# release workflow builds them (the build-release-linux-* jobs in
# .github/workflows/release.yml call this script, so CI builds == downstream
# builds), plus shell completions generated from the built `min`.
#
# Build shape (extracted from those jobs; do not recollapse without cutting
# the release profile's link-time memory first):
#   - ONE cargo invocation per package (mip, minimal, minimald, minvmd), not
#     one combined build. `[profile.release]` is fat LTO with
#     codegen-units = 1, so a combined build lets cargo schedule all the final
#     LTO links concurrently — the peak that SIGTERMed the arm64 release job
#     (exit 143). Sequential invocations share dependency artifacts through
#     the same target/ dir, so the cost is a few graph resolutions, not
#     several builds, while the LTO links run one at a time.
#   - `minvmd` is built in its OWN invocation, after the rest: `min` depends
#     on the minvmd crate with default-features = false, and one combined
#     invocation would unify the `libkrun` feature into the CLI's copy.
#
# Env knobs (the target triple is the single positional argument):
#   FEATURES        Comma-separated cargo features for the guest minimald,
#                   the same convention as scripts/build-initramfs.sh. Empty
#                   by default; the shipped release build passes none.
#   LIBKRUN_PREFIX  Prefix holding libkrun, consumed by crates/minvmd/build.rs.
#                   REQUIRED for *-linux-musl targets: it must contain
#                   libkrun.a (build it with scripts/build-libkrun-linux.sh).
#                   A default-features minvmd REQUESTS the KVM backend, and
#                   without libkrun build.rs silently compiles a STUB that
#                   compiles, links, and then bails at VM boot — so this
#                   script fails loudly instead of shipping one. For
#                   *-linux-gnu targets it is optional: when unset, build.rs
#                   scans the standard library dirs, and a miss is still a
#                   build error (MINVMD_REQUIRE_LIBKRUN=1), never a stub.
#   COMPLETIONS_DIR Where the generated completions are written (default:
#                   .scratch/dist-completions). Generated only when the
#                   target's OS+arch runs on this host — a cross-built `min`
#                   cannot execute to emit its own completions.
#
# Usage: scripts/dist-build.sh <target-triple>
#   e.g. scripts/dist-build.sh x86_64-unknown-linux-musl
#
# Requires: cargo with the repo's pinned toolchain, and for a non-host musl
# triple the musl-gcc linker (apt install musl-tools) — defaulted here the
# same way release.yml's build jobs set it at the job level.
#
set -euo pipefail

die() {
    printf 'dist-build: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

case "${1:-}" in
    -h|--help) usage 0 ;;
esac
[ "$#" -ge 1 ] || die "missing target triple (usage: dist-build.sh <target-triple>)"
TARGET="$1"
[ "$#" -le 1 ] || die "unexpected argument: $2 (usage: dist-build.sh <target-triple>)"

FEATURES="${FEATURES:-}"
LIBKRUN_PREFIX="${LIBKRUN_PREFIX:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
COMPLETIONS_DIR="${COMPLETIONS_DIR:-$ROOT/.scratch/dist-completions}"
BIN_DIR="$ROOT/target/$TARGET/release"
cd "$ROOT"

# musl cross-linking needs musl-gcc as the linker. Cargo's documented env form
# of the `[target.<triple>] linker` config key (triple uppercased, dashes to
# underscores); set here rather than appended to .cargo/config.toml so the
# build never mutates the checkout. An explicit value always wins — that is
# how release.yml's jobs pin it at the job level.
case "$TARGET" in
    *-linux-musl)
        LINKER_VAR="CARGO_TARGET_$(printf '%s' "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER"
        linker_set="$(printenv "$LINKER_VAR" 2>/dev/null || true)"
        if [ -z "$linker_set" ] && [ "$TARGET" != "$(rustc -vV | sed -n 's/^host: //p')" ]; then
            command -v musl-gcc >/dev/null || die "$TARGET is not the host triple and musl-gcc is not installed (apt install musl-tools)"
            export "$LINKER_VAR=musl-gcc"
        fi
        ;;
esac

# One invocation per package — see the header for why the fat-LTO links must
# serialize and why minvmd never shares an invocation with the rest.
cargo build --release --locked --target "$TARGET" --package mip
cargo build --release --locked --target "$TARGET" --package minimal

# The guest minimald takes its cargo features from FEATURES (see
# scripts/build-initramfs.sh); empty means the shipped default.
if [ -n "$FEATURES" ]; then
    echo "dist-build: minimald features: $FEATURES"
    cargo build --release --locked --target "$TARGET" --package minimald --features "$FEATURES"
else
    cargo build --release --locked --target "$TARGET" --package minimald
fi

# minvmd: demand the KVM backend its default features request, per link model.
case "$TARGET" in
    *-linux-musl)
        # The shipped model: the static archive, no rpath, one self-contained
        # binary. Check before the build so a missing archive fails here with
        # the fix named, instead of after the whole dependency tree compiles.
        [ -n "$LIBKRUN_PREFIX" ] || die "minvmd for a musl target needs a static libkrun.a: build it with scripts/build-libkrun-linux.sh <prefix> $TARGET and set LIBKRUN_PREFIX=<prefix>"
        [ -f "$LIBKRUN_PREFIX/libkrun.a" ] || die "LIBKRUN_PREFIX=$LIBKRUN_PREFIX has no libkrun.a (build it with scripts/build-libkrun-linux.sh; see the LIBKRUN_PREFIX section of this header)"
        # MINVMD_REQUIRE_LIBKRUN=static re-proves the static link inside
        # build.rs, so a regression there is a build error, not a stub.
        MINVMD_REQUIRE_LIBKRUN=static cargo build --release --locked --target "$TARGET" --package minvmd --bin minvmd
        ;;
    *-linux-gnu)
        # Dynamic link against a system or prefix libkrun; MINVMD_REQUIRE_LIBKRUN
        # still turns a miss into a build error rather than a silent stub.
        MINVMD_REQUIRE_LIBKRUN=1 cargo build --release --locked --target "$TARGET" --package minvmd --bin minvmd
        ;;
    *)
        # Any other platform (e.g. a macOS native build): build.rs always links
        # libkrun, and a missing one is a hard link error — nothing to demand.
        cargo build --release --locked --target "$TARGET" --package minvmd --bin minvmd
        ;;
esac

# Completions from the built `min`, the technique packaging/arch/PKGBUILD-bin.tmpl
# uses: XDG
# overrides steer its user-level install targets into a scratch dir, and
# ZDOTDIR keeps the zsh compinit-dump cleanup off this host's ~.
#
# The gate compares OS as well as arch: an arm64 macOS host matches an
# aarch64-linux target on arch alone, and running that musl ELF is a hard
# exec-format failure after the whole fat-LTO build — never try to run a
# cross-built binary.
case "$(uname -s)" in
    Darwin) host_os=darwin ;;
    *)      host_os=linux ;;
esac
case "$TARGET" in
    *-linux-*) target_os=linux ;;
    *-darwin)  target_os=darwin ;;
    *)         target_os=unknown ;;
esac
case "$(uname -m)" in
    x86_64) HOST_ARCH=x86_64 ;;
    aarch64|arm64) HOST_ARCH=aarch64 ;;
    *) HOST_ARCH="$(uname -m)" ;;
esac
if [ "$host_os" != "$target_os" ] || [ "$HOST_ARCH" != "${TARGET%%-*}" ]; then
    echo "dist-build: $TARGET does not run on this host ($host_os/$HOST_ARCH); skipping completions (generate them on a matching build)" >&2
else
    # Own scratch: start clean so a failed generation can't masquerade as a
    # success behind files a previous run left behind.
    rm -rf "$COMPLETIONS_DIR"
    mkdir -p "$COMPLETIONS_DIR"
    # BASH_COMPLETION_USER_DIR forces the bash write: `min` otherwise skips
    # bash when it finds no bash-completion loader on the build host — the
    # right call for an install, wrong for a generation run.
    XDG_DATA_HOME="$COMPLETIONS_DIR" \
    XDG_CONFIG_HOME="$COMPLETIONS_DIR" \
    ZDOTDIR="$COMPLETIONS_DIR/zdotdir" \
    BASH_COMPLETION_USER_DIR="$COMPLETIONS_DIR" \
        "$BIN_DIR/min" completions install --no-input \
            --minimal-dir "$COMPLETIONS_DIR/minimal-cache" bash zsh fish
    # `completions install` is best-effort per shell (a skip is a warning, not
    # a failure) — a shippable build must assert every file actually landed.
    for f in \
        "$COMPLETIONS_DIR/bash-completion/completions/min" \
        "$COMPLETIONS_DIR/zsh/completions/_min" \
        "$COMPLETIONS_DIR/fish/completions/min.fish"; do
        [ -f "$f" ] || die "completions install did not write $f; see its warnings above"
    done
    echo "dist-build: completions -> $COMPLETIONS_DIR"
fi

echo "dist-build: $TARGET built -> $BIN_DIR (mip, min, minimald, minvmd)"
