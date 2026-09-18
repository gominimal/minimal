#!/usr/bin/env sh
# Run the Kani bounded-verification harnesses (#1109) over the proved
# crates: rcache (index_file untrusted-bytes parse path) and sessions
# (PathDecision combination lattice).
#
# Install: cargo install --locked kani-verifier --version 0.67.0
#          && cargo kani setup
# Pin EXACTLY 0.67.0+: older releases give spurious verification
# failures on arrays >64 elements (kani#2416/#4408) — one wire record
# is 68 bytes.
#
# MSRV note, and why the scratch copy exists: Kani 0.67.0 bundles a
# 1.93-nightly toolchain, numerically below the workspace's declared
# rust-version floor. The gate is declarative only — the nightly
# compiles this tree fine (all proofs verify) — but cargo hard-errors
# on the floor and cargo-kani exposes no --ignore-rust-version. Until
# Kani ships a >=floor toolchain, run from a scratch copy with the
# floor relaxed. The copy includes uncommitted changes (rsync of the
# working tree, not a git checkout) so local iteration works.
#
# Sequential on purpose: -j once OOMed CBMC running four byte-level
# harnesses at once; the whole suite solves in seconds sequentially.
set -eu

# Build artifacts land in the REAL workspace's target dir (not the
# scratch copy): CI's rust-cache persists ./target across runs and
# local runs stay incremental — without this, every invocation
# recompiles the whole dep tree from scratch.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/kani}"

ws="$(mktemp -d "${TMPDIR:-/tmp}/kani-ws.XXXXXX")"
cleanup() { rm -rf "$ws"; }
trap cleanup EXIT INT TERM

rsync -a --exclude target --exclude .git --exclude .claude --exclude .scratch \
    --exclude 'crates/*/fuzz/corpus' ./ "$ws/"

# Relax the single workspace-level floor (every crate inherits it).
sed -i.kani-bak 's/^package\.rust-version = "[0-9.][0-9.]*"/package.rust-version = "1.90"/' "$ws/Cargo.toml"
rm -f "$ws/Cargo.toml.kani-bak"

# Kani builds every crate against its own `std` shim (passed as
# `--extern std=$KANI/lib/libstd.rlib`), which `#[macro_export]`s Kani's
# `assert!`/`panic!`/`unreachable!`. A `#![no_std]` dependency that does BOTH
# `#[macro_use] extern crate std;` and `use std::prelude::v1::*;` therefore
# resolves two DIFFERENT `unreachable!` — the shim's via the macro_use
# prelude, real std's via the glob — and dies with E0659. `backtrace` (in the
# graph via nickel-lang-core -> topiary-core -> miette[fancy]) is exactly that
# shape. This bites from Kani 0.68.0, whose shim grew a `prelude` module that
# forwards to real std's; 0.67.0 had none, so the glob imported no macro and
# there was no second candidate. Kani's own escape hatch,
# --no-assert-overrides, does NOT help: it suppresses the compiler's injection
# into local crates, not the shim crate's exports
# (model-checking/kani#4665/#4666/#4687). 0.3.76 is the newest release and
# upstream master is still unqualified, so there is no version to bump to.
# Qualify the one call site in a vendored copy: `core::unreachable!` is the
# same macro, so neither lane's proofs change meaning. The copy lives in the
# persisted target dir keyed by version, so it is built once rather than
# re-fingerprinted (and its dependents rebuilt) on every run. When a fixed
# backtrace ships, the `grep` stops matching and this block self-disables —
# delete it then.
btver="$(sed -n '/^name = "backtrace"$/{n;s/^version = "\(.*\)"$/\1/p;}' "$ws/Cargo.lock")"
btsrc=""
for d in "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/backtrace-"$btver"; do
    if [ -d "$d" ]; then
        btsrc="$d"
        break
    fi
done
if [ -n "$btver" ] && [ -n "$btsrc" ] &&
    grep -q '^        unreachable!()$' "$btsrc/src/types.rs"; then
    vendor="$CARGO_TARGET_DIR/kani-vendor/backtrace-$btver"
    if [ ! -d "$vendor" ]; then
        mkdir -p "$CARGO_TARGET_DIR/kani-vendor"
        rm -rf "$vendor.tmp"
        cp -R "$btsrc" "$vendor.tmp"
        chmod -R u+w "$vendor.tmp"
        sed -i.kani-bak 's/^        unreachable!()$/        core::unreachable!()/' \
            "$vendor.tmp/src/types.rs"
        rm -f "$vendor.tmp/src/types.rs.kani-bak"
        mv "$vendor.tmp" "$vendor"
    fi
    # awk, not sed: appending under the existing [patch.crates-io] needs a
    # newline in the replacement, which BSD sed does not honour.
    awk -v p="$vendor" '
        { print }
        /^\[patch\.crates-io\]$/ && !done { print "backtrace = { path = \"" p "\" }"; done = 1 }
    ' "$ws/Cargo.toml" >"$ws/Cargo.toml.kani"
    mv "$ws/Cargo.toml.kani" "$ws/Cargo.toml"
    grep -q '^backtrace = { path = ' "$ws/Cargo.toml" || {
        echo "FATAL: no [patch.crates-io] table to carry the backtrace E0659 workaround" >&2
        exit 1
    }
fi

cd "$ws"
# Assert the harness COUNT, not just exit status: `cargo kani` exits 0
# on a crate with zero harnesses, so if the #[cfg(kani)] modules ever
# stop compiling in, the lane would go green having proved nothing.
# Streams output while running (a silent 8-minute compile is
# undiagnosable in CI); avoids pipe-to-tee, which swallows exit status
# in POSIX sh. The log file lives in the scratch ws, cleaned by trap.
expect() { # crate expected_count
    log="$ws/kani-$1.log"
    cargo kani -p "$1" --output-format=terse 2>&1 | tee "$log"
    # tee masks cargo's status (no pipefail in sh): the count grep below
    # is the gate, and a failed run cannot print the success line.
    grep -q "Complete - $2 successfully verified harnesses, 0 failures" "$log" || {
        echo "FATAL: expected $2 verified harnesses in $1 — vacuous or failing lane" >&2
        exit 1
    }
}
expect sessions 6
expect rcache 3
