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
