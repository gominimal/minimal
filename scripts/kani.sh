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

rsync -a --exclude target --exclude .git --exclude 'crates/*/fuzz/target' \
    --exclude 'crates/*/fuzz/corpus' ./ "$ws/"

# Relax the single workspace-level floor (every crate inherits it).
sed -i.kani-bak 's/^package\.rust-version = "[0-9.][0-9.]*"/package.rust-version = "1.90"/' "$ws/Cargo.toml"
rm -f "$ws/Cargo.toml.kani-bak"

cd "$ws"
cargo kani -p sessions --output-format=terse
cargo kani -p rcache --output-format=terse
