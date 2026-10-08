#!/usr/bin/env sh
# Run the Kani bounded-verification harnesses (#1109) over the proved
# crates: rcache (index_file untrusted-bytes parse path) and sessions
# (PathDecision combination lattice, the egress frame verdict's
# admit-iff-declared property, and the publish-verb decision's
# applied-iff-table-admits property), mlog (the telemetry switches and
# the spool's clean-up plan), and minvmd (the guest boot line: the token
# alphabet both its readers agree on and the budget that leaves libkrun
# its reserve).
#
# Install: cargo install --locked kani-verifier --version 0.68.0
#          && cargo kani setup
# Pin EXACTLY 0.68.0+, for two reasons. Releases older than 0.67.0 give
# spurious verification failures on arrays >64 elements
# (kani#2416/#4408) — one wire record is 68 bytes. And 0.68.0 is the
# first release whose bundled toolchain (nightly-2026-08-21, rustc
# 1.100.0-nightly) sits above the workspace's declared rust-version
# floor: cargo hard-errors on that floor and cargo-kani exposes no
# --ignore-rust-version, so 0.67.0's 1.93-nightly needed the floor
# patched down before it would build this tree at all.
#
# Why the scratch copy exists: the backtrace workaround below rewrites
# Cargo.toml to add a [patch.crates-io] entry, and that must not touch
# the real tree. It is an rsync of the working tree rather than a clean
# checkout, so uncommitted changes are proved too and local iteration
# works.
#
# Sequential on purpose: -j once OOMed CBMC running four byte-level
# harnesses at once; the whole suite solves in seconds sequentially.
#
# Measured cost (2026-10-07, Kani 0.68.0 / CBMC 6.11.0, on the lab box: a
# Dell R730, 2x Xeon E5-2680 v3, 48 threads, 377 GB). Each run sat in a
# systemd scope with swap off (MemorySwapMax=0); peak is the scope's
# cgroup memory.peak, page cache included. Per crate, run alone with a
# warm Kani target dir:
#   sessions  10/10 harnesses  1060 s  11.87 GB peak
#   rcache     3/3               31 s   0.99 GB peak
#   mlog       9/9               47 s   0.56 GB peak
#   minvmd     5/5               42 s   1.67 GB peak (122 s, 5.55 GB cold)
# The whole script verifies 27/27 in 1157 s at a 12.33 GB peak under the
# default ceiling below (the ulimit path), and in 1260 s at 12.32 GB in a
# 16 GB scope; no OOM event in any run. sessions sets the peak. On
# GitHub-hosted CI (run 37364930742, "CI (Kani proofs)", 2026-10-05,
# ubuntu-24.04) all 27 harnesses passed, minvmd in about 66 s.
#
# Memory guard: a box that runs the lane as one job has nothing else
# between one harness's CBMC and the machine. On 2026-10-05 an uncapped
# run on the lab box, with swap on, reached 302 GB of RAM and 365 GB of
# swap in the minvmd lane before systemd stopped the runner under memory
# pressure, and its log went with it. Its cause, re-measured on that tree
# (series v10 before patch 0092), each harness alone in a 16 GB scope
# with swap off and a 15-minute limit: the minvmd harnesses then built
# Strings of symbolic length under #[kani::unwind(32)] (a token of
# symbolic length push_str'd onto the 1779-byte base line; a value pushed
# char by char from symbolic bytes), and CBMC models every byte of such a
# String. a_filter_at_the_budget_is_forwarded_or_skipped_whole reached
# 16 GB in 14 minutes, every_rejected_value_has_a_reason_and_no_token and
# every_accepted_token_is_in_the_alphabet in 11.5 minutes each, and
# guest_env_tokens_cross_all_or_none ran 15 minutes at 3.9 GB without a
# verdict. Kani checks a crate's harnesses in reverse source order, so the
# uncapped run met guest_env_tokens_cross_all_or_none first and
# a_filter_at_the_budget_is_forwarded_or_skipped_whole next; which one held
# the 302 GB is not recorded. The fifth, the_budget_leaves_libkrun_its_reserve,
# had no unwind bound at all but verifies in 8 s at 0.62 GB. KANI_MEM_MAX
# did not exist then. The same day those proofs were rewritten over
# lengths and bytes, the five measured above.
#
# KANI_MEM_MAX is the ceiling (systemd's size syntax: bytes, or K/M/G/T
# for 1024-based units, e.g. KANI_MEM_MAX=64G). Unset, it is 14G, which
# leaves a 16 GB runner its OS: CI sets nothing, so CI runs under it.
# KANI_MEM_MAX=off runs with no ceiling. Each crate's `cargo kani` runs
# under the ceiling, so a harness that outgrows it dies alone and the log
# says which: in a transient systemd scope with MemoryMax and swap denied
# to the scope (MemorySwapMax=0; a cgroup at its MemoryMax swaps rather
# than dies, which is the incident's shape) when systemd-run can reach a
# user manager; else under `ulimit -v` in a subshell, which caps each
# process's address space (CBMC is one process). The 1157 s run above
# took the ulimit path, with no user manager reachable.
set -eu

# Build artifacts land in the REAL workspace's target dir (not the
# scratch copy): CI's rust-cache persists ./target across runs and
# local runs stay incremental — without this, every invocation
# recompiles the whole dep tree from scratch.
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target/kani}"
# Absolute, always: the vendored-backtrace [patch] below writes this path into
# the SCRATCH copy's Cargo.toml, and cargo resolves a patch path against that
# manifest's directory — a relative override would resolve inside $ws, where
# nothing was ever created, and fail the lane as "vacuous" instead.
case "$CARGO_TARGET_DIR" in
    /*) ;;
    *) CARGO_TARGET_DIR="$PWD/$CARGO_TARGET_DIR" ;;
esac
export CARGO_TARGET_DIR

ws="$(mktemp -d "${TMPDIR:-/tmp}/kani-ws.XXXXXX")"
cleanup() { rm -rf "$ws"; }
trap cleanup EXIT INT TERM

rsync -a --exclude target --exclude .git --exclude .claude --exclude .scratch \
    --exclude 'crates/*/fuzz/corpus' ./ "$ws/"

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
# Fetch FIRST: the vendored copy is cut from the registry's UNPACKED source,
# but nothing has run cargo at this point (the first build is the `cargo kani`
# below), so a registry holding only the `.crate` archive leaves the glob empty
# and this whole block no-ops — the lane then dies with the very E0659 it
# exists to prevent. CI's cache is exactly that shape: rust-cache deletes
# registry/src before saving (everything but `-sys` crates) and restores only
# registry/cache. `cargo fetch` extracts, and settles Cargo.lock before the
# version is read out of it.
(cd "$ws" && cargo fetch)
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
elif [ -n "$btver" ] && [ -z "$btsrc" ]; then
    # Unreachable after the fetch above, so say so out loud rather than
    # skipping mutely: a lane that then fails on E0659 is one read from
    # diagnosed instead of three nights of guessing.
    echo "WARNING: backtrace-$btver not unpacked in the cargo registry — E0659 workaround SKIPPED" >&2
elif [ -n "$btver" ]; then
    # Source present, call site no longer matching. Two futures reach here
    # and the log cannot tell them apart: backtrace fixed the call (delete
    # this block) or merely reformatted it (the pattern needs widening, and
    # the build is about to say E0659). Name both rather than pass over it.
    echo "NOTE: backtrace-$btver no longer matches the patched call site — E0659 workaround not applied; delete this block if upstream fixed it, widen the pattern if the proof build now fails on E0659" >&2
fi

cd "$ws"

# The memory guard, decided once (see the header). Unset means the
# default ceiling, 14G, which leaves a 16 GB runner its OS; `off` means
# no guard. `kani_guard` is "scope", "ulimit" or empty; `kani_mem_kib` is
# the ulimit figure.
KANI_MEM_MAX="${KANI_MEM_MAX:-14G}"
kani_guard=""
kani_mem_kib=""
if [ "$KANI_MEM_MAX" = off ]; then
    echo "kani.sh: memory guard off (KANI_MEM_MAX=off)" >&2
else
    digits="${KANI_MEM_MAX%[KMGT]}"
    case "$digits" in
        "" | *[!0-9]*)
            echo "FATAL: KANI_MEM_MAX='$KANI_MEM_MAX' is not a size: digits, optionally K, M, G or T" >&2
            exit 1
            ;;
        # Plain decimal only: a leading zero would make the arithmetic
        # below read the figure as octal (08G is an error, 010G is 8G).
        0?*)
            echo "FATAL: KANI_MEM_MAX='$KANI_MEM_MAX' has a leading zero; write the size in plain decimal" >&2
            exit 1
            ;;
    esac
    # Probe the scope path on `true`: no user manager (no session bus, a
    # box without systemd) fails here, not on the real run, and the lane
    # falls back to ulimit rather than on its face.
    if command -v systemd-run >/dev/null 2>&1 &&
        systemd-run --user --scope -q -p MemoryMax="$KANI_MEM_MAX" -p MemorySwapMax=0 \
            true >/dev/null 2>&1; then
        kani_guard="scope"
    else
        case "$KANI_MEM_MAX" in
            *K) kani_mem_kib="$digits" ;;
            *M) kani_mem_kib=$((digits * 1024)) ;;
            *G) kani_mem_kib=$((digits * 1024 * 1024)) ;;
            *T) kani_mem_kib=$((digits * 1024 * 1024 * 1024)) ;;
            *) kani_mem_kib=$((digits / 1024)) ;;
        esac
        kani_guard="ulimit"
    fi
    echo "kani.sh: memory guard '$kani_guard' at KANI_MEM_MAX=$KANI_MEM_MAX" >&2
fi

# `cargo kani` on one crate, under the memory guard when one is set.
# `--scope` runs the command in the caller's foreground and returns its
# status, so no --wait (systemd-run refuses --wait with --scope). Not -q:
# the "Running scope as unit: run-….scope" line names the unit to watch
# (`systemctl --user status run-….scope` shows its memory while it runs).
kani_crate() { # crate
    case "$kani_guard" in
        scope)
            systemd-run --user --scope -p MemoryMax="$KANI_MEM_MAX" -p MemorySwapMax=0 \
                cargo kani -p "$1" --output-format=terse
            ;;
        ulimit)
            # shellcheck disable=SC3045 # ulimit -v is not POSIX; dash, bash and busybox sh have it
            (ulimit -v "$kani_mem_kib" && exec cargo kani -p "$1" --output-format=terse)
            ;;
        *) cargo kani -p "$1" --output-format=terse ;;
    esac
}

# Assert the harness COUNT, not just exit status: `cargo kani` exits 0
# on a crate with zero harnesses, so if the #[cfg(kani)] modules ever
# stop compiling in, the lane would go green having proved nothing.
# Streams output while running (a silent 8-minute compile is
# undiagnosable in CI); avoids pipe-to-tee, which swallows exit status
# in POSIX sh. The log file lives in the scratch ws, cleaned by trap.
expect() { # crate expected_count
    log="$ws/kani-$1.log"
    kani_crate "$1" 2>&1 | tee "$log"
    # tee masks cargo's status (no pipefail in sh): the count grep below
    # is the gate, and a failed run cannot print the success line.
    grep -q "Complete - $2 successfully verified harnesses, 0 failures" "$log" || {
        # Say which kind of failure this is: a dependency that will not
        # build is not a proof regression, though the count message reads
        # like one (three canary nights were read that way). A log with no
        # rustc error — `cargo kani` missing, or dead before compiling —
        # falls through to the count message, which fits that case.
        # Match the bare phrase, not an `error:` prefix: the lane runs under
        # CARGO_TERM_COLOR=always, where cargo writes the summary as
        # `\033[1m\033[91merror\033[0m: could not compile ...` and an escape
        # sits between `error` and the colon, so neither an anchored nor an
        # unanchored `error: could not compile` can match.
        if grep -q 'could not compile' "$log"; then
            echo "FATAL: $1 proof build failed to COMPILE — not a proof result; see the rustc error above" >&2
        else
            echo "FATAL: expected $2 verified harnesses in $1 — vacuous or failing lane" >&2
        fi
        exit 1
    }
}
expect sessions 10
expect rcache 3
expect mlog 9
expect minvmd 5
