#!/usr/bin/env sh
# Run Verus over the verified crates and compare each result with the count
# pinned below.
#
# Verus proves that functions meet the specifications written beside them
# (crates/netcore/README.md). After the proofs the same run's account of the
# crate is checked against the two locks (crates/netcore-lock/README.md): a
# changed claim fails here, not only a failed proof. The specification and
# proof code is under
# `cfg(verus_keep_ghost)`, which only Verus sets, so no other lane compiles it:
# without this script a change can break a proof and every other check passes.
#
# Install: a release from https://github.com/verus-lang/verus/releases at
# EXACTLY the version below, unpacked with `verus` on PATH, and the Rust
# toolchain that release names (`verus --version` prints it; rustup installs
# it). Pin exactly: the verified count and the proofs' resource use both move
# between releases.
#
# The rule (the same as scripts/kani.sh): a crate with Verus contracts has an
# `expect` line here and a path in .github/workflows/ci-verus.yml's filter, in
# the same change that adds the contracts.
#
# A count is pinned after a green run. It says how many items were checked and
# is not a measure of what the contracts say. A change that adds or removes a
# verified function changes the count on purpose, in the same commit.
#
# Fails closed: a missing tool, another version, no summary line, any error,
# or any other count is a failure.

set -eu

VERUS_VERSION="${VERUS_VERSION:-0.2026.11.02.8bf68ee}"
# The default resource limit is 10. The lane runs at 0.3: the proofs are kept
# passing there, and each change is also checked at 0.2 with six solver seeds
# before it lands, so a proof that has drifted fails here long before it
# would at the default.
#
# The solver matters as much as Verus: every result so far was produced with
# z3 4.16.0, the solver the packaged Verus is pointed at. Another z3 can change
# both what passes and the margin.
VERUS_RLIMIT="${VERUS_RLIMIT:-0.3}"

root="$(cd "$(dirname "$0")/.." && pwd)"
failed=0

if ! command -v verus >/dev/null 2>&1; then
    echo "verus.sh: verus is not on PATH (want $VERUS_VERSION)" >&2
    exit 1
fi
have="$(verus --version 2>&1 | sed -n 's/^ *Version: *//p' | head -n 1)"
if [ "$have" != "$VERUS_VERSION" ]; then
    echo "verus.sh: found Verus '$have', want exactly '$VERUS_VERSION'" >&2
    exit 1
fi

# expect <crate> <verified>
expect() {
    crate="$1"
    want="$2"
    out="$(mktemp)"
    echo "verus.sh: $crate (want $want verified, 0 errors, rlimit $VERUS_RLIMIT)"
    status=0
    log="$(mktemp -d)"
    (cd "$root/crates/$crate" &&
        verus --edition=2024 --crate-type=lib --rlimit "$VERUS_RLIMIT" \
            --log vir --log-dir "$log" src/lib.rs) >"$out" 2>&1 || status=$?
    line="$(grep 'verification results::' "$out" | tail -n 1 || true)"
    if [ "$status" -ne 0 ] || [ "$line" != "verification results:: $want verified, 0 errors" ]; then
        echo "verus.sh: $crate FAILED (exit $status): ${line:-no summary line}" >&2
        grep -E '^(error|warning: unused)' "$out" | head -n 40 >&2 || true
        tail -n 20 "$out" >&2
        failed=1
    else
        echo "verus.sh: $crate ok: $line"
        locks "$crate" "$log/crate.vir"
    fi
    rm -f "$out"
    rm -rf "$log"
}

# locks <crate> <dump>: the source against the statement lock, and the
# verifier's own account against the second lock and against the text. A
# crate without a lock directory has no locks to check.
locks() {
    dir="$root/crates/$1-lock"
    if [ ! -d "$dir" ]; then
        return 0
    fi
    if [ ! -s "$2" ]; then
        echo "verus.sh: $1 FAILED: the run wrote no account of the crate" >&2
        failed=1
        return 0
    fi
    if ! python3 -I -B "$dir/statements.py" --check \
        --crate "$root/crates/$1" --verus-script "$root/scripts/verus.sh"; then
        echo "verus.sh: $1 FAILED: the statements differ from STATEMENTS.lock" >&2
        failed=1
    fi
    if ! python3 -I -B "$dir/view.py" --check --vir "$2" --crate "$root/crates/$1" \
        --verus-script "$root/scripts/verus.sh"; then
        echo "verus.sh: $1 FAILED: the verifier's account differs from VIEW.lock" >&2
        failed=1
    fi
    if [ -f "$dir/controls.py" ] &&
        ! python3 -I -B "$dir/controls.py" --check --crate "$root/crates/$1/src"; then
        echo "verus.sh: $1 FAILED: a control in controls.toml does not apply to the crate" >&2
        failed=1
    fi
}

expect netcore 892

exit "$failed"
