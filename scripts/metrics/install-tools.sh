#!/usr/bin/env bash
# Install the metrics pipeline's tools at their pinned versions (spec 30).
#
# One pin per tool, here and nowhere else. `run.sh` records the versions it
# finds into the snapshot, so a reader can tell a drifted tool from a
# changed tree; `--check` says which pins the host does not meet.
# cargo-binstall is used when present (prebuilt binaries, seconds); otherwise
# `cargo install --locked` compiles each tool (minutes). Neither is required
# for a tool already installed at the pinned version.
#
# Usage: scripts/metrics/install-tools.sh [--check]
#   --check   report what is missing or mispinned, install nothing; exit 1 if any.
#
# Also needs the toolchain's `llvm-tools-preview` for coverage; rustup hosts
# get it from `rustup component add`, others set LLVM_COV/LLVM_PROFDATA to a
# matching LLVM. The check below says which.
set -euo pipefail

# tool  crate  version  version-command
pins=(
    "cargo-llvm-cov  cargo-llvm-cov  0.9.1   cargo llvm-cov --version"
    "cargo-modules   cargo-modules   0.27.0  cargo modules --version"
    "cargo-shear     cargo-shear     1.14.0  cargo shear --version"
    "cargo-nextest   cargo-nextest   0.9.148 cargo nextest --version"
    "tokei           tokei           15.0.0  tokei --version"
)

check_only=0
[ "${1:-}" = "--check" ] && check_only=1

# Installed version of a tool, or empty. Every tool prints its version
# somewhere in the first line; the first dotted number is it.
installed_version() {
    local bin="$1"; shift
    command -v "$bin" >/dev/null 2>&1 || return 0
    "$@" 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

missing=()
for pin in "${pins[@]}"; do
    # shellcheck disable=SC2086 # the pin row is meant to split
    set -- $pin
    tool="$1" crate="$2" want="$3"; shift 3
    have="$(installed_version "$tool" "$@")"
    if [ "$have" = "$want" ]; then
        echo "ok        $tool $want"
    elif [ -z "$have" ]; then
        echo "missing   $tool (want $want)"
        missing+=("$crate@$want")
    else
        echo "mispinned $tool $have (want $want)"
        missing+=("$crate@$want")
    fi
done

if [ "${#missing[@]}" -eq 0 ]; then
    echo "metrics tools: all pinned versions present"
    exit 0
fi
if [ "$check_only" -eq 1 ]; then
    echo "metrics tools: missing or mispinned: ${missing[*]}" >&2
    echo "install with: scripts/metrics/install-tools.sh" >&2
    exit 1
fi

if command -v cargo-binstall >/dev/null 2>&1; then
    cargo binstall -y --locked "${missing[@]}"
else
    echo "cargo-binstall not found; compiling with cargo install (slow)." >&2
    echo "Speed this up next time: cargo install cargo-binstall --locked" >&2
    for spec in "${missing[@]}"; do
        crate="${spec%@*}" version="${spec#*@}"
        cargo install --locked "$crate" --version "$version"
    done
fi
