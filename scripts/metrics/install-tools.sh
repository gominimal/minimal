#!/usr/bin/env bash
# Install the metrics pipeline's tools at their pinned versions (spec 31).
#
# One pin per tool, here and nowhere else. `run.sh` records the versions it
# finds into the snapshot, so a reader can tell a drifted tool from a
# changed tree; `--check` says which pins the host does not meet.
# cargo-binstall is used when present (prebuilt binaries, seconds); otherwise
# `cargo install --locked` compiles each tool (minutes). Neither is required
# for a tool already installed at the pinned version.
#
# Usage: scripts/metrics/install-tools.sh [--check] [--experimental] [--only TOOL]...
#   --check         report what is missing or mispinned, install nothing;
#                   exit 1 if any.
#   --experimental  also install the experimental collectors (rustqual,
#                   cargo-anatomy). Without it `--check` lists them as
#                   optional and they never count as missing: what they
#                   measure is recorded, never gated (QM-005), so a host
#                   without them still writes a complete snapshot.
#   --only TOOL     consider only this tool (repeatable), so a task that needs
#                   two tools installs those two at their pins and no others.
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
    "cargo-mutants   cargo-mutants   27.1.0  cargo mutants --version"
    "cargo-crap      cargo-crap      0.7.0   cargo crap --version"
    "tokei           tokei           15.0.0  tokei --version"
)
# The experimental collectors (metrics/README.md, "Experimental coupling
# metrics"). cargo-anatomy documents only the short `-V`.
experimental_pins=(
    "rustqual        rustqual        1.8.3   rustqual --version"
    "cargo-anatomy   cargo-anatomy   0.7.7   cargo anatomy -V"
)

check_only=0 experimental=0 only=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --check) check_only=1; shift ;;
        --experimental) experimental=1; shift ;;
        --only) [ "$#" -ge 2 ] || { echo "$0: --only takes a tool" >&2; exit 1; }; only+=("$2"); shift 2 ;;
        *) echo "usage: $0 [--check] [--experimental] [--only TOOL]..." >&2; exit 1 ;;
    esac
done
for want_tool in ${only[@]+"${only[@]}"}; do   # bash 3.2 + set -u: an empty array is unset
    known=0
    for pin in "${pins[@]}" "${experimental_pins[@]}"; do
        [ "${pin%% *}" = "$want_tool" ] && known=1
    done
    [ "$known" -eq 1 ] || { echo "$0: --only $want_tool: no pin for that tool" >&2; exit 1; }
done

# Installed version of a tool, or empty. Every tool prints its version
# somewhere in the first line; the first dotted number is it.
installed_version() {
    local bin="$1"; shift
    command -v "$bin" >/dev/null 2>&1 || return 0
    "$@" 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

missing=()
# check_pin <required 0|1> <pin row>: report the row; a required row that is
# not at its pin joins `missing`.
check_pin() {
    local required="$1" tool crate want have
    # shellcheck disable=SC2086 # the pin row is meant to split
    set -- $2
    tool="$1" crate="$2" want="$3"; shift 3
    if [ "${#only[@]}" -gt 0 ] && [[ " ${only[*]} " != *" $tool "* ]]; then
        return 0
    fi
    have="$(installed_version "$tool" "$@")"
    if [ "$have" = "$want" ]; then
        echo "ok        $tool $want"
    elif [ "$required" -eq 0 ]; then
        echo "optional  $tool ${have:-missing} (want $want; install with --experimental)"
    elif [ -z "$have" ]; then
        echo "missing   $tool (want $want)"
        missing+=("$crate@$want")
    else
        echo "mispinned $tool $have (want $want)"
        missing+=("$crate@$want")
    fi
}
for pin in "${pins[@]}"; do check_pin 1 "$pin"; done
for pin in "${experimental_pins[@]}"; do check_pin "$experimental" "$pin"; done

if [ "${#missing[@]}" -eq 0 ]; then
    echo "metrics tools: all pinned versions present"
    exit 0
fi
if [ "$check_only" -eq 1 ]; then
    hint=""
    [ "$experimental" -eq 1 ] && hint=" --experimental"
    echo "metrics tools: missing or mispinned: ${missing[*]}" >&2
    echo "install with: scripts/metrics/install-tools.sh$hint" >&2
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
