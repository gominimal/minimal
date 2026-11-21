#!/usr/bin/env bash
#
# check-rust-pin_test.sh — test harness for check-rust-pin.sh, and the gate
# that runs it against this tree.
#
# The fixture cases serve a fake pkgs tree over file://, so they need no
# network. The last case checks the real checkout against the real pkgs
# commit; it skips when GitHub is unreachable, except on GitHub Actions
# (GITHUB_ACTIONS set), where it fails. Not CI: a sandbox with no network,
# such as the agent runtime's verify box, must not fail on the fetch.
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-rust-pin.sh"
command -v curl >/dev/null 2>&1 || { echo "curl not installed — skipping check-rust-pin_test.sh"; exit 0; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-rustpintest)"
trap 'rm -rf "$root"' EXIT

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

commit=0123456789abcdef0123456789abcdef01234567

# fixture <name> <channel> <pkgs rust version> — a checkout and a pkgs tree.
fixture() {
    local dir="$root/$1"
    mkdir -p "$dir/.minimal" "$dir/pkgs/$commit/packages/rust"
    printf '[toolchain]\nchannel = "%s"\ncomponents = ["clippy"]\n' "$2" >"$dir/rust-toolchain.toml"
    cat >"$dir/.minimal/minimal.toml" <<EOF
[upstream] # Source of software & tooling
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "$commit"

[sideloads.other]
locked_commit = "ffffffffffffffffffffffffffffffffffffffff"
EOF
    printf 'let rustc-1-98-1 = import "x" in\nlet version = "%s" in\n{ name = "rust" }\n' "$3" \
        >"$dir/pkgs/$commit/packages/rust/build.ncl"
    printf '%s' "$dir"
}

# check <dir> <want exit> <description>
check() {
    local got=0
    PKGS_RAW_BASE="file://$1/pkgs" "$script" "$1" >"$root/out" 2>&1 || got=$?
    if [ "$got" = "$2" ]; then ok "$3"; else bad "$3: exit $got, want $2: $(cat "$root/out")"; fi
}

check "$(fixture agree 1.99.1 1.99.1)" 0 "pins that agree pass"
check "$(fixture drift 1.97.0 1.98.1)" 1 "a toolchain pin behind pkgs fails"
check "$(fixture floating stable 1.99.1)" 1 "a channel that is not x.y.z fails"
dir="$(fixture missing 1.99.1 1.99.1)"
rm -r "$dir/pkgs"
check "$dir" 2 "an unfetchable build.ncl exits 2"

# This checkout against the live pkgs repo.
got=0
"$script" "$here/.." >"$root/out" 2>&1 || got=$?
if [ "$got" = 0 ]; then
    ok "this tree: $(cat "$root/out")"
elif [ "$got" = 2 ] && [ -z "${GITHUB_ACTIONS:-}" ]; then
    echo "skip - this tree: pkgs unreachable off GitHub Actions: $(cat "$root/out")"
else
    bad "this tree: $(cat "$root/out")"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
