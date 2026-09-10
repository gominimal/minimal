#!/usr/bin/env bash
#
# assert-release-version_test.sh — test harness for
# scripts/assert-release-version.sh.
#
# No network, no real Cargo.toml: each case drives the script against a
# fixture manifest with explicit --tag/--cargo-toml flags and asserts the exit
# code plus a stderr/stdout substring. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/assert-release-version.sh"
[ -f "$script" ] || { echo "cannot find assert-release-version.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-verassert)"
trap 'rm -rf "$root"' EXIT

cargo_toml() {
    printf '[package]\nname = "minimal"\nversion = "0.0.0"\n%s\n' "$1" >"$root/Cargo.toml"
}

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
expect() {
    local want_rc="$1" want_msg="$2" desc="$3"; shift 3
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -eq "$want_rc" ] && [[ "$out" == *"$want_msg"* ]]; then
        ok "$desc"
    else
        bad "$desc (want rc=$want_rc and '$want_msg'; got rc=$rc, out: $out)"
    fi
}

run() {
    "$script" --tag "$1" --cargo-toml "$root/Cargo.toml"
}

# --- matching / mismatching -------------------------------------------------

cargo_toml 'package.version = "0.5.4"'
expect 0 "matches tag v0.5.4" "matching tag and package.version passes" -- run v0.5.4
expect 1 "package.version is 0.5.4" "stale package.version fails the run" -- run v0.6.0

# The fallback version is the tag verbatim (crates/version/build.rs passes an
# exactly-tagged HEAD through stripped of the v prefix), prerelease included:
# Cargo SemVer carries it in package.version just as well.
cargo_toml 'package.version = "0.6.0-rc.1"'
expect 0 "matches tag v0.6.0-rc.1" "prerelease tag matches its verbatim version" -- run v0.6.0-rc.1
cargo_toml 'package.version = "0.6.0"'
expect 1 "package.version is 0.6.0" "plain version under a prerelease tag fails" -- run v0.6.0-rc.1

# --- non-tag flows skip, they do not fail ----------------------------------

expect 0 "not a tag push" "branch ref skips the assertion" -- \
    env GITHUB_REF_TYPE=branch GITHUB_REF_NAME=main "$script" --cargo-toml "$root/Cargo.toml"
expect 0 "not a v* semver tag" "release-<sha> ref skips the assertion" -- run release-abc12345

# --- malformed input fails loudly -------------------------------------------

cargo_toml '# package.version moved into a comment'
expect 1 "could not extract package.version" "unreadable Cargo.toml fails loudly" -- run v0.5.4
expect 1 "no such Cargo.toml" "missing Cargo.toml fails loudly" -- \
    "$script" --tag v0.5.4 --cargo-toml "$root/absent.toml"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
