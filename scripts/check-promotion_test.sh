#!/usr/bin/env bash
#
# check-promotion_test.sh — tests for scripts/check-promotion.sh.
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-promotion.sh"

pass=0 fail=0
ok() { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
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

check() { "$script" --version "$1" --current "$2" "${@:3}"; }

# Candidates.
expect 1 "is a candidate" "0.7.3-rc1 is refused" -- check 0.7.3-rc1 0.7.2
expect 1 "is a candidate" "0.7.3-rc2 is refused" -- check 0.7.3-rc2 0.7.2
expect 1 "is a candidate" "rollback doesn't let a candidate through" -- check 0.7.3-rc2 0.7.4 --rollback

# Moving forward.
expect 0 "can replace stable" "0.7.3 replaces 0.7.2" -- check 0.7.3 0.7.2
expect 0 "can replace stable" "0.8.0 replaces 0.7.9" -- check 0.8.0 0.7.9
expect 0 "can replace stable" "0.7.10 replaces 0.7.9" -- check 0.7.10 0.7.9
expect 0 "can replace stable" "promoting stable's own version again is fine" -- check 0.7.3 0.7.3
expect 0 "can replace stable" "a final replaces its own candidate" -- check 0.7.3 0.7.3-rc2

# Moving backward: staged 0.7.3, emergency 0.7.4, then 0.7.3 on Monday.
expect 1 "below stable (0.7.4)" "0.7.3 can't replace 0.7.4" -- check 0.7.3 0.7.4
expect 1 "below stable" "0.7.9 can't replace 0.7.10" -- check 0.7.9 0.7.10
expect 1 "below stable" "0.7.3 can't replace 0.8.0" -- check 0.7.3 0.8.0
expect 1 "below stable" "0.7.3 can't replace a 0.7.4 candidate" -- check 0.7.3 0.7.4-rc1
expect 0 "rolling stable back from 0.7.4 to 0.7.3" "rollback allows it" -- check 0.7.3 0.7.4 --rollback

# Nightly shas have no order.
expect 0 "nightly sha" "a nightly sha warns and passes" -- check 014fa3eb 0.7.2
expect 0 "nightly sha" "a sha in stable warns and passes" -- check 0.7.3 014fa3eb

# Bad input.
expect 1 "neither a version" "junk is refused" -- check latest 0.7.2
expect 1 "cannot read" "a junk stable is refused" -- check 0.7.3 "<html>"
expect 1 "required" "an empty stable is refused" -- "$script" --version 0.7.3

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
