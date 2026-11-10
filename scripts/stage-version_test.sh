#!/usr/bin/env bash
#
# stage-version_test.sh — tests for scripts/stage-version.sh and
# scripts/dispatch-release.sh. `gh` is stubbed, so nothing touches the network.
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/stage-version.sh"
dispatch="$here/dispatch-release.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-stagetest)"
trap 'rm -rf "$root"' EXIT

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

used="$root/used"
smoked="$root/smoked"
# used <version>... — write the --used file.
set_used() { printf '%s\n' "$@" >"$used"; }

check() { "$script" --check --line "$1" --used "$used" --version "$2"; }
next() { "$script" --next --line "$1" --used "$used"; }

# --- newest line --------------------------------------------------------------

newest() { printf '%s\n' "$@" | "$script" --newest-line; }
expect 0 "release/0.7.x" "release/0.6.0 is not a line" -- newest release/0.6.0 release/0.7.x
expect 0 "release/0.10.x" "0.10 sorts above 0.9" -- newest release/0.9.x release/0.10.x release/0.8.x
expect 0 "release/1.0.x" "a new major wins" -- newest release/0.10.x release/1.0.x
expect 1 "no release/X.Y.x" "no line fails" -- newest release/0.6.0 main

# --- the 0.7.3 path, today ------------------------------------------------------

# Tags on the line and the staged rows as of rc1, plus a nightly row.
set_used 0.7.0 0.7.1 0.7.2 0.7.3-rc1 014fa3eb
expect 0 "0.7.3" "next final after rc1 is 0.7.3" -- next release/0.7.x
expect 1 "0.7.3-rc1 is already used" "rc1 can't be staged twice" -- check release/0.7.x 0.7.3-rc1
expect 1 "0.7.3 or 0.7.3-rc2" "the refusal names both next versions" -- check release/0.7.x 0.7.3-rc1
expect 0 "0.7.3-rc2 is next" "rc2 is next" -- check release/0.7.x 0.7.3-rc2
expect 0 "0.7.3 is next" "final can follow rc1" -- check release/0.7.x 0.7.3
expect 1 "not next" "rc3 can't skip rc2" -- check release/0.7.x 0.7.3-rc3
expect 1 "not next" "0.7.4 can't skip 0.7.3" -- check release/0.7.x 0.7.4
expect 1 "0.7.2 is already used" "a downgrade is refused" -- check release/0.7.x 0.7.2
expect 1 "not next" "an unused lower candidate is refused" -- check release/0.7.x 0.7.2-rc9
expect 1 "does not belong" "another line's version is refused" -- check release/0.7.x 0.8.0

# --- after rc2, and after the final --------------------------------------------

set_used 0.7.0 0.7.1 0.7.2 0.7.3-rc1 0.7.3-rc2
expect 1 "already used" "rc2 is used once staged" -- check release/0.7.x 0.7.3-rc2
expect 0 "0.7.3-rc3 is next" "rc3 follows rc2" -- check release/0.7.x 0.7.3-rc3
expect 0 "0.7.3 is next" "final follows rc2" -- check release/0.7.x 0.7.3

set_used 0.7.0 0.7.1 0.7.2 0.7.3-rc1 0.7.3-rc2 0.7.3
expect 0 "0.7.4" "a staged final uses up its number, promoted or not" -- next release/0.7.x
expect 1 "already used" "the final can't be staged twice" -- check release/0.7.x 0.7.3
expect 1 "not next" "a candidate below a staged final is refused" -- check release/0.7.x 0.7.3-rc3
expect 0 "0.7.4-rc1 is next" "candidates start again at rc1" -- check release/0.7.x 0.7.4-rc1
expect 0 "0.7.4 is next" "0.7.4 is next" -- check release/0.7.x 0.7.4

# --- a new line ------------------------------------------------------------------

set_used 0.7.0 0.7.1 0.7.2 0.7.3
expect 0 "0.8.0" "a new line starts at .0" -- next release/0.8.x
expect 0 "0.8.0 is next" "0.8.0 is next on 0.8.x" -- check release/0.8.x 0.8.0
expect 0 "0.8.0-rc1 is next" "0.8.0-rc1 is next on 0.8.x" -- check release/0.8.x 0.8.0-rc1
set_used 0.7.9 0.7.10
expect 0 "0.7.11" "patch numbers compare as numbers" -- next release/0.7.x

# --- restage ---------------------------------------------------------------------

restage() {
    "$script" --check --line release/0.7.x --used "$used" --version "$1" --restage --smoked "$smoked"
}
set_used 0.7.2 0.7.3-rc1 0.7.3
printf '%s\n' 0.7.2 0.7.3-rc1 >"$smoked"
expect 0 "restaging 0.7.3" "a staged row with no smoke record can be restaged" -- restage 0.7.3
expect 1 "has a smoke record" "a smoked row can't be restaged" -- restage 0.7.3-rc1
expect 1 "not staged" "an unstaged version can't be restaged" -- restage 0.7.4

# --- bad input ---------------------------------------------------------------------

expect 1 "not a release line" "a non-line branch is refused" -- check release/0.7.0 0.7.3
expect 1 "not found" "a missing --used file is refused" -- \
    "$script" --next --line release/0.7.x --used "$root/nope"

# --- dispatch-release.sh --------------------------------------------------------

mkdir -p "$root/bin"
cat >"$root/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Answers the four calls dispatch-release.sh makes, and logs each one.
printf '%s\n' "$*" >>"$GH_STUB_LOG"
case "$*" in
    *"/git/ref/heads/"*) echo "$GH_STUB_TIP" ;;
    *"/cancel"*) ;;
    *"/dispatches"*) echo "${GH_STUB_RUN_ID-101}" ;;
    *".head_sha"*)
        # Fail as many reads as GH_STUB_SHA_ERRORS holds.
        n="$(cat "$GH_STUB_SHA_ERRORS" 2>/dev/null || echo 0)"
        if [ "$n" -gt 0 ]; then echo $((n - 1)) >"$GH_STUB_SHA_ERRORS"; echo "HTTP 502" >&2; exit 1; fi
        echo "$GH_STUB_RUN_SHA" ;;
    *)
        # One state per read, from the front of the file.
        state="$(head -n 1 "$GH_STUB_STATES")"
        sed -i.bak 1d "$GH_STUB_STATES"
        [ "$state" != "error" ] || { echo "HTTP 502" >&2; exit 1; }
        echo "$state" ;;
esac
STUB
chmod +x "$root/bin/gh"

export PATH="$root/bin:$PATH" GITHUB_REPOSITORY=gominimal/minimal POLL_SECONDS=0
export GH_STUB_LOG="$root/gh.log" GH_STUB_STATES="$root/states" GH_STUB_SHA_ERRORS="$root/sha_errors"
export GH_STUB_TIP=abc GH_STUB_RUN_SHA=abc

run_dispatch() { : >"$GH_STUB_LOG"; "$dispatch" --line release/0.7.x --sha abc --dry-run "$1" "${@:2}"; }
states() { printf '%s\n' "$@" >"$GH_STUB_STATES"; }
# logged <pattern> <description> — the stub saw a matching call.
logged() { if grep -q -- "$1" "$GH_STUB_LOG"; then ok "$2"; else bad "$2"; fi; }

states "queued null" "error" "in_progress null" "completed success"
expect 0 "passed" "polls through a failed read until the run passes" -- run_dispatch true
logged 'inputs\[dry_run\]=true' "passes dry_run=true"
logged 'inputs\[versioned\]=true' "runs versioned"
logged 'ref=release/0.7.x' "dispatches on the line"

states "completed failure"
expect 1 "ended: failure" "a failed run fails" -- run_dispatch false
logged 'inputs\[dry_run\]=false' "passes dry_run=false"

states "completed cancelled"
expect 1 "ended: cancelled" "a cancelled run fails" -- run_dispatch true

states "completed success"
expect 0 "passed" "restage reaches the run" -- run_dispatch false --restage true
logged 'inputs\[restage\]=true' "passes restage=true"

GH_STUB_TIP=def
expect 1 "moved from abc to def" "a moved tip is not dispatched" -- run_dispatch false
if grep -q dispatches "$GH_STUB_LOG"; then bad "a moved tip dispatched"; else ok "no dispatch after the tip moved"; fi
GH_STUB_TIP=abc

GH_STUB_RUN_SHA=def
expect 1 "cancelled it" "a run on another commit is cancelled" -- run_dispatch false
logged '/cancel' "cancel was sent"
GH_STUB_RUN_SHA=abc

echo 2 >"$GH_STUB_SHA_ERRORS"
states "completed success"
expect 0 "passed" "a failed read of the run's commit is retried" -- run_dispatch true

echo 3 >"$GH_STUB_SHA_ERRORS"
expect 1 "unknown commit" "a run whose commit can't be read is cancelled" -- run_dispatch true
logged '/cancel' "cancel was sent for the unread commit"
rm -f "$GH_STUB_SHA_ERRORS"

export GH_STUB_RUN_ID=""
expect 1 "no run id" "a dispatch with no run id fails" -- run_dispatch true
unset GH_STUB_RUN_ID

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
