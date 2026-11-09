#!/usr/bin/env bash
#
# backport-title-guard_test.sh — test harness for backport-title-guard.sh and
# backport-conflict-paths.sh.
#
# Each title is committed to a throwaway repo and given to next-version.sh, so
# the guard must refuse exactly what forces a minor. The conflict cases run a
# real cherry-pick the way the backport action does. Run directly or via
# `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
guard="$here/backport-title-guard.sh"
paths="$here/backport-conflict-paths.sh"
next_version="$here/next-version.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-backporttest)"
trap 'rm -rf "$root"' EXIT

# Identity through the environment: CI runners have no global git identity.
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# bump <message> — the level next-version.sh gives one commit with this message.
bump() {
    local repo
    repo="$(mktemp -d "$root/bump.XXXXXX")"
    git init -q "$repo"
    git -C "$repo" commit -q --allow-empty -m "chore: base"
    git -C "$repo" tag v0.1.0
    git -C "$repo" commit -q --allow-empty -m "$1"
    "$next_version" --repo "$repo" --bump
}

# agrees <title> <refused|allowed> — the guard's answer, and next-version.sh's.
agrees() {
    local title="$1" want="$2" got=allowed level
    "$guard" "$title" >/dev/null || got=refused
    level="$(bump "$title")"
    if [ "$got" != "$want" ]; then
        bad "$title: guard $got, want $want"
    elif { [ "$got" = refused ] && [ "$level" != minor ]; } ||
        { [ "$got" = allowed ] && [ "$level" != patch ]; }; then
        bad "$title: guard $got, but next-version says $level"
    else
        ok "$title: $got ($level)"
    fi
}

agrees "feat: add a thing" refused
agrees "feat(minimald): add a thing" refused
agrees "feat(net)!: replace a thing" refused
agrees "fix!: change a thing" refused
agrees "fix(minvmd)!: change a thing" refused
agrees "refactor!: move a thing" refused
agrees "fix: repair a thing" allowed
agrees "fix(minimald): answer a create over the re-read fact (#3026)" allowed
agrees "perf(net): skip a copy" allowed
agrees "ci(release): scope and lock the signing keychain on 0.7.x" allowed
agrees "build: declare 0.7.3-rc1 as the first release candidate" allowed
agrees "T123 — A piped stdin reaches a task box's task (#3086)" allowed
agrees "feature: not a type next-version knows" allowed
agrees "Feat: capitals are not a type" allowed
agrees "feat without a colon" allowed

# footer <message> <refused|allowed> — the guard on a fix title and this commit message.
footer() {
    local message="$1" want="$2" got=allowed level
    printf '%s\n' "$message" >"$root/message"
    "$guard" "fix: a retitled change" "$root/message" >/dev/null || got=refused
    level="$(bump "$message")"
    if [ "$got" != "$want" ]; then
        bad "footer: guard $got, want $want: $message"
    elif { [ "$got" = refused ] && [ "$level" != minor ]; } ||
        { [ "$got" = allowed ] && [ "$level" != patch ]; }; then
        bad "footer: guard $got, but next-version says $level: $message"
    else
        ok "footer: $got ($level)"
    fi
}

footer $'fix: a change\n\nBREAKING CHANGE: the flag is gone' refused
footer $'fix: a change\n\nBREAKING-CHANGE: the flag is gone' refused
footer $'fix: a change\n\nThis is not a BREAKING CHANGE: it stays' allowed
footer $'fix: a change\n\n* feat(net): a squashed commit subject' allowed

if "$guard" >/dev/null 2>&1; then bad "no title is a usage error"; else ok "no title is a usage error"; fi

# A real conflict, committed the way the action commits one.
repo="$root/conflict"
git init -q -b main "$repo"
printf 'one\n' >"$repo/edited"
printf 'one\n' >"$repo/removed-on-line"
printf 'one\n' >"$repo/clean"
git -C "$repo" add .
git -C "$repo" commit -q -m "chore: base"
git -C "$repo" branch line
printf 'main\n' >"$repo/edited"
printf 'main\n' >"$repo/removed-on-line"
printf 'main\n' >"$repo/clean"
git -C "$repo" commit -qam "fix: change everything"
source_commit="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -q line
printf 'line\n' >"$repo/edited"
git -C "$repo" rm -q removed-on-line
git -C "$repo" commit -qam "fix: change the line"
onto="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" switch -qc backport/1-to-line
if git -C "$repo" cherry-pick -x "$source_commit" >/dev/null 2>&1; then
    bad "the fixture must conflict"
fi
git -C "$repo" commit -q --all -m BACKPORT-CONFLICT

got="$(cd "$repo" && "$paths" "$onto" "$source_commit" | tr '\n' ' ')"
if [ "$got" = "edited removed-on-line " ]; then
    ok "conflict paths include a modify/delete, and not the clean file"
else
    bad "conflict paths: got '$got'"
fi
if [ -z "$(git -C "$repo" status --porcelain)" ]; then
    ok "conflict paths leave a clean tree"
else
    bad "conflict paths left the tree dirty"
fi

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
