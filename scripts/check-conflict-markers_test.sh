#!/usr/bin/env bash
#
# check-conflict-markers_test.sh — test harness for check-conflict-markers.sh.
#
# Makes real conflicts in a throwaway repo, in both of git's conflict styles,
# and commits them the way the backport action does. Run directly or via
# `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-conflict-markers.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-markertest)"
trap 'rm -rf "$root"' EXIT

# Identity through the environment: CI runners have no global git identity.
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# Built here so that the scan passes on this file.
opening="$(printf '<%.0s' 1 2 3 4 5 6 7)"
closing="$(printf '>%.0s' 1 2 3 4 5 6 7)"

# scan <dir> <0|1> <description> — the exit code the scan must give in <dir>.
scan() {
    local dir="$1" want="$2" got=0
    (cd "$dir" && "$script") >"$root/out" 2>&1 || got=$?
    if [ "$got" = "$want" ]; then ok "$3"; else bad "$3: exit $got, want $want: $(cat "$root/out")"; fi
}

# fixture <name> <file-content> — a repo with one committed file.
fixture() {
    local repo="$root/$1"
    git init -q -b main "$repo"
    printf '%b' "$2" >"$repo/file"
    git -C "$repo" add file
    git -C "$repo" commit -q -m "chore: base"
    printf '%s' "$repo"
}

# conflicted <name> <merge|diff3> — a real conflict, committed with its markers.
conflicted() {
    local repo
    repo="$(fixture "$1" 'base\n')"
    git -C "$repo" config merge.conflictStyle "$2"
    git -C "$repo" switch -qc other
    printf 'other\n' >"$repo/file"
    git -C "$repo" commit -qam "fix: other"
    git -C "$repo" switch -q main
    printf 'main\n' >"$repo/file"
    git -C "$repo" commit -qam "fix: main"
    git -C "$repo" cherry-pick other >/dev/null 2>&1 || true
    git -C "$repo" commit -q --all -m BACKPORT-CONFLICT
    printf '%s' "$repo"
}

scan "$(fixture clean 'fn main() {}\n')" 0 "a clean tree passes"
scan "$(conflicted merge merge)" 1 "a committed conflict fails"
scan "$(conflicted diff3 diff3)" 1 "a committed diff3 conflict fails"
scan "$(fixture opening "$opening HEAD\n")" 1 "a lone opening marker fails"
scan "$(fixture closing "$closing 1234567 (fix: a thing)\n")" 1 "a lone closing marker fails"
scan "$(fixture heading 'Heading\n=======\n')" 0 "a Markdown heading underline passes"
scan "$(fixture indented "    $opening HEAD\n")" 0 "an indented marker passes"
scan "$(fixture midline "a $opening b\n")" 0 "a marker inside a line passes"
scan "$(fixture long "$opening<<< HEAD\n")" 0 "a longer run of the character passes"
scan "$(fixture binary "\000$opening HEAD\n")" 0 "a binary file passes"

repo="$(fixture untracked 'clean\n')"
printf '%s HEAD\n' "$opening" >"$repo/untracked"
scan "$repo" 0 "an untracked file passes"

if (cd "$root" && "$script") >/dev/null 2>&1; then
    bad "outside a repository must fail"
else
    ok "outside a repository fails"
fi

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
