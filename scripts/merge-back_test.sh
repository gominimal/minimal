#!/usr/bin/env bash
#
# merge-back_test.sh — test harness for scripts/merge-back.sh.
#
# Builds a bare origin and a clone, with a line, a tag and a moved main, and
# pushes only to that origin. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/merge-back.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-mergeback)"
trap 'rm -rf "$root"' EXIT

# Identity through the environment: CI runners have no global git identity.
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# write <repo> <file> <content> <message> — commit one file.
write() {
    printf '%s\n' "$3" >"$1/$2"
    git -C "$1" add "$2"
    git -C "$1" commit -q -m "$4"
}

# setup <name> — prints a clone. main and release/0.7.x have the same fix, and
# the line has the tag v0.7.3. Both are pushed to the bare origin.
setup() {
    local repo="$root/$1" fix
    git init -q --bare -b main "$repo.git"
    git clone -q "$repo.git" "$repo" 2>/dev/null
    git -C "$repo" switch -qc main
    write "$repo" base one "chore: base"
    git -C "$repo" switch -qc release/0.7.x
    git -C "$repo" switch -q main
    write "$repo" fix one "fix: the fix"
    fix="$(git -C "$repo" rev-parse HEAD)"
    write "$repo" main-only one "fix: main moves on"
    git -C "$repo" switch -q release/0.7.x
    git -C "$repo" cherry-pick -x "$fix" >/dev/null
    git -C "$repo" tag v0.7.3
    git -C "$repo" switch -q main
    git -C "$repo" push -q origin main release/0.7.x v0.7.3
    printf '%s' "$repo"
}

# run <repo> <args...> — run the script in <repo>. Sets $code, and $out to stdout.
run() {
    local repo="$1"
    shift
    code=0
    out="$(cd "$repo" && "$script" "$@" 2>"$root/stderr")" || code=$?
}

# expect <want> <description> — compare $code.
expect() {
    if [ "$code" = "$1" ]; then ok "$2"; else bad "$2: exit $code, want $1: $(cat "$root/stderr")"; fi
}

# same <got> <want> <description> — compare two values.
same() {
    if [ "$1" = "$2" ]; then ok "$3"; else bad "$3: got $1, want $2"; fi
}

origin_main() { git -C "$1.git" rev-parse main; }

# A clean line.
repo="$(setup clean)"
before="$(origin_main "$repo")"
run "$repo" check 0.7.3
expect 0 "check passes when every line commit is on main"
same "$(origin_main "$repo")" "$before" "check pushes nothing"

run "$repo" merge 0.7.3
expect 0 "merge succeeds"
after="$(origin_main "$repo")"
if git -C "$repo.git" merge-base --is-ancestor v0.7.3 main; then
    ok "the tag is reachable from main"
else
    bad "the tag is not reachable from main"
fi
same "$(git -C "$repo.git" rev-parse "main^{tree}")" "$(git -C "$repo.git" rev-parse "$before^{tree}")" \
    "the merge keeps the tree of main"
same "$(git -C "$repo.git" rev-parse main^1)" "$before" "the first parent is the old main"
same "$(git -C "$repo.git" rev-parse main^2)" "$(git -C "$repo.git" rev-parse release/0.7.x)" \
    "the second parent is the line"
same "$(git -C "$repo.git" describe --tags --abbrev=0 main)" v0.7.3 "git describe on main finds the tag"

run "$repo" merge 0.7.3
expect 0 "a second merge does nothing"
same "$(origin_main "$repo")" "$after" "a second merge pushes nothing"

# An unported commit stops it.
repo="$(setup unported)"
git -C "$repo" switch -q release/0.7.x
write "$repo" line-only one "fix: only on the line"
stuck="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" tag -f v0.7.3 >/dev/null
git -C "$repo" push -q --force origin release/0.7.x v0.7.3
git -C "$repo" switch -q main
before="$(origin_main "$repo")"

run "$repo" check 0.7.3
expect 3 "check stops on an unported commit"
case "$out" in
    *"$stuck"*"fix: only on the line"*) ok "check lists the unported commit" ;;
    *) bad "check did not list the commit: $out" ;;
esac
run "$repo" merge 0.7.3
expect 3 "merge stops on an unported commit"
same "$(origin_main "$repo")" "$before" "a stopped merge pushes nothing"
if git -C "$repo.git" merge-base --is-ancestor v0.7.3 main; then
    bad "a stopped merge must leave the tag off main"
else
    ok "a stopped merge leaves the tag off main"
fi

# A commit that lands on the line after the tag counts too.
repo="$(setup after-tag)"
git -C "$repo" switch -q release/0.7.x
write "$repo" late one "fix: after the tag"
git -C "$repo" push -q origin release/0.7.x
git -C "$repo" switch -q main
run "$repo" check 0.7.3
expect 3 "a line commit after the tag stops it"

# A reviewed sha clears only itself.
repo="$(setup reviewed)"
git -C "$repo" switch -q release/0.7.x
write "$repo" version one "build: declare 0.7.3"
bump="$(git -C "$repo" rev-parse HEAD)"
write "$repo" line-only one "fix: only on the line"
other="$(git -C "$repo" rev-parse HEAD)"
git -C "$repo" tag -f v0.7.3 >/dev/null
git -C "$repo" push -q --force origin release/0.7.x v0.7.3
git -C "$repo" switch -q main
run "$repo" check 0.7.3 "$bump"
expect 3 "one reviewed sha does not clear another commit"
case "$out" in
    *"$bump"*) bad "the reviewed commit is still listed" ;;
    *"$other"*) ok "only the other commit stays listed" ;;
    *) bad "check listed neither commit: $out" ;;
esac
run "$repo" merge 0.7.3 "${bump:0:10}" "$other"
expect 0 "every commit reviewed, short shas included, lets it merge"

# The picked note.
repo="$(setup picked)"
fix="$(git -C "$repo" rev-parse main~1)"
git -C "$repo" switch -q release/0.7.x
write "$repo" fix "resolved by hand" "fix: the fix, resolved

(cherry picked from commit $fix)"
git -C "$repo" tag -f v0.7.3 >/dev/null
git -C "$repo" push -q --force origin release/0.7.x v0.7.3
git -C "$repo" switch -q main
run "$repo" check 0.7.3
expect 3 "a resolved pick still stops it"
case "$out" in
    *"which is on main"*) ok "a resolved pick is marked as on main" ;;
    *) bad "no note on a resolved pick: $out" ;;
esac

# Bad input.
repo="$(setup input)"
run "$repo" check 0.7.3-rc1
expect 2 "a release candidate is refused"
run "$repo" check 0.7
expect 2 "a short version is refused"
run "$repo" check 0.7.3 "--force"
expect 2 "a reviewed value that is not a sha is refused"
run "$repo" nonsense 0.7.3
expect 2 "an unknown mode is refused"
run "$repo" check 0.7.4
if [ "$code" != 0 ]; then ok "a missing tag fails"; else bad "a missing tag passed"; fi

# A tag that is not on the line.
repo="$(setup offline)"
git -C "$repo" tag v0.7.4 main
git -C "$repo" push -q origin v0.7.4
run "$repo" check 0.7.4
expect 1 "a tag off the line is refused"

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
