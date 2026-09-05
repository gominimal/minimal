#!/usr/bin/env bash
#
# resolve-release-version_test.sh — test harness for
# scripts/resolve-release-version.sh.
#
# Builds a throwaway git repo with a fixed tag topology (no network, no
# checkout of the real repo) and asserts the resolution contract: exact tag
# wins, newest reachable released tag otherwise, prerelease tags never resolve
# (and never fall through to an older release), untagged history skips with
# exit 3, and a bad sha fails loudly. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/resolve-release-version.sh"
[ -f "$script" ] || { echo "cannot find resolve-release-version.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-reshatest)"
trap 'rm -rf "$root"' EXIT

# Identity through the environment, not repo config: the fixture grows more
# than one repository, and CI runners have no global git identity (an
# un-configured `git commit` dies with "Author identity unknown").
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

repo="$root/repo"
git init -q --bare "$repo/origin.git"
git clone -q "$repo/origin.git" "$repo/work"

# commit <message> [tag...] — one empty commit, optionally tagged at HEAD.
commit() {
    git -C "$repo/work" commit -q --allow-empty -m "$1"
    shift
    local tag
    for tag in "$@"; do
        git -C "$repo/work" tag "$tag"
    done
}

sha_of() {
    git -C "$repo/work" rev-parse "$1"
}

# Pick up tags pushed to the bare origin the way a fetch-depth: 0 checkout
# would see them (tags travel with a clone; commits made after the clone do
# not, so push between the two phases).
push_all() {
    git -C "$repo/work" push -q origin --all
    git -C "$repo/work" push -q origin --tags
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

# expect_out <want_stdout> <description> -- <command...>
expect_out() {
    local want="$1" desc="$2"; shift 2
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local got rc=0
    got="$("$@" 2>/dev/null)" || rc=$?
    if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then
        ok "$desc"
    else
        bad "$desc (want stdout '$want'; got rc=$rc, stdout '$got')"
    fi
}

resolve() {
    "$script" --repo "$repo/work" --sha "$1"
}

# --- fixture topology -------------------------------------------------------
#
# v0.5.3 ── v0.6.0-rc1 ── v0.6.0 ── (untagged head)
#    └── exact-dual (v0.5.4 + v0.5.2 both on one commit)
commit base
commit rel-053 v0.5.3;      tagged="$(sha_of HEAD)"
commit post-053;            post053="$(sha_of HEAD)"
commit rc-060 v0.6.0-rc1;   rc_sha="$(sha_of HEAD)"
commit rel-060 v0.6.0
commit head;                untagged="$(sha_of HEAD)"
commit exact-dual v0.5.4 v0.5.2;   dual="$(sha_of HEAD)"
push_all

# --- the resolution contract ------------------------------------------------

expect_out "0.5.3" "exact tag on the promoted sha resolves it" -- resolve "$tagged"
expect_out "0.5.3" "untagged sha after a tag resolves the newest reachable release" -- resolve "$post053"
expect_out "0.6.0" "sha after two releases resolves the newest" -- resolve "$untagged"

# The head sits after v0.6.0; an RC sha must not fall through to v0.5.3.
expect 3 "prerelease" "sha tagged only with an RC skips (no downgrade fallback)" -- resolve "$rc_sha"
expect_out "0.6.0" "sha after an RC still resolves the released tag" -- resolve "$untagged"

# Two tags on one commit: the newest release wins.
expect_out "0.5.4" "newest of two tags on the same commit wins" -- resolve "$dual"

# A repo with commits but no tags at all skips rather than fabricating one.
git init -q "$repo/no-tags"
git -C "$repo/no-tags" commit -q --allow-empty -m only
expect 3 "no released v* tag reachable" "tagless repo skips" -- \
    "$script" --repo "$repo/no-tags" --sha HEAD

# Hard failures stay hard: an unknown sha and a missing repo.
expect 1 "cannot resolve" "unknown sha fails loudly" -- resolve 0000000000000000000000000000000000000000
expect 1 "git cannot resolve" "missing repo fails loudly" -- "$script" --repo "$root/nope" --sha HEAD

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
