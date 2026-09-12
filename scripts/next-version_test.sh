#!/usr/bin/env bash
#
# next-version_test.sh — test harness for scripts/next-version.sh.
#
# Builds a throwaway git repo with a fixed tag topology and Conventional
# Commit history (no network, no checkout of the real repo) and asserts the
# derivation contract: feat -> minor, fix/perf and everything else -> patch,
# breaking changes detected from `!` AND from body-only footers but never
# moving the number while ALLOW_MAJOR is off, pre-release tags skipped over as
# the range base yet counted by the strictly-greater lint, and --check's two
# rules. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/next-version.sh"
[ -f "$script" ] || { echo "cannot find next-version.sh next to test" >&2; exit 1; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-nexttest)"
trap 'rm -rf "$root"' EXIT

# Identity through the environment, not repo config: CI runners have no
# global git identity (an un-configured `git commit` dies with "Author
# identity unknown").
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com

repo="$root/repo"
git init -q "$repo"

# commit <message> [tag...] — one empty commit (message may be multi-line),
# optionally tagged at HEAD.
commit() {
    git -C "$repo" commit -q --allow-empty -m "$1"
    shift
    local tag
    for tag in "$@"; do
        git -C "$repo" tag "$tag"
    done
}

# cargo_toml <version-line> — write a fixture Cargo.toml carrying the given package.version.
cargo_toml() {
    printf '[package]\nname = "minimal"\nversion = "0.0.0"\npackage.version = "%s"\n' "$1" >"$root/Cargo.toml"
}

pass=0 fail=0
# ok / bad <description> — count and print one passing / failing case.
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
        bad "$desc (want '$want'; got rc=$rc, '$got')"
    fi
}

# expect_notes <description> <substring>... — the notes contain every substring.
expect_notes() {
    local desc="$1"; shift
    local notes rc=0 want
    notes="$(nv --notes --cargo-toml "$root/absent.toml" 2>&1)" || rc=$?
    [ "$rc" -eq 0 ] || { bad "$desc (--notes rc=$rc: $notes)"; return; }
    for want in "$@"; do
        [[ "$notes" == *"$want"* ]] || { bad "$desc (missing '$want' in: $notes)"; return; }
    done
    ok "$desc"
}

# refute_notes <description> <substring>... — the notes contain none of them.
refute_notes() {
    local desc="$1"; shift
    local notes rc=0 want
    notes="$(nv --notes --cargo-toml "$root/absent.toml" 2>&1)" || rc=$?
    [ "$rc" -eq 0 ] || { bad "$desc (--notes rc=$rc: $notes)"; return; }
    for want in "$@"; do
        [[ "$notes" != *"$want"* ]] || { bad "$desc (unexpected '$want' in: $notes)"; return; }
    done
    ok "$desc"
}

# nv <args...> — the script under test against the fixture repo.
nv() {
    "$script" --repo "$repo" "$@"
}

# check <version> — write the fixture package.version, then run --check against it.
check() {
    cargo_toml "$1"
    nv --check --cargo-toml "$root/Cargo.toml"
}

# --- no release tag ---------------------------------------------------------

commit "chore: initial"
expect 1 "no released v* tag" "untagged history is a hard error" -- nv

# --- fix-only range: patch --------------------------------------------------

commit "feat: the 0.5.4 feature" v0.5.4
expect_out "0.5.5" "exactly on the tag: next is a patch" -- nv
expect_out "patch" "exactly on the tag: bump is patch" -- nv --bump

commit "fix(lcache): handle concurrent rename"
commit "docs: explain things"
commit "build(deps): bump the cargo group"
expect_out "0.5.5" "fix + docs + build: next is a patch" -- nv --next
expect_out "patch" "fix + docs + build: bump is patch" -- nv --bump
expect_notes "notes group fixes and other changes with scope and sha" \
    "## 0.5.5" "3 commit(s) since v0.5.4." "### Fixes" \
    "- **lcache**: handle concurrent rename (" "### Other changes" "- explain things (" \
    "- **deps**: bump the cargo group ("
refute_notes "a fix-only range has no features or breaking sections" "### Features" "### Breaking"

expect 0 "satisfies the 3 commit(s) since v0.5.4 (patch bump, at least 0.5.5)" \
    "check: 0.5.5 declared over a fix-only range passes" -- check 0.5.5
expect 0 "package.version 0.6.0 satisfies" "check: declaring more than required is allowed" -- check 0.6.0
expect 1 "package.version 0.5.4 is not strictly greater than the newest tag v0.5.4" \
    "check: the shipped version is stale" -- check 0.5.4
expect 1 "package.version 0.5.3 is not strictly greater than the newest tag v0.5.4" \
    "check: an older version is stale" -- check 0.5.3

# --- a feat: minor ------------------------------------------------------------

commit "feat(sessions): add a thing (#123)"
expect_out "0.6.0" "a feat makes the next a minor" -- nv
expect_out "minor" "a feat makes the bump minor" -- nv --bump
expect_notes "notes list the feature" "### Features" "- **sessions**: add a thing (#123) ("
expect 1 "package.version 0.5.5 is behind the commits since v0.5.4, which require a minor bump to at least 0.6.0 (1 feat commit(s): " \
    "check: a patch declared over a feat range fails, naming the feat" -- check 0.5.5
expect 0 "package.version 0.6.0 satisfies" "check: the minor passes" -- check 0.6.0
expect 0 "package.version 0.6.0-rc1 satisfies" "check: a pre-release of the minor passes (cores compared)" -- check 0.6.0-rc1
expect 0 "package.version 0.7.0 satisfies" "check: over-declaring passes" -- check 0.7.0
expect 1 "is not SemVer" "check: a non-SemVer package.version fails" -- check 0.6

# --- breaking changes: detected, never a major while alpha -------------------

commit "feat(minimald)!: swap the wire contract

BREAKING CHANGE: the exec-channel wire contract changed, so a client and
daemon from different builds cannot talk.

Refs: #1"
expect_out "0.6.0" "a bang feat still bumps minor only (alpha: no major)" -- nv
expect_out "minor" "bump stays minor under a breaking change" -- nv --bump
expect_notes "breaking entry is rendered first with its footer paragraph" \
    "### Breaking changes" "- **minimald**: swap the wire contract (" \
    "  BREAKING CHANGE: the exec-channel wire contract changed, so a client and" \
    "  daemon from different builds cannot talk."
refute_notes "footers past the BREAKING CHANGE paragraph are dropped" "Refs: #1"
n_listed="$(nv --notes --cargo-toml "$root/absent.toml" 2>/dev/null | grep -c -- '- \*\*minimald\*\*: swap the wire contract (' || true)"
if [ "$n_listed" -eq 1 ]; then
    ok "the breaking entry is listed once, not repeated under features"
else
    bad "the breaking entry is listed $n_listed times (want 1)"
fi

commit "feat(minimald): move the detach chord off ctrl-w

Two clients with different configs on the same session each get their own
chord.

BREAKING CHANGE: the default detach chord changes from ctrl-w to ctrl-]"
expect_notes "a body-only BREAKING CHANGE footer under a plain feat subject is caught" \
    "- **minimald**: move the detach chord off ctrl-w (" \
    "  BREAKING CHANGE: the default detach chord changes from ctrl-w to ctrl-]"

commit "fix: something

BREAKING-CHANGE: the hyphenated spelling counts too"
expect_notes "BREAKING-CHANGE (hyphen) is detected" "  BREAKING-CHANGE: the hyphenated spelling counts too"
expect_out "0.6.0" "three breaking changes: still a minor" -- nv
expect_out "1.0.0" "the GA switch turns breaking into a major" -- \
    env NEXT_VERSION_ALLOW_MAJOR=1 "$script" --repo "$repo"
expect_out "major" "the GA switch reports a major bump" -- \
    env NEXT_VERSION_ALLOW_MAJOR=1 "$script" --repo "$repo" --bump
cargo_toml 0.6.0
expect 1 "require a major bump to at least 1.0.0 (3 breaking change(s))" \
    "the GA switch makes --check demand the major" -- \
    env NEXT_VERSION_ALLOW_MAJOR=1 "$script" --repo "$repo" --check --cargo-toml "$root/Cargo.toml"

# --- pre-release tags: skipped as the base, counted by the lint --------------

commit "chore: cut rc1" v0.6.0-rc1
commit "fix(op): an rc fix"
expect_out "0.6.0" "an rc tag is not the range base: the final's derivation still spans since v0.5.4" -- nv
expect_notes "notes for the final cover the whole range since the previous final" \
    "since v0.5.4." "- **sessions**: add a thing (#123) (" "- **op**: an rc fix ("
expect 1 "package.version 0.6.0-rc1 is not strictly greater than the newest tag v0.6.0-rc1" \
    "check: the cut rc's own version is stale once tagged" -- check 0.6.0-rc1
expect 0 "package.version 0.6.0-rc2 satisfies" "check: the next rc passes" -- check 0.6.0-rc2
expect 0 "package.version 0.6.0 satisfies" "check: the final passes" -- check 0.6.0
expect 1 "not strictly greater than the newest tag v0.6.0-rc1" \
    "check: an rc below the cut rc is stale" -- check 0.6.0-rc0
expect 0 "package.version 0.6.0-rc1.1 satisfies" "check: a longer pre-release ranks above its prefix" -- check 0.6.0-rc1.1

# --- non-SemVer v* tags are ignored -------------------------------------------

commit "chore: a tag that only looks like a version" v999-backup v999backup
expect_out "0.6.0" "v999-backup / v999backup do not become the newest tag or the range base" -- nv
expect 0 "package.version 0.6.0 satisfies" "check: malformed v* tags do not fail a valid package.version" -- check 0.6.0
expect 0 "is greater than the newest tag v0.6.0-rc1" "check: the newest tag is still the newest SemVer one" -- check 0.6.0
expect_notes "notes still span since the last released SemVer tag" "since v0.5.4."

# --- --rev walks an older release point ---------------------------------------

expect_out "0.5.5" "--rev at the fix-only commit derives a patch" -- nv --next --rev v0.5.4~0
expect_out "0.5.5" "--rev before the feat derives a patch" -- nv --next --rev v0.6.0-rc1~5
expect 1 "git cannot resolve nope" "--rev with an unknown rev fails loudly" -- nv --rev nope

# --- --notes FILE -------------------------------------------------------------

cargo_toml 0.6.0
expect 0 "wrote release notes for 0.6.0" "--notes FILE writes the file and reports" -- \
    nv --notes "$root/notes.md" --cargo-toml "$root/Cargo.toml"
if [ -f "$root/notes.md" ] && head -n 1 "$root/notes.md" | grep -q '^## 0.6.0$'; then
    ok "--notes FILE titles the notes with package.version"
else
    bad "--notes FILE did not write a file titled with package.version"
fi

# --- malformed input -----------------------------------------------------------

expect 1 "no such Cargo.toml" "--check without a Cargo.toml fails loudly" -- \
    nv --check --cargo-toml "$root/absent.toml"
printf '# package.version moved into a comment\n' >"$root/Cargo.toml"
expect 1 "could not extract package.version" "--check with no package.version fails loudly" -- \
    nv --check --cargo-toml "$root/Cargo.toml"
expect 1 "unknown argument" "unknown flags are rejected" -- nv --bogus

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
