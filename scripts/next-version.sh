#!/usr/bin/env bash
#
# next-version.sh — the next release version, its bump level, and the release
# notes, derived from the Conventional Commits since the last release.
#
# The derivation is git-cliff's (config: cliff.toml at the repo root), run
# through scripts/git-cliff.sh so nothing has to be installed:
#
#   * the next version and its bump level: git-cliff --bumped-version, from the
#     [bump] rules in cliff.toml. A feature is always a minor; a breaking change
#     is a minor while the major is 0 (NEXT_VERSION_ALLOW_MAJOR=1 makes it a
#     major, the GA switch). Commitlint enforces the commit format, so the range
#     determines the level.
#   * the notes: cliff.toml's template and commit_parsers, grouped as
#     breaking changes / features / fixes / other changes, each entry keeping
#     its scope, PR reference, and short sha. A `BREAKING CHANGE:` footer under
#     a plain `feat:` subject is seen, and rendered first.
#
# This script keeps the parts that are policy rather than derivation: which tag
# is the range base, the "N commit(s) since <tag>" header line, and --check.
#
# The declared version lives in Cargo.toml `package.version`: the base of
# every `-dev.N.g<sha>` build and the version a release build is given as
# MINIMAL_RELEASE_VERSION (crates/version/src/scheme.rs). --check is the lint
# that keeps it honest — checked on every PR through the workspace
# `package_version` test (crates/common/tests/package_version.rs) and `just
# check-version`, so drift fails the PR that introduces it, not the release:
#
#   1. strictly greater than the newest v* tag (pre-release tags included:
#      after `v0.6.0-rc1` is cut, `0.6.0-rc1` must become `0.6.0-rc2` or
#      `0.6.0`);
#   2. at least the version the commits since the last release require,
#      comparing cores, so a declared `0.6.0-rc1` satisfies a required `0.6.0`.
#      Declaring MORE than required (a deliberate minor over a fix-only range)
#      is allowed; declaring less is the drift this catches.
#
# The range base is the newest RELEASED tag reachable from the rev (plain
# vX.Y.Z; `v0.6.0-rc1` is skipped over), so the notes and the level for a
# final release cover everything since the previous final, not just the last
# rc. git-cliff only ever sees SemVer v* tags (cliff.toml's tag_pattern), so a
# `vendor/…-20260901` or `release-<sha>` tag cannot become a version.
#
# Usage:
#   scripts/next-version.sh [options] [MODE]
#
# Modes (default: --next):
#   --next                print the derived next version (X.Y.Z) on stdout
#   --bump                print the bump level: major | minor | patch
#   --notes [FILE]        write release-notes markdown to FILE (stdout if omitted)
#   --check               assert Cargo.toml package.version against the derivation
#
# Options:
#   --repo DIR            repository to walk (default: this script's checkout)
#   --rev REV             the release commit (default: HEAD)
#   --cargo-toml FILE     Cargo.toml carrying package.version (default:
#                         <repo>/Cargo.toml). Required by --check; --notes
#                         titles the notes with it when readable, else with
#                         the derived next version.
#   -h, --help            show this help
#
# Exit codes: 0 ok; 1 lint failure or hard error (no git, no released v* tag
# reachable, unreadable Cargo.toml for --check, git-cliff unavailable).
#
# Requires: git with the tags fetched (actions/checkout needs fetch-depth: 0;
# the workspace test self-skips on a shallow or tagless clone). git-cliff is
# fetched and verified by scripts/git-cliff.sh; set GIT_CLIFF_BIN to use a
# local build instead.

set -euo pipefail

# The GA switch. 0: a breaking change is detected and reported but bumps only
# to a minor while the project is 0.x. 1: breaking -> major. Mirrors
# cliff.toml's breaking_always_bump_major.
ALLOW_MAJOR="${NEXT_VERSION_ALLOW_MAJOR:-0}"

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'next-version: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

REPO=""
REV="HEAD"
CARGO_TOML=""
MODE="next"
NOTES_FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --repo)       [ -n "${2:-}" ] || die "--repo needs a directory"; REPO="$2"; shift 2 ;;
        --rev)        [ -n "${2:-}" ] || die "--rev needs a revision"; REV="$2"; shift 2 ;;
        --cargo-toml) [ -n "${2:-}" ] || die "--cargo-toml needs a file"; CARGO_TOML="$2"; shift 2 ;;
        --next)       MODE="next"; shift ;;
        --bump)       MODE="bump"; shift ;;
        --check)      MODE="check"; shift ;;
        --notes)
            MODE="notes"; shift
            if [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; then
                NOTES_FILE="$1"; shift
            fi
            ;;
        -h|--help)    usage 0 ;;
        *)            die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$REPO" ] || REPO="$(cd "$(dirname "$0")/.." && pwd)"
[ -n "$CARGO_TOML" ] || CARGO_TOML="$REPO/Cargo.toml"

command -v git >/dev/null 2>&1 || die "git not found"
git -C "$REPO" rev-parse --verify --quiet "${REV}^{commit}" >/dev/null 2>&1 \
    || die "git cannot resolve $REV in $REPO (bad rev, or a checkout without history)"

# The wrapper and its config belong to this installation, not to the repo being
# walked (--repo names the git repo to read). Resolved next to this script.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIFF="$SCRIPT_DIR/git-cliff.sh"
CONFIG="$SCRIPT_DIR/../cliff.toml"
[ -x "$CLIFF" ] || die "missing $CLIFF"
[ -f "$CONFIG" ] || die "missing $CONFIG"

# NEXT_VERSION_ALLOW_MAJOR=1 flips the one [bump] rule that is a release-policy
# switch rather than a fact about the commits. Edited into a temp copy so the
# checked-in cliff.toml keeps its 0.x default and the CLI stays the same.
cliff_config="$CONFIG"
if [ "$ALLOW_MAJOR" = 1 ]; then
    # A temp dir, not a bare mktemp file: git-cliff infers the config format
    # from the extension, so the copy has to be named cliff.toml.
    cliff_tmpdir="$(mktemp -d)"
    cliff_config="$cliff_tmpdir/cliff.toml"
    trap 'rm -f "$cliff_config"; rmdir "$cliff_tmpdir" 2>/dev/null || true' EXIT
    sed 's/^breaking_always_bump_major = false/breaking_always_bump_major = true/' "$CONFIG" >"$cliff_config"
fi

# --- SemVer precedence -------------------------------------------------------

# semver_cmp A B — prints lt | eq | gt under SemVer 2.0 precedence (build
# metadata ignored; a version without a pre-release ranks above one with).
# `sort -V` gets pre-releases backwards (0.6.0 < 0.6.0-rc1), hence this.
semver_cmp() {
    local a="${1%%+*}" b="${2%%+*}"
    local acore="${a%%-*}" bcore="${b%%-*}" apre="" bpre=""
    [ "$a" = "$acore" ] || apre="${a#*-}"
    [ "$b" = "$bcore" ] || bpre="${b#*-}"
    local -a ac bc ap bp
    IFS=. read -r -a ac <<<"$acore"
    IFS=. read -r -a bc <<<"$bcore"
    local i
    for i in 0 1 2; do
        if [ "${ac[i]:-0}" -lt "${bc[i]:-0}" ]; then echo lt; return; fi
        if [ "${ac[i]:-0}" -gt "${bc[i]:-0}" ]; then echo gt; return; fi
    done
    if [ -z "$apre" ] && [ -z "$bpre" ]; then echo eq; return; fi
    if [ -z "$apre" ]; then echo gt; return; fi
    if [ -z "$bpre" ]; then echo lt; return; fi
    IFS=. read -r -a ap <<<"$apre"
    IFS=. read -r -a bp <<<"$bpre"
    local n="${#ap[@]}" x y
    [ "${#bp[@]}" -gt "$n" ] && n="${#bp[@]}"
    for (( i = 0; i < n; i++ )); do
        x="${ap[i]:-}"; y="${bp[i]:-}"
        [ -n "$x" ] || { echo lt; return; }   # fewer identifiers ranks lower
        [ -n "$y" ] || { echo gt; return; }
        if [[ "$x" =~ ^[0-9]+$ && "$y" =~ ^[0-9]+$ ]]; then
            if [ "$x" -lt "$y" ]; then echo lt; return; fi
            if [ "$x" -gt "$y" ]; then echo gt; return; fi
        elif [[ "$x" =~ ^[0-9]+$ ]]; then echo lt; return   # numeric < alphanumeric
        elif [[ "$y" =~ ^[0-9]+$ ]]; then echo gt; return
        elif [[ "$x" < "$y" ]]; then echo lt; return
        elif [[ "$x" > "$y" ]]; then echo gt; return
        fi
    done
    echo eq
}

# is_semver <version> — SemVer 2.0 shape: X.Y.Z with optional -pre and +build tails.
is_semver() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

# --- The tags ----------------------------------------------------------------

# Only tags that are SemVer (`vX.Y.Z[-pre][+build]`) count: `v[0-9]*` alone
# would also match a `v999-backup` or `v999backup`, and either would win a
# version sort. Newest first — git's version sort ranks `v0.6.0-rc1` ABOVE
# `v0.6.0` unless told a `-` suffix is a pre-release.
semver_tags() {
    git -C "$REPO" -c versionsort.suffix=- tag -l 'v[0-9]*' --sort=-version:refname "$@" \
        | while IFS= read -r t; do is_semver "${t#v}" && printf '%s\n' "$t"; done
}

# Newest RELEASED tag reachable from the rev: the range base. Pre-release
# tags are skipped so a final's notes and level cover everything since the
# previous final.
# (`|| true`: under pipefail an empty selection is grep's exit 1, which must
# reach the die below as "no tag", not abort the substitution silently.)
base_tag="$(semver_tags --merged "$REV" | grep -v -- '-' | sed -n '1p' || true)"
[ -n "$base_tag" ] || die "no released v* tag (vX.Y.Z) reachable from $REV in $REPO — nothing to derive from (shallow clone? actions/checkout needs fetch-depth: 0)"
base_version="${base_tag#v}"

# Newest SemVer tag overall, pre-releases included, for the strictly-greater
# check. Deliberately NOT scoped to tags reachable from the rev (unlike the
# range base above): tags are one namespace for the whole repository, and a
# release must exceed every version ever tagged, whatever branch it was cut
# from — the publishers (Homebrew, AUR) have no channels, so a version below
# an existing tag is a downgrade for their users and an equal one is a tag
# collision at publish. A tag on an unmerged branch that sits above
# package.version therefore fails --check on purpose: main's declared next
# release is genuinely wrong until it is bumped past it.
newest_tag="$(semver_tags | sed -n '1p' || true)"
newest_version="${newest_tag#v}"

# --- The derivation ----------------------------------------------------------
#
# git-cliff's --bumped-version reads the range's commits under cliff.toml's
# [bump] rules and returns the next version, `v`-prefixed.

bumped=""
range_commits="$(git -C "$REPO" rev-list --no-merges --count "$base_tag..$REV")"
if [ "$range_commits" -eq 0 ]; then
    # Nothing since the last release (a rev cut exactly on its tag). The
    # contract is a patch — a release always increments — but an empty range
    # makes git-cliff fall back to the whole history, so bump it here.
    IFS=. read -r base_major base_minor base_patch <<<"${base_version%%-*}"
    next="$base_major.$base_minor.$((base_patch + 1))"
else
    # RUST_LOG=off swallows git-cliff's success INFO line but not its errors: a
    # config or template parse failure prints its real reason to our stderr
    # before the die, instead of dying with only a guess.
    bumped="$( cd "$REPO" && RUST_LOG=off "$CLIFF" --config "$cliff_config" "$base_tag..$REV" --bumped-version )" \
        || die "git-cliff --bumped-version failed"
    next="${bumped#v}"
fi

# The bump level, from base -> next. Three numeric fields, so a field compare
# is enough; a pre-release on either side cannot change which field moved.
IFS=. read -r base_major base_minor _ <<<"${base_version%%-*}"
IFS=. read -r next_major next_minor _ <<<"${next%%-*}"
if [ "$next_major" != "$base_major" ]; then level=major
elif [ "$next_minor" != "$base_minor" ]; then level=minor
else level="patch"
fi

# --- Cargo.toml package.version ---------------------------------------------

# The workspace `package.version` line. `head -n 1`: the first match is the
# [package] table's own key (later tables never repeat it, but a comment or a
# dependency table must not win either). Same extraction as
# scripts/assert-release-version.sh.
package_version=""
if [ -f "$CARGO_TOML" ]; then
    package_version="$(sed -n 's/^package\.version[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$CARGO_TOML" | head -n 1)"
fi

# --- Output ------------------------------------------------------------------

emit_notes() {
    local title="${package_version:-$next}"
    printf '## %s\n\n' "$title"
    # --no-merges so the count matches the sections: cliff.toml skips merges.
    printf '%d commit(s) since %s.\n\n' \
        "$range_commits" "$base_tag"
    # git-cliff reads the repository from its working directory, so run it in
    # $REPO (which --repo may have pointed elsewhere) while --config and the
    # wrapper stay absolute. The awk trims git-cliff's leading/trailing blanks.
    ( cd "$REPO" && RUST_LOG=off "$CLIFF" --config "$cliff_config" "$base_tag..$REV" --tag "$next" ) \
        | awk '{ line[NR] = $0 } $0 != "" { if (!first) first = NR; last = NR }
               END { for (i = first; i <= last; i++) print line[i] }'
}

case "$MODE" in
    next)
        printf '%s\n' "$next"
        ;;
    bump)
        printf '%s\n' "$level"
        ;;
    notes)
        if [ -n "$NOTES_FILE" ]; then
            emit_notes >"$NOTES_FILE"
            printf 'next-version: wrote release notes for %s (%s bump, since %s) to %s\n' \
                "${package_version:-$next}" "$level" "$base_tag" "$NOTES_FILE" >&2
        else
            emit_notes
        fi
        ;;
    check)
        [ -f "$CARGO_TOML" ] || die "no such Cargo.toml: $CARGO_TOML"
        [ -n "$package_version" ] || die "could not extract package.version from $CARGO_TOML"
        is_semver "$package_version" || die "package.version '$package_version' in $CARGO_TOML is not SemVer"

        if [ "$(semver_cmp "$package_version" "$newest_version")" != gt ]; then
            die "package.version $package_version is not strictly greater than the newest tag $newest_tag — $CARGO_TOML must declare the NEXT release (the commits since $base_tag require at least $next)"
        fi
        declared_core="${package_version%%-*}"
        declared_core="${declared_core%%+*}"
        if [ "$(semver_cmp "$declared_core" "$next")" = lt ]; then
            die "package.version $package_version is behind the $range_commits commit(s) since $base_tag, which require a $level bump to at least $next — bump $CARGO_TOML"
        fi
        printf 'next-version: package.version %s satisfies the %d commit(s) since %s (%s bump, at least %s) and is greater than the newest tag %s\n' \
            "$package_version" "$range_commits" "$base_tag" "$level" "$next" "$newest_tag"
        ;;
esac
