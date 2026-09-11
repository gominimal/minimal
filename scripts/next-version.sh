#!/usr/bin/env bash
#
# next-version.sh — the next release version, its bump level, and the release
# notes, all derived from the Conventional Commits since the last release.
#
# ONE walk of `<last release tag>..<rev>` reading FULL commit bodies
# (`git log --format=%B`), so a `BREAKING CHANGE:` footer under a plain
# `feat:` subject is seen — the exact entry a subject-line filter drops (the
# 0.5.4 range's detach-chord change had one). Both consumers read that one
# walk rather than each growing its own parser:
#
#   * the bump level: `feat:` -> minor; `fix:`/`perf:` (and a range with
#     nothing release-worthy) -> patch. Commitlint enforces the format, so the
#     range determines the level. Breaking changes (`!` or a
#     `BREAKING CHANGE:`/`BREAKING-CHANGE:` footer) are DETECTED and rendered
#     first in the notes but do NOT move the number while the project is
#     0.x/alpha: no major increment is cut until the team decides on GA, so
#     this lint never demands 1.0.0. ALLOW_MAJOR below is the one-line switch
#     for that day (an explicit item on the GA checklist).
#   * the notes: markdown grouped as breaking changes / features / fixes /
#     other changes, each entry keeping its scope, PR reference, and short sha.
#     Breaking entries carry their footer text.
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
# rc.
#
# Usage:
#   scripts/next-version.sh [options] [MODE]
#
# Modes (default: --next):
#   --next                print the derived next version (X.Y.Z) on stdout
#   --bump                print the bump level: minor | patch (major only with ALLOW_MAJOR=1)
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
# reachable, unreadable Cargo.toml for --check).
#
# Requires: git with the tags fetched (actions/checkout needs fetch-depth: 0;
# the workspace test self-skips on a shallow or tagless clone).

set -euo pipefail

# The GA switch. 0: a breaking change is detected and reported but bumps
# nothing beyond what its type does (0.x/alpha rule). 1: breaking -> major.
ALLOW_MAJOR="${NEXT_VERSION_ALLOW_MAJOR:-0}"

die() {
    printf 'next-version: %s\n' "$1" >&2
    exit 1
}

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

is_semver() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

# --- The tags ----------------------------------------------------------------

# Newest RELEASED tag reachable from the rev: the range base. --exclude drops
# pre-release tags so a final's notes and level cover everything since the
# previous final.
base_tag="$(git -C "$REPO" describe --tags --abbrev=0 --match 'v[0-9]*' --exclude 'v*-*' "$REV" 2>/dev/null || true)"
[ -n "$base_tag" ] || die "no released v* tag (vX.Y.Z) reachable from $REV in $REPO — nothing to derive from (shallow clone? actions/checkout needs fetch-depth: 0)"
base_version="${base_tag#v}"
is_semver "$base_version" || die "tag $base_tag is not a SemVer vX.Y.Z tag"

# Newest v* tag overall, pre-releases included, for the strictly-greater
# check. Git's version sort ranks `v0.6.0-rc1` ABOVE `v0.6.0` unless told a
# `-` suffix is a pre-release.
newest_tag="$(git -C "$REPO" -c versionsort.suffix=- tag -l 'v[0-9]*' --sort=-version:refname | sed -n '1p')"
newest_version="${newest_tag#v}"

# --- The walk ----------------------------------------------------------------
#
# One record per commit: sha, subject, body, separated by \x1f (unit) and
# terminated by \x1e (record), so multi-line bodies survive. Merges carry no
# change of their own (main is squash-merged; a merge commit's subject is
# not a Conventional Commit).

level="patch"
n_commits=0 n_feat=0 n_fix=0 n_breaking=0
breaking_entries=() feat_entries=() fix_entries=() other_entries=()
feat_drivers=()

# entry <sha> <scope> <desc> — one markdown bullet.
entry() {
    local sha="$1" scope="$2" desc="$3"
    if [ -n "$scope" ]; then
        printf -- '- **%s**: %s (%s)' "$scope" "$desc" "$sha"
    else
        printf -- '- %s (%s)' "$desc" "$sha"
    fi
}

# breaking_footer <body> — the BREAKING CHANGE footer paragraph(s), each from
# its footer line to the next blank line or the end of the body.
breaking_footer() {
    printf '%s\n' "$1" | awk '
        /^BREAKING[ -]CHANGE: / { on = 1 }
        /^[[:space:]]*$/       { on = 0 }
        on                     { print }
    '
}

# `type(scope)!: description` — parentheses in a regex literal do not parse
# inside [[ ]], so it lives in a variable.
subject_re='^([a-z]+)(\(([^)]*)\))?(!)?:[[:space:]]+(.+)$'

while IFS=$'\x1f' read -r -d $'\x1e' sha subject body; do
    sha="${sha#"${sha%%[![:space:]]*}"}"   # a leading newline precedes every record but the first
    [ -n "$sha" ] || continue
    n_commits=$((n_commits + 1))
    short="${sha:0:8}"

    type="" scope="" bang="" desc="$subject"
    if [[ "$subject" =~ $subject_re ]]; then
        type="${BASH_REMATCH[1]}"
        scope="${BASH_REMATCH[3]}"
        bang="${BASH_REMATCH[4]}"
        desc="${BASH_REMATCH[5]}"
    fi

    footer="$(breaking_footer "$body")"
    if [ -n "$bang" ] || [ -n "$footer" ]; then
        n_breaking=$((n_breaking + 1))
        e="$(entry "$short" "$scope" "$desc")"
        if [ -n "$footer" ]; then
            e="$e"$'\n\n'"$(printf '%s\n' "$footer" | sed 's/^/  /')"
        fi
        breaking_entries+=("$e")
        [ "$ALLOW_MAJOR" = 1 ] && level=major
    fi

    case "$type" in
        feat)
            n_feat=$((n_feat + 1))
            feat_drivers+=("$short $subject")
            [ "$level" = major ] || level=minor
            [ -n "$bang" ] || [ -n "$footer" ] || feat_entries+=("$(entry "$short" "$scope" "$desc")")
            ;;
        fix|perf)
            n_fix=$((n_fix + 1))
            [ -n "$bang" ] || [ -n "$footer" ] || fix_entries+=("$(entry "$short" "$scope" "$desc")")
            ;;
        *)
            [ -n "$bang" ] || [ -n "$footer" ] || other_entries+=("$(entry "$short" "$scope" "$desc")")
            ;;
    esac
done < <(git -C "$REPO" log --no-merges --reverse --format=$'%H\x1f%s\x1f%b\x1e' "$base_tag..$REV")

# --- The next version --------------------------------------------------------

IFS=. read -r major minor patch <<<"$base_version"
case "$level" in
    major) next="$((major + 1)).0.0" ;;
    minor) next="$major.$((minor + 1)).0" ;;
    patch) next="$major.$minor.$((patch + 1))" ;;
esac

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
    printf '%d commit(s) since %s.\n' "$n_commits" "$base_tag"
    if [ "${#breaking_entries[@]}" -gt 0 ]; then
        printf '\n### Breaking changes\n\n'
        printf '%s\n' "${breaking_entries[@]}"
    fi
    if [ "${#feat_entries[@]}" -gt 0 ]; then
        printf '\n### Features\n\n'
        printf '%s\n' "${feat_entries[@]}"
    fi
    if [ "${#fix_entries[@]}" -gt 0 ]; then
        printf '\n### Fixes\n\n'
        printf '%s\n' "${fix_entries[@]}"
    fi
    if [ "${#other_entries[@]}" -gt 0 ]; then
        printf '\n### Other changes\n\n'
        printf '%s\n' "${other_entries[@]}"
    fi
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
            printf 'next-version: wrote release notes for %s (%d commits since %s) to %s\n' \
                "${package_version:-$next}" "$n_commits" "$base_tag" "$NOTES_FILE" >&2
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
            reason="$n_fix fix/perf commit(s)"
            [ "$level" = minor ] && reason="$n_feat feat commit(s): $(printf '%s; ' "${feat_drivers[@]}" | sed 's/; $//')"
            [ "$level" = major ] && reason="$n_breaking breaking change(s)"
            die "package.version $package_version is behind the commits since $base_tag, which require a $level bump to at least $next ($reason) — bump $CARGO_TOML"
        fi
        printf 'next-version: package.version %s satisfies the %d commit(s) since %s (%s bump, at least %s) and is greater than the newest tag %s\n' \
            "$package_version" "$n_commits" "$base_tag" "$level" "$next" "$newest_tag"
        ;;
esac
