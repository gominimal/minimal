#!/usr/bin/env bash
#
# stage-version.sh — the version a release line stages next.
#
# gs://minimal-one/versions/<version>/ is write-once, so a number is used up
# once it is tagged or staged, promoted or not. A candidate uses up only its
# own number: 0.7.3 stays free after 0.7.3-rc1 is staged.
#
# release/X.Y.x next stages X.Y.N or X.Y.N-rcM. N is one above the highest
# final version used on the line (0 if there is none). M is one above the
# highest candidate of X.Y.N (1 if there is none).
#
# Usage:
#   scripts/stage-version.sh --newest-line < branch-names
#   scripts/stage-version.sh --next --line release/X.Y.x --used FILE
#   scripts/stage-version.sh --check --line release/X.Y.x --used FILE --version V
#   scripts/stage-version.sh --check --line release/X.Y.x --used FILE --version V \
#       --restage --smoked FILE
#
# --used lists one version a line: tags without the v, and staged row names.
# --smoked lists the rows that have a smoke record. A row name that is not a
# version, such as a nightly sha, is ignored.
#
# --newest-line prints the highest release/X.Y.x. --next prints the next final
# version. --check fails unless V is the next final or the next candidate. With
# --restage it fails unless V is staged and has no smoke record, which is the
# one case release.yml's restage input exists for.

set -euo pipefail

die() {
    printf 'stage-version: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

MODE="" LINE="" USED="" SMOKED="" VERSION="" RESTAGE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --newest-line) MODE="newest-line"; shift ;;
        --next)        MODE="next"; shift ;;
        --check)       MODE="check"; shift ;;
        --line)        [ -n "${2:-}" ] || die "--line needs a branch"; LINE="$2"; shift 2 ;;
        --used)        [ -n "${2:-}" ] || die "--used needs a file"; USED="$2"; shift 2 ;;
        --smoked)      [ -n "${2:-}" ] || die "--smoked needs a file"; SMOKED="$2"; shift 2 ;;
        --version)     [ -n "${2:-}" ] || die "--version needs a version"; VERSION="$2"; shift 2 ;;
        --restage)     RESTAGE=1; shift ;;
        -h|--help)     usage 0 ;;
        *)             die "unknown argument: $1 (try --help)" ;;
    esac
done

if [ "$MODE" = "newest-line" ]; then
    newest="$(grep -E '^release/[0-9]+\.[0-9]+\.x$' | sort -V | tail -n 1 || true)"
    [ -n "$newest" ] || die "no release/X.Y.x branch"
    printf '%s\n' "$newest"
    exit 0
fi

[ -n "$MODE" ] || die "pick a mode: --newest-line, --next or --check"
[[ "$LINE" =~ ^release/([0-9]+)\.([0-9]+)\.x$ ]] || die "not a release line: '$LINE'"
major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}"
[ -f "$USED" ] || die "--used file not found: '$USED'"

# highest <regex> <suffix-to-strip> — the highest number that ends a matching
# line of --used, or nothing.
highest() {
    { grep -E "$1" "$USED" || true; } | sed "s/$2//" | sort -n | tail -n 1
}

patch="$(highest "^$major\.$minor\.[0-9]+$" '.*\.')"
next="$major.$minor.$((${patch:--1} + 1))"
rc="$(highest "^$major\.$minor\.$((${patch:--1} + 1))-rc[0-9]+$" '.*-rc')"
next_rc="$next-rc$((${rc:-0} + 1))"

if [ "$MODE" = "next" ]; then
    printf '%s\n' "$next"
    exit 0
fi

[ -n "$VERSION" ] || die "--check needs --version"
case "$VERSION" in
    "$major.$minor."*) ;;
    *) die "$VERSION does not belong on $LINE" ;;
esac

if [ "$RESTAGE" -eq 1 ]; then
    [ -f "$SMOKED" ] || die "--smoked file not found: '$SMOKED'"
    grep -qxF -- "$VERSION" "$USED" || die "$VERSION is not staged, so there is nothing to restage"
    if grep -qxF -- "$VERSION" "$SMOKED"; then
        die "$VERSION has a smoke record, so it stays as it is; stage $next or $next_rc"
    fi
    printf 'stage-version: restaging %s, which has no smoke record\n' "$VERSION"
    exit 0
fi

if [ "$VERSION" != "$next" ] && [ "$VERSION" != "$next_rc" ]; then
    if grep -qxF -- "$VERSION" "$USED"; then
        die "$VERSION is already used and cannot be staged again; set package.version on $LINE to $next or $next_rc"
    fi
    die "$VERSION is not next on $LINE; set package.version to $next or $next_rc"
fi
printf 'stage-version: %s is next on %s\n' "$VERSION" "$LINE"
