#!/usr/bin/env bash
#
# package-version.sh — normalize one canonical Minimal version into a package
# manager's version charset.
#
# The canonical version is what the shipped binaries report (crates/version):
# a released semver `0.6.0`, or a dev build `0.6.0-dev.10.g8e7e72c2`. Each
# package manager has its own charset and ordering rules for the same string,
# so every channel packager (nfpm's deb/rpm/apk, the AUR, Homebrew) runs it
# through this one helper instead of growing its own substitution:
#
#   deb / rpm  0.6.0~dev.10.g8e7e72c2   `-` introduces a prerelease in semver
#                                      but separates Version from Release in
#                                      rpm and is illegal in a deb Version
#                                      field; `~` sorts BELOW the bare release
#                                      in both, so a user with a stable suite
#                                      enabled stays on stable unless they opt
#                                      into a channel suite explicitly.
#   apk        0.6.0_pre10             apk's grammar is
#                                      number{.number}...{letter}{_suffix{number}}...
#                                      over a FIXED suffix vocabulary (alpha,
#                                      beta, pre, rc, cvs, svn, git, hg, p), so
#                                      neither the `dev` word nor the git hash
#                                      is expressible: a dev tail
#                                      `-dev.<N>.g<hash>` becomes `_pre<N>`.
#                                      `pre` sorts BELOW the release (a channel
#                                      suite must never outrank stable), and <N>
#                                      is the commit count, so successive builds
#                                      stay ordered. The hash is dropped: a
#                                      trailing {<hash>} must be lowercase hex
#                                      and would concatenate onto <N>
#                                      ambiguously (`_pre10` + `8e7e72c2` reads
#                                      as the number 108). A plain prerelease
#                                      keeps its word (`0.6.0-rc1` ->
#                                      `0.6.0_rc1`), which apk already knows.
#                                      KNOWN EDGE: a dev series past a
#                                      prerelease tag (`0.6.0-rc1.dev.<N>`)
#                                      also collapses to `_pre<N>`, losing the
#                                      `rc1` marker and restarting its count;
#                                      apk cannot express "rc1 plus N commits"
#                                      without relying on suffix-array
#                                      comparison this repo cannot exercise
#                                      without an apk host. apk is also the one
#                                      charset with no `+build` separator, so
#                                      build metadata is refused rather than
#                                      silently dropped.
#   aur        0.6.0.dev.10.g8e7e72c2   pacman's pkgver forbids `-`; the
#                                      prerelease becomes one more dot segment.
#   brew       0.6.0-dev.10.g8e7e72c2   Homebrew versions may carry `-`
#                                      verbatim (identity).
#
# For a released semver (no prerelease tail) the normalization is the identity
# in every format: `0.6.0` stays `0.6.0`. That is what keeps the stable nfpm
# packages byte-identical to the ones built before channels existed.
#
# Usage: scripts/package-version.sh --format FORMAT VERSION
#
#   --format FORMAT   One of deb, rpm, apk, aur, brew.
#   VERSION           The canonical version, WITHOUT a leading v.
#
# Prints the normalized version on stdout; exits 1 with a message on stderr for
# an unknown format or a version that is not a canonical semver.
#
# Requires: bash, grep.

set -euo pipefail

die() {
    printf 'package-version: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

FORMAT=""
VERSION=""
while [ $# -gt 0 ]; do
    case "$1" in
        --format) [ -n "${2:-}" ] || die "--format needs a value (deb, rpm, apk, aur, brew)"; FORMAT="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        -*)       die "unknown argument: $1 (try --help)" ;;
        *)        [ -z "$VERSION" ] || die "unexpected extra argument: $1"; VERSION="$1"; shift ;;
    esac
done

[ -n "$FORMAT" ] || die "--format is required (deb, rpm, apk, aur, brew)"
[ -n "$VERSION" ] || die "VERSION is required (the canonical version, without the v prefix)"
case "$VERSION" in
    v*) die "VERSION must not carry the v prefix: '$VERSION' (use ${VERSION#v})" ;;
esac
# The canonical shape crates/version emits: X.Y.Z with an optional prerelease
# and/or build-metadata tail. Rejecting everything else keeps a typo (a bare
# sha, a tag name) from being "normalized" into something a package manager
# accepts but nobody meant to publish.
printf '%s\n' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+_-]+)?$' \
    || die "VERSION '$VERSION' is not a canonical X.Y.Z (optional -prerelease/+build) version"

# Split off semver build metadata first: `+` is legal in every charset below
# and must survive untouched, so only the base (X.Y.Z-pre) is rewritten.
base="${VERSION%%+*}"
build=""
case "$VERSION" in
    *+*) build="${VERSION#*+}" ;;
esac

case "$FORMAT" in
    deb|rpm) repl='~' ;;
    apk)     ;; # handled separately below: apk needs a grammar, not a substitution
    aur)     repl='.' ;;
    brew)    repl='-' ;;
    *)       die "unknown --format '$FORMAT' (want deb, rpm, apk, aur, or brew)" ;;
esac

if [ "$FORMAT" = "apk" ]; then
    # apk is the one charset a blind substitution cannot serve. Its grammar is
    # number{.number}...{letter}{_suffix{number}}...{<hash>}{-r#} over a FIXED
    # suffix vocabulary — alpha, beta, pre, rc, cvs, svn, git, hg, p — so a dev
    # build's `-dev.<N>.g<hash>` tail becomes neither `_dev.10` nor `_g8e7e72c2`
    # and apk rejects the version outright (see the header).
    core="${base%%-*}"
    case "$base" in
        *-*)
            tail="${base#*-}"
            case "$tail" in
                *dev.*)
                    # `-dev.<N>.g<hash>` (and `-rc1.dev.<N>.g<hash>`) -> `_pre<N>`:
                    # `pre` sorts below the release and <N> orders the series.
                    n="${tail#*dev.}"
                    n="${n%%.*}"
                    case "$n" in
                        ''|*[!0-9]*)
                            die "cannot read a commit count from '$VERSION' (want the -dev.<N>.g<hash> shape)" ;;
                    esac
                    out="${core}_pre${n}" ;;
                *)
                    # A plain prerelease word is already a valid apk suffix
                    # (`0.6.0-rc1` -> `0.6.0_rc1`); the veto below rejects one
                    # that is not.
                    out="${core}_${tail}" ;;
            esac ;;
        *) out="$base" ;;
    esac
else
    out="${base//-/$repl}"
fi
[ -z "$build" ] || out="$out+$build"

# A closing veto per charset, so a bug in the mapping above fails here rather
# than on a package manager days later. apk gets the real grammar rather than
# the cross-format union: it is the one charset that silently rejects a
# prerelease it cannot parse, and the only one with no `+` separator at all
# (so build metadata is refused here instead of producing a package apk will
# not install).
if [ "$FORMAT" = "apk" ]; then
    printf '%s\n' "$out" | grep -qE '^[0-9]+(\.[0-9]+)*[a-z]?(_(alpha|beta|pre|rc|cvs|svn|git|hg|p)[0-9]*)*$' \
        || die "'$out' (from '$VERSION' as apk) is not a valid apk version — apk suffixes are alpha, beta, pre, rc, cvs, svn, git, hg, p only, and there is no +build separator"
else
    # The allowed set is the union that is legal somewhere; `-` is legal only in
    # a Homebrew version (and never survives the substitutions anyway).
    printf '%s\n' "$out" | grep -qE '^[0-9][0-9A-Za-z.+~_-]*$' \
        || die "'$out' (from '$VERSION' as $FORMAT) is not a legal $FORMAT version"
fi
case "$FORMAT" in
    deb|rpm|apk|aur)
        case "$out" in
            *-*) die "'$out' (from '$VERSION' as $FORMAT) may not contain '-'" ;;
        esac ;;
esac

printf '%s\n' "$out"
