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
#   apk        0.6.0_dev.10.g8e7e72c2   apk has no `~`; `-` is its own
#                                      revision separator (`-r<N>`), so the
#                                      prerelease is glued on with `_`.
#                                      NOTE: apk ordering for this shape is
#                                      asserted only when `apk version -t` is
#                                      on PATH (see package-version_test.sh);
#                                      the fallback if a real apk rejects it is
#                                      `0.6.0_git<N>`.
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
    apk)     repl='_' ;;
    aur)     repl='.' ;;
    brew)    repl='-' ;;
    *)       die "unknown --format '$FORMAT' (want deb, rpm, apk, aur, or brew)" ;;
esac

out="${base//-/$repl}"
[ -z "$build" ] || out="$out+$build"

# A closing veto per charset, so a bug in the substitution above fails here
# rather than on a package manager days later. The allowed set is the union
# that is legal somewhere; `-` is legal only in a Homebrew version (and never
# survives the substitutions anyway).
printf '%s\n' "$out" | grep -qE '^[0-9][0-9A-Za-z.+~_-]*$' \
    || die "'$out' (from '$VERSION' as $FORMAT) is not a legal $FORMAT version"
case "$FORMAT" in
    deb|rpm|apk|aur)
        case "$out" in
            *-*) die "'$out' (from '$VERSION' as $FORMAT) may not contain '-'" ;;
        esac ;;
esac

printf '%s\n' "$out"
