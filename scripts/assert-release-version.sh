#!/usr/bin/env bash
#
# assert-release-version.sh — the version being released must match
# package.version in Cargo.toml.
#
# Two flows carry a release version to assert (crates/version/src/scheme.rs):
#
#   * MINIMAL_RELEASE_VERSION set: a release build on an untagged commit. The
#     binaries report that value verbatim, so it must be the workspace
#     package.version (build.rs fails the build on a mismatch; this script
#     fails the job before the expensive builds start).
#   * a v* tag push: the tag is the version, and package.version is what a
#     no-.git build (a source tarball) reports, so the two must agree.
#
# Workflow-dispatch and the nightly (release-<sha>) flows carry neither and
# skip. When both are present, both are asserted.
#
# Usage: scripts/assert-release-version.sh [--tag v0.5.4] [--cargo-toml FILE]
#   --tag         the ref being released (default: GITHUB_REF_NAME with
#                 GITHUB_REF_TYPE; when neither carries a tag the script
#                 asserts nothing about the tag)
#   --cargo-toml  Cargo.toml to read (default: <repo root>/Cargo.toml; the flag
#                 exists so the harness can test against a fixture)
#
# Env: MINIMAL_RELEASE_VERSION — asserted equal to package.version when set.
#
# Exit codes: 0 = matches (or nothing to assert), 1 = mismatch or unreadable
# input.

set -euo pipefail

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'assert-release-version: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

REF_NAME="${GITHUB_REF_NAME:-}"
REF_TYPE="${GITHUB_REF_TYPE:-}"
CARGO_TOML=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tag) [ -n "${2:-}" ] || die "--tag needs a value"; REF_NAME="$2"; REF_TYPE="tag"; shift 2 ;;
        --cargo-toml) [ -n "${2:-}" ] || die "--cargo-toml needs a file"; CARGO_TOML="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$CARGO_TOML" ] || CARGO_TOML="$(cd "$(dirname "$0")/.." && pwd)/Cargo.toml"

release_version="${MINIMAL_RELEASE_VERSION:-}"

# Tags are vX.Y.Z (and vX.Y.Z-rc.N); package.version is X.Y.Z. Anything else
# (a branch ref on workflow dispatch, release-<sha> nightly refs) carries no
# tag version to assert.
tag_version=""
if [ "$REF_TYPE" = "tag" ]; then
    case "$REF_NAME" in
        v[0-9]*) tag_version="${REF_NAME#v}" ;;
        *) echo "assert-release-version: ref $REF_NAME is not a v* semver tag — no tag version to assert" ;;
    esac
else
    echo "assert-release-version: not a tag push (ref ${REF_NAME:-<none>}, type ${REF_TYPE:-<none>}) — no tag version to assert"
fi

if [ -z "$release_version" ] && [ -z "$tag_version" ]; then
    echo "assert-release-version: MINIMAL_RELEASE_VERSION unset — nothing to assert"
    exit 0
fi

[ -f "$CARGO_TOML" ] || die "no such Cargo.toml: $CARGO_TOML"

# The workspace `package.version` line. `head -n 1`: the first match is the
# [package] table's own key (later tables never repeat it, but a comment or a
# dependency table must not win either).
package_version="$(sed -n 's/^package\.version[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$CARGO_TOML" | head -n 1)"
[ -n "$package_version" ] || die "could not extract package.version from $CARGO_TOML"

if [ -n "$release_version" ]; then
    if [ "$package_version" != "$release_version" ]; then
        die "MINIMAL_RELEASE_VERSION is $release_version but package.version is $package_version — they must match (crates/version/build.rs bakes the override into every binary verbatim). Bump package.version in Cargo.toml (scripts/next-version.sh --check says what the commits require) or fix the override."
    fi
    echo "assert-release-version: package.version ($package_version) matches MINIMAL_RELEASE_VERSION"
fi

if [ -n "$tag_version" ]; then
    if [ "$package_version" != "$tag_version" ]; then
        die "releasing $REF_NAME but package.version is $package_version — they must match (crates/version/build.rs falls back to package.version when no v* git tag is reachable, e.g. in a source tarball). Bump package.version in Cargo.toml before tagging, or retag."
    fi
    echo "assert-release-version: package.version ($package_version) matches tag $REF_NAME"
fi
