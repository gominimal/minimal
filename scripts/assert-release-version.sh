#!/usr/bin/env bash
#
# assert-release-version.sh — the tag being released must match
# package.version in Cargo.toml.
#
# crates/version/build.rs derives the version from `git describe` and falls
# back to `package.version` only when no `v*` tag is reachable (e.g. a source
# tarball with no .git). A stale package.version therefore makes exactly the
# builds this repo ships from a tarball report the wrong `-V`. Tag pushes are
# the only flow carrying a semver tag to assert; workflow-dispatch and the
# nightly (release-<sha>) flows have none and skip.
#
# Usage: scripts/assert-release-version.sh [--tag v0.5.4] [--cargo-toml FILE]
#   --tag         the ref being released (default: GITHUB_REF_NAME with
#                 GITHUB_REF_TYPE; when neither carries a tag the script
#                 asserts nothing and exits 0)
#   --cargo-toml  Cargo.toml to read (default: <repo root>/Cargo.toml; the flag
#                 exists so the harness can test against a fixture)
#
# Exit codes: 0 = matches (or nothing to assert), 1 = mismatch or unreadable
# input.

set -euo pipefail

die() {
    printf 'assert-release-version: %s\n' "$1" >&2
    exit 1
}

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

# Only tag pushes carry a semver to assert. Workflow dispatch and the nightly
# (release-<sha>) runs have a branch ref or a --tag-less invocation.
if [ "$REF_TYPE" != "tag" ]; then
    echo "assert-release-version: not a tag push (ref ${REF_NAME:-<none>}, type ${REF_TYPE:-<none>}) — no version tag to assert"
    exit 0
fi

# Tags are vX.Y.Z (and vX.Y.Z-rc.N); package.version is X.Y.Z. Anything else
# (release-<sha> nightly refs) is not asserted here.
case "$REF_NAME" in
    v[0-9]*) tag_version="${REF_NAME#v}" ;;
    *)
        echo "assert-release-version: ref $REF_NAME is not a v* semver tag — nothing to assert"
        exit 0
        ;;
esac

[ -f "$CARGO_TOML" ] || die "no such Cargo.toml: $CARGO_TOML"

# The workspace `package.version` line. `head -n 1`: the first match is the
# [package] table's own key (later tables never repeat it, but a comment or a
# dependency table must not win either).
package_version="$(sed -n 's/^package\.version[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$CARGO_TOML" | head -n 1)"
[ -n "$package_version" ] || die "could not extract package.version from $CARGO_TOML"

if [ "$package_version" != "$tag_version" ]; then
    die "releasing $REF_NAME but package.version is $package_version — they must match (crates/version/build.rs falls back to package.version when no v* git tag is reachable, e.g. in a source tarball). Bump package.version in Cargo.toml before tagging, or retag."
fi

echo "assert-release-version: package.version ($package_version) matches tag $REF_NAME"
