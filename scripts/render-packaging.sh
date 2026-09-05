#!/usr/bin/env bash
#
# render-packaging.sh — stamp @@NAME@@ tokens in a packaging template from env.
#
# The packaging templates under packaging/ (the AUR PKGBUILD, the nfpm config,
# the Homebrew formula) are plain text carrying one @@NAME@@ token per stamped
# value — NAME matches [A-Z0-9_]+. Each token is replaced with the value of
# the caller's environment variable of the same name (PKGVER for the promoted
# semver, SHA_* for the artifact checksums, ...), so every satellite publish
# shares one substitution rule instead of growing its own renderer.
#
# A token whose variable is unset or empty, and any surviving "@@" — malformed
# or not — fails the run and is listed on stderr: a half-stamped packaging file
# must never be committed or pushed. Templates cannot carry a literal "@@";
# that is the price of the guarantee above.
#
# Usage: scripts/render-packaging.sh <template-file> <output-file>
#
# Requires: bash 4+, grep, sed, printenv.

set -euo pipefail

# A replacement value containing `&` must reach the output literally. bash >=
# 5.2's patsub_replacement expands a bare `&` in the replacement back to the
# matched token, so `MAINTAINER="A & B"` would re-inject the token it just
# replaced (and a token whose value ends in `&` loops forever). Turning the
# option off restores the pre-5.2 literal behavior everywhere; on older bash
# it is already the default (and unknown shopt names are errors).
shopt -u patsub_replacement 2>/dev/null || true

die() {
    printf 'render-packaging: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

case "${1:-}" in
    -h|--help) usage 0 ;;
esac

[ "$#" -ge 2 ] || die "usage: render-packaging.sh <template-file> <output-file>"
[ "$#" -le 2 ] || die "unexpected argument: $3 (usage: render-packaging.sh <template-file> <output-file>)"

template="$1"
output="$2"

[ -f "$template" ] || die "no such template file: $template"

# $(cat) drops trailing newlines; the sentinel x keeps the file byte-exact.
content="$(cat "$template"; printf x)"
content="${content%x}"

# One pass over the distinct well-formed tokens; the leftover check below
# catches everything else — including tokens the well-formed scan skipped
# (lowercase, embedded '@'), which the first version's `@@[^@]*@@` scan could
# not span.
while IFS= read -r token; do
    name="${token//@@/}"
    # printenv exits 0 for a SET-BUT-EMPTY variable too, so its status alone
    # cannot tell "unset, fail" from "empty, stamp it". An empty value is a
    # caller bug either way: a checksum or version token that stamps as the
    # empty string is a half-stamped file the leftover scan cannot see.
    if ! value="$(printenv "$name")" || [ -z "$value" ]; then
        die "token @@${name}@@ in $template: environment variable $name is unset or empty"
    fi
    content="${content//@@${name}@@/$value}"
done < <(grep -oE '@@[A-Z0-9_]+@@' "$template" | sort -u)

leftovers="$(printf '%s\n' "$content" | grep -nE '@@' || true)"
if [ -n "$leftovers" ]; then
    printf 'render-packaging: refusing to write %s, unrendered token(s) remain:\n' "$output" >&2
    printf '%s\n' "$leftovers" >&2
    exit 1
fi

printf '%s' "$content" > "$output"
