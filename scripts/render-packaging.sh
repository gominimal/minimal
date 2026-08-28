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
# A token whose variable is unset, and any @@...@@ that survives the pass
# (including malformed names), fails the run and is listed on stderr: a
# half-stamped packaging file must never be committed or pushed.
#
# Usage: scripts/render-packaging.sh <template-file> <output-file>
#
# Requires: bash, grep, sed, printenv.

set -euo pipefail

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
# catches the malformed rest.
while IFS= read -r token; do
    name="${token//@@/}"
    if ! value="$(printenv "$name")"; then
        die "token @@${name}@@ in $template: environment variable $name is not set"
    fi
    content="${content//@@${name}@@/$value}"
done < <(grep -oE '@@[A-Z0-9_]+@@' "$template" | sort -u)

leftovers="$(printf '%s\n' "$content" | grep -oE '@@[^@]*@@' || true)"
if [ -n "$leftovers" ]; then
    printf 'render-packaging: refusing to write %s, unrendered token(s) remain:\n' "$output" >&2
    printf '%s\n' "$leftovers" >&2
    exit 1
fi

printf '%s' "$content" > "$output"
