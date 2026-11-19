#!/usr/bin/env bash
#
# check-rust-pin.sh — fail when the Rust that Minimal sessions and tasks use
# disagrees with rust-toolchain.toml.
#
# CI compiles with the rustup toolchain rust-toolchain.toml pins. Sessions and
# tasks, the agent runtime's verify box among them, have no rustup: their rustc
# is the `rust` package of the pkgs [upstream] at the locked_commit in
# .minimal/minimal.toml. When the two drift, clippy in the sandbox reports
# lints CI never sees (gominimal/agent-runtime#419).
#
# Usage: scripts/check-rust-pin.sh [<checkout root>]
#
# Reads the pkgs repo from [upstream] `repo` and fetches its
# packages/rust/build.ncl at `locked_commit` from raw.githubusercontent.com.
# Set PKGS_RAW_BASE to fetch from elsewhere (the harness points it at a
# file:// fixture). Exits 1 on drift or on a file it cannot parse, and 2 when
# the fetch fails.

set -euo pipefail

root="${1:-.}"
toolchain="$root/rust-toolchain.toml"
config="$root/.minimal/minimal.toml"

die() { echo "check-rust-pin: $*" >&2; exit 1; }

# A key's quoted value inside one TOML table.
table_value() {
    awk -v table="$2" -v key="$3" '
        /^[[:space:]]*\[/ { inside = ($0 ~ "^[[:space:]]*\\[" table "\\]") }
        inside && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (match($0, /"[^"]*"/)) { print substr($0, RSTART + 1, RLENGTH - 2); exit }
        }
    ' "$1"
}

[ -f "$toolchain" ] || die "no $toolchain"
[ -f "$config" ] || die "no $config"

pinned="$(table_value "$toolchain" toolchain channel)"
[ -n "$pinned" ] || die "no [toolchain] channel in $toolchain"
[[ "$pinned" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "$toolchain channel is \"$pinned\"; pin an exact x.y.z so it can be compared"

repo="$(table_value "$config" upstream repo)"
commit="$(table_value "$config" upstream locked_commit)"
[ -n "$repo" ] || die "no [upstream] repo in $config"
[ -n "$commit" ] || die "no [upstream] locked_commit in $config"

repo="${repo%.git}"
base="${PKGS_RAW_BASE:-${repo/https:\/\/github.com\//https://raw.githubusercontent.com/}}"
url="$base/$commit/packages/rust/build.ncl"

spec="$(curl -fsSL --retry 3 "$url")" || {
    echo "check-rust-pin: cannot fetch $url" >&2
    exit 2
}

upstream="$(printf '%s\n' "$spec" | sed -nE 's/^[[:space:]]*let version = "([^"]+)" in.*/\1/p' | head -n1)"
[ -n "$upstream" ] || die "no \`let version = \"...\" in\` in $url"

if [ "$upstream" != "$pinned" ]; then
    echo "check-rust-pin: rust-toolchain.toml pins $pinned, but the [upstream] locked_commit ${commit:0:12} builds rust $upstream" >&2
    echo "check-rust-pin: move locked_commit to a pkgs commit whose packages/rust is $pinned, or bump rust-toolchain.toml to $upstream" >&2
    exit 1
fi
echo "rust pin agrees: rust-toolchain.toml and pkgs@${commit:0:12} are both $pinned"
