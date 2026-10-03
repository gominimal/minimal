#!/usr/bin/env bash
# Report how far each non-Rust dependency pin lags its upstream, and check that
# pins duplicated across files agree.
#
# WHY THIS EXISTS
# ---------------
# Dependabot covers cargo and the workflow actions only. Everything else this
# repo builds or ships is pinned by hand in a lock file, a pkgs recipe at the
# `.minimal/minimal.toml` `locked_commit`, or a version string inside a config
# file, and nothing reported when those fell behind. This script is the
# inventory: the PINS table below names each pin, where its pinned value
# lives, and which upstream answers "what is latest". The CHECKS table names
# pins that are written down twice and must stay equal.
#
# USAGE
# -----
#   scripts/deps-freshness.sh            report every pin, then run the checks
#   scripts/deps-freshness.sh --check    run only the consistency checks
#   scripts/deps-freshness.sh --check --offline
#                                        run only the checks that read local
#                                        files (no gh, no network)
#
# The report never fails on lag: a pin behind upstream is information, and an
# upstream that cannot be reached prints `unknown`. The checks fail (exit 1)
# on a mismatch AND on a value that cannot be resolved, because a check that
# could not look is not a pass.
#
# Requires `gh` (authenticated) for GitHub lookups and `curl` for kernel.org
# and Alpine. DEPS_ROOT overrides the repo root (the test harness points it
# at a fixture tree).
#
# TABLE SYNTAX
# ------------
# Columns are separated by ` | `. A pinned-value source is one of:
#   kv FILE KEY      the `KEY=value` line of a lock file
#   re FILE ERE      the first capture group of ERE (sed -E) in FILE
#   pkgs FILE VAR    `let VAR = "value"` in FILE of gominimal/pkgs at the
#                    `locked_commit` of .minimal/minimal.toml
#   locked-commit    the `locked_commit` itself
# An upstream is one of:
#   gh-release REPO  the latest GitHub release tag of REPO
#   kernel           the newest kernel.org release in the pinned major.minor
#   alpine           Alpine's latest-stable release version
#   pkgs-main        gominimal/pkgs main (lag counted in commits)
# Leading `v` and `kani-` tag prefixes are stripped before comparing.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="${DEPS_ROOT:-$(cd "$here/.." && pwd)}"
pkgs_repo="gominimal/pkgs"

PINS='
pkgs locked_commit         | locked-commit                                           | pkgs-main
kernel (pkgs virtio-linux) | pkgs packages/virtio-linux/build.ncl version            | kernel
libkrun (pkgs)             | pkgs packages/libkrun/build.ncl version                 | gh-release libkrun/libkrun
libkrunfw (pkgs)           | pkgs packages/libkrunfw/build.ncl version               | gh-release libkrun/libkrunfw
alpine rootfs (pkgs)       | pkgs packages/microvm-rootfs/build.ncl alpine_release   | alpine
libkrun (vendored)         | kv vendor/libkrun/libkrun.lock version                  | gh-release libkrun/libkrun
gvproxy                    | kv vendor/gvproxy/gvproxy.lock version                  | gh-release containers/gvisor-tap-vsock
nfpm                       | kv vendor/nfpm/nfpm.lock version                        | gh-release goreleaser/nfpm
rust toolchain             | re rust-toolchain.toml ^channel = "([^"]+)"             | gh-release rust-lang/rust
kani                       | re .github/workflows/ci-kani.yml KANI_VERSION: *([0-9.]+) | gh-release model-checking/kani
zizmor                     | re .github/workflows/ci.yml zizmor@([0-9.]+)            | gh-release zizmorcore/zizmor
actionlint                 | re .github/workflows/ci.yml rhysd/actionlint:([0-9.]+)  | gh-release rhysd/actionlint
protoc (cross image)       | re Cross.toml protoc-([0-9.]+)-linux                    | gh-release protocolbuffers/protobuf
shellcheck                 | re .tool-versions ^shellcheck ([0-9.]+)                 | gh-release koalaman/shellcheck
vale ai-tells              | re .vale.ini vale-ai-tells/releases/download/v([0-9.]+)/ | gh-release tbhb/vale-ai-tells
vale ste                   | re .vale.ini vale-ste/releases/download/v([0-9.]+)/     | gh-release amoslives/vale-ste
'

# Pins written down twice. Both sides must resolve to the same version.
CHECKS='
libkrun vendored = pkgs    | kv vendor/libkrun/libkrun.lock version                    | pkgs packages/libkrun/build.ncl version
kani workflow = justfile   | re .github/workflows/ci-kani.yml KANI_VERSION: *([0-9.]+) | re justfile kani-verifier --version ([0-9.]+)
zizmor ci = nightly-tests  | re .github/workflows/ci.yml zizmor@([0-9.]+)              | re .github/workflows/nightly-tests.yml zizmor@([0-9.]+)
actionlint ci = nightly    | re .github/workflows/ci.yml rhysd/actionlint:([0-9.]+)    | re .github/workflows/nightly-tests.yml rhysd/actionlint:([0-9.]+)
'

check_only=0 offline=0
for arg in "$@"; do
    case "$arg" in
        --check) check_only=1 ;;
        --offline) offline=1 ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "deps-freshness: unknown argument '$arg'" >&2; exit 2 ;;
    esac
done
if [ "$offline" -eq 1 ] && [ "$check_only" -eq 0 ]; then
    echo "deps-freshness: --offline only applies to --check (the report needs the network)" >&2
    exit 2
fi

cache="$(mktemp -d 2>/dev/null || mktemp -d -t deps-freshness)"
trap 'rm -rf "$cache"' EXIT

trim() { sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }
norm() { sed 's/^kani-//; s/^v//'; }

locked_commit() {
    sed -n 's/^locked_commit *= *"\([0-9a-f]*\)".*/\1/p' "$root/.minimal/minimal.toml" | head -1
}

# pkgs_file PATH — PATH from gominimal/pkgs at locked_commit, fetched once.
pkgs_file() {
    local key out
    key="$cache/pkgs-$(printf '%s' "$1" | tr '/' '_')"
    if [ ! -f "$key" ]; then
        out="$(gh api "repos/$pkgs_repo/contents/$1?ref=$(locked_commit)" \
            -H 'Accept: application/vnd.github.raw' 2>/dev/null)" || return 1
        printf '%s\n' "$out" >"$key"
    fi
    cat "$key"
}

# needs_network SOURCE — whether resolving SOURCE leaves the local tree.
needs_network() { case "$1" in pkgs\ *) return 0 ;; *) return 1 ;; esac; }

# pinned SOURCE — print the pinned value SOURCE names, or fail.
pinned() {
    local kind a b
    read -r kind a b <<<"$1"
    case "$kind" in
        kv) [ -f "$root/$a" ] && sed -n "s/^$b=//p" "$root/$a" | head -1 ;;
        re) [ -f "$root/$a" ] && sed -nE "s|.*$b.*|\\1|p" "$root/$a" | head -1 ;;
        pkgs) pkgs_file "$a" | sed -n "s/^let $b = \"\\([^\"]*\\)\" in.*/\\1/p" | head -1 ;;
        locked-commit) locked_commit ;;
        *) echo "deps-freshness: bad source kind '$kind'" >&2; return 1 ;;
    esac
}

# latest UPSTREAM PINNED — print the newest upstream version, or fail.
latest() {
    local kind repo series
    read -r kind repo <<<"$1"
    case "$kind" in
        gh-release)
            gh api "repos/$repo/releases/latest" --jq .tag_name 2>/dev/null ;;
        kernel)
            series="$(printf '%s' "$2" | cut -d. -f1-2 | sed 's/\./\\./g')"
            curl -fsSL --max-time 30 https://www.kernel.org/releases.json 2>/dev/null \
                | grep -oE "\"version\": *\"$series\\.[0-9]+\"" \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1 ;;
        alpine)
            curl -fsSL --max-time 30 https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml 2>/dev/null \
                | sed -n 's/^ *version: *//p' | head -1 ;;
        pkgs-main)
            gh api "repos/$pkgs_repo/compare/$2...main" --jq .ahead_by 2>/dev/null ;;
        *) echo "deps-freshness: bad upstream kind '$kind'" >&2; return 1 ;;
    esac
}

# status PINNED LATEST — current / behind / ahead, by version order.
status() {
    if [ "$1" = "$2" ]; then echo current
    elif [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]; then echo behind
    else echo ahead
    fi
}

report() {
    local name src up p l s
    printf '%-28s %-14s %-14s %s\n' DEPENDENCY PINNED LATEST STATUS
    while IFS='|' read -r name src up; do
        name="$(printf '%s' "$name" | trim)"
        [ -n "$name" ] || continue
        src="$(printf '%s' "$src" | trim)"
        up="$(printf '%s' "$up" | trim)"
        p="$(pinned "$src" | norm || true)"
        if [ -z "$p" ]; then
            printf '%-28s %-14s %-14s %s\n' "$name" '?' '?' 'unknown (pin unreadable)'
            continue
        fi
        if [ "$up" = pkgs-main ]; then
            l="$(latest "$up" "$p" || true)"
            case "$l" in
                '') s='unknown (upstream unreachable)' ;;
                0) s=current ;;
                *) s="behind ($l commits)" ;;
            esac
            printf '%-28s %-14s %-14s %s\n' "$name" "${p:0:12}" main "$s"
            continue
        fi
        l="$(latest "$up" "$p" | norm || true)"
        if [ -z "$l" ]; then
            s='unknown (upstream unreachable)'
        else
            s="$(status "$p" "$l")"
        fi
        printf '%-28s %-14s %-14s %s\n' "$name" "$p" "${l:-?}" "$s"
    done <<<"$PINS"
}

checks() {
    local name left right a b failed=0 ran=0
    while IFS='|' read -r name left right; do
        name="$(printf '%s' "$name" | trim)"
        [ -n "$name" ] || continue
        left="$(printf '%s' "$left" | trim)"
        right="$(printf '%s' "$right" | trim)"
        if [ "$offline" -eq 1 ] && { needs_network "$left" || needs_network "$right"; }; then
            printf 'skip %-28s needs the network\n' "$name"
            continue
        fi
        ran=$((ran + 1))
        a="$(pinned "$left" | norm || true)"
        b="$(pinned "$right" | norm || true)"
        if [ -z "$a" ] || [ -z "$b" ]; then
            printf 'FAIL %-28s unresolved (%s vs %s)\n' "$name" "${a:-?}" "${b:-?}"
            failed=1
        elif [ "$a" != "$b" ]; then
            printf 'FAIL %-28s %s != %s\n' "$name" "$a" "$b"
            failed=1
        else
            printf 'ok   %-28s %s\n' "$name" "$a"
        fi
    done <<<"$CHECKS"
    [ "$ran" -gt 0 ] || { echo "deps-freshness: no consistency check ran" >&2; return 1; }
    return "$failed"
}

if [ "$check_only" -eq 0 ]; then
    report
    echo
fi
checks
