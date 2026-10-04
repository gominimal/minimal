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
# could not look is not a pass. Beyond the CHECKS table, `--check` also fails
# when a PINS row no longer resolves (its file moved, its line changed shape,
# or it matches more than one value), and when a `vendor/*/*.lock` file has
# no PINS row. `--offline` limits both to the rows read from this tree.
#
# Requires `gh` (authenticated) for GitHub lookups, and `curl` and `jq` for
# kernel.org and Alpine. DEPS_ROOT overrides the repo root (the test harness
# points it at a fixture tree).
#
# TABLE SYNTAX
# ------------
# Columns are separated by ` | `. A pinned-value source is one of:
#   kv FILE KEY      the `KEY=value` line of a lock file
#   re FILE ERE      the first capture group of ERE (sed -E) in FILE. ERE
#                    must start with `^` and spell out the line's shape, so
#                    a comment that mentions the tool cannot match first
#   pkgs FILE VAR    `let VAR = "value"` in FILE of gominimal/pkgs at the
#                    `locked_commit` of .minimal/minimal.toml
#   locked-commit    the `locked_commit` itself
# Every source must resolve to exactly one distinct value: two lines that
# match with different values make the pin ambiguous, not "the first one".
# An upstream is one of:
#   gh-release REPO  the latest GitHub release tag of REPO
#   kernel           the newest kernel.org release in the pinned major.minor;
#                    flags the series EOL when kernel.org does, or when it
#                    no longer lists the series at all
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
rust toolchain             | re rust-toolchain.toml ^channel = "([^"]+)" *$          | gh-release rust-lang/rust
kani                       | re .github/workflows/ci-kani.yml ^ *KANI_VERSION: *([0-9.]+) *$ | gh-release model-checking/kani
zizmor                     | re .github/workflows/ci.yml ^ *tool: [a-z0-9,-]*zizmor@([0-9.]+) | gh-release zizmorcore/zizmor
actionlint                 | re .github/workflows/ci.yml ^ *run: docker run .*rhysd/actionlint:([0-9.]+) | gh-release rhysd/actionlint
protoc (cross image)       | re Cross.toml ^ *"wget https://github.com/protocolbuffers/protobuf/releases/download/v([0-9.]+)/protoc- | gh-release protocolbuffers/protobuf
shellcheck                 | re .tool-versions ^shellcheck ([0-9.]+) *$              | gh-release koalaman/shellcheck
vale ai-tells              | re .vale.ini ^Packages = .*/vale-ai-tells/releases/download/v([0-9.]+)/ | gh-release tbhb/vale-ai-tells
vale ste                   | re .vale.ini ^Packages = .*/vale-ste/releases/download/v([0-9.]+)/ | gh-release amoslives/vale-ste
'

# Pins written down twice. Both sides must resolve to the same version.
CHECKS='
libkrun vendored = pkgs    | kv vendor/libkrun/libkrun.lock version                    | pkgs packages/libkrun/build.ncl version
kani workflow = justfile   | re .github/workflows/ci-kani.yml ^ *KANI_VERSION: *([0-9.]+) *$ | re justfile ^kani: .*kani-verifier --version ([0-9.]+)
zizmor ci = nightly-tests  | re .github/workflows/ci.yml ^ *tool: [a-z0-9,-]*zizmor@([0-9.]+) | re .github/workflows/nightly-tests.yml ^ *tool: [a-z0-9,-]*zizmor@([0-9.]+)
actionlint ci = nightly    | re .github/workflows/ci.yml ^ *run: docker run .*rhysd/actionlint:([0-9.]+) | re .github/workflows/nightly-tests.yml ^ *run: docker run .*rhysd/actionlint:([0-9.]+)
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

# one — pass through the single distinct input line. Fail on none, and on
# several (naming them on stderr): an ambiguous pin is not its first match.
one() {
    local vals n
    vals="$(sed '/^$/d' | sort -u)"
    n="$(printf '%s' "$vals" | grep -c '' || true)"
    case "$n" in
        0) return 1 ;;
        1) printf '%s\n' "$vals" ;;
        *) echo "ambiguous: $(printf '%s' "$vals" | tr '\n' ' ' | sed 's/ $//')" >&2; return 1 ;;
    esac
}

# pinned SOURCE — print the pinned value SOURCE names, or fail.
pinned() {
    local kind a b
    read -r kind a b <<<"$1"
    case "$kind" in
        kv) [ -f "$root/$a" ] && sed -n "s/^$b=//p" "$root/$a" | one ;;
        re)
            case "$b" in
                ^*) ;;
                *) echo "deps-freshness: re pattern for $a must start with ^: $b" >&2; return 1 ;;
            esac
            [ -f "$root/$a" ] && sed -nE "s|$b.*|\\1|p" "$root/$a" | one ;;
        pkgs) pkgs_file "$a" | sed -n "s/^let $b = \"\\([^\"]*\\)\" in.*/\\1/p" | one ;;
        locked-commit) locked_commit ;;
        *) echo "deps-freshness: bad source kind '$kind'" >&2; return 1 ;;
    esac
}

# latest UPSTREAM PINNED — print the newest upstream version, optionally
# followed by a tab and a note for the status column, or fail.
latest() {
    local kind repo series
    read -r kind repo <<<"$1"
    case "$kind" in
        gh-release)
            gh api "repos/$repo/releases/latest" --jq .tag_name 2>/dev/null ;;
        kernel)
            command -v jq >/dev/null 2>&1 || return 1
            series="$(printf '%s' "$2" | cut -d. -f1-2)"
            curl -fsSL --max-time 30 https://www.kernel.org/releases.json 2>/dev/null \
                | jq -er --arg s "$series." '
                    [.releases[] | select(.version | startswith($s))]
                    | if length == 0 then "\tseries EOL (no longer listed on kernel.org)"
                      else max_by(.version | split(".") | map(tonumber))
                           | .version + (if .iseol then "\tseries EOL" else "" end)
                      end' ;;
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

# why — the reason pinned() left on stderr, or a generic one.
why() { [ -s "$cache/err" ] && sed -n '$p' "$cache/err" || echo 'pin unreadable'; }

report() {
    local name src up p l note s
    printf '%-28s %-14s %-14s %s\n' DEPENDENCY PINNED LATEST STATUS
    while IFS='|' read -r name src up; do
        name="$(printf '%s' "$name" | trim)"
        [ -n "$name" ] || continue
        src="$(printf '%s' "$src" | trim)"
        up="$(printf '%s' "$up" | trim)"
        p="$(pinned "$src" 2>"$cache/err" | norm || true)"
        if [ -z "$p" ]; then
            printf '%-28s %-14s %-14s %s\n' "$name" '?' '?' "unknown ($(why))"
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
        l="$(latest "$up" "$p" || true)"
        note="$(printf '%s' "$l" | cut -s -f2)"
        l="$(printf '%s' "$l" | cut -f1 | norm)"
        if [ -n "$l" ]; then
            s="$(status "$p" "$l")${note:+ ($note)}"
        elif [ -n "$note" ]; then
            s="$note"
        else
            s='unknown (upstream unreachable)'
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
        # Why a side is unresolved is reported by the per-pin check below.
        a="$(pinned "$left" 2>/dev/null | norm || true)"
        b="$(pinned "$right" 2>/dev/null | norm || true)"
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

    # Every PINS row still resolves to exactly one value.
    local src bad=0 skipped=0
    while IFS='|' read -r name src _; do
        name="$(printf '%s' "$name" | trim)"
        [ -n "$name" ] || continue
        src="$(printf '%s' "$src" | trim)"
        if [ "$offline" -eq 1 ] && needs_network "$src"; then
            skipped=$((skipped + 1))
            continue
        fi
        if [ -z "$(pinned "$src" 2>"$cache/err" || true)" ]; then
            printf 'FAIL %-28s %s (%s)\n' "pin: $name" "$(why)" "$src"
            bad=1
        fi
    done <<<"$PINS"
    if [ "$bad" -eq 0 ]; then
        if [ "$skipped" -gt 0 ]; then
            printf 'ok   %s\n' "every pin resolves (pkgs rows skipped: need the network)"
        else
            printf 'ok   %s\n' "every pin resolves"
        fi
    fi

    # Every vendored lock file is in the inventory.
    local f rel unlisted=0
    for f in "$root"/vendor/*/*.lock; do
        [ -e "$f" ] || continue
        rel="${f#"$root"/}"
        if ! grep -qF "kv $rel " <<<"$PINS"; then
            printf 'FAIL %-28s %s has no PINS row\n' "lock file unlisted" "$rel"
            unlisted=1
        fi
    done
    [ "$unlisted" -eq 1 ] || printf 'ok   %s\n' "every vendor lock file is listed"

    [ "$failed" -eq 0 ] && [ "$bad" -eq 0 ] && [ "$unlisted" -eq 0 ]
}

if [ "$check_only" -eq 0 ]; then
    report
    echo
fi
checks
