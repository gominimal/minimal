#!/usr/bin/env bash
#
# publish-brew_test.sh — test harness for scripts/publish-brew.sh.
#
# Drives the publisher end to end against fixtures: a local bare "tap" repo to
# clone and a local file:// release-asset base (MINIMAL_RELEASE_URL), with no
# GITHUB_TOKEN and no ssh-agent. Asserts that a dry run downloads the four
# macOS assets, checksums them, renders the formula fully stamped — including
# the libkrun dylib installed into the prefix's lib/, which @loader_path/../lib
# resolves — and pushes nothing. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-brew.sh"
[ -f "$script" ] || { echo "cannot find publish-brew.sh next to test" >&2; exit 1; }

missing=""
for tool in git curl; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "publish-brew_test: skipping, no$missing on PATH"
    exit 0
fi

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-brewtest)"
trap 'rm -rf "$root"' EXIT

# --- fixtures -----------------------------------------------------------------

# The versioned release assets, each with distinct content so the sha256s
# differ. Keyed under releases/v<pkgver>/ the way MINIMAL_RELEASE_URL resolves.
releases="$root/releases"
mkdir -p "$releases/v0.5.4"
release="$releases/v0.5.4"
assets=(minimal-macos-arm64 minvmd-macos-arm64 gvproxy-darwin-arm64 libkrun-macos-arm64.dylib)
for a in "${assets[@]}"; do
    printf 'mach-o payload of %s\n' "$a" >"$release/$a"
done

# A bare "tap" repo with a committed formula to diff against.
tap="$root/tap.git"
git init -q --bare -b main "$tap"
seed="$root/seed"
git clone -q "$tap" "$seed"
git -C "$seed" config user.email test@example.com
git -C "$seed" config user.name test
mkdir -p "$seed/Formula"
printf 'class Minimal < Formula\n  version "0.0.0"\nend\n' >"$seed/Formula/minimal.rb"
git -C "$seed" add -A
git -C "$seed" commit -q -m seed
git -C "$seed" push -q origin main

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
expect() {
    local want_rc="$1" want_msg="$2" desc="$3"; shift 3
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -eq "$want_rc" ] && [[ "$out" == *"$want_msg"* ]]; then
        ok "$desc"
    else
        bad "$desc (want rc=$want_rc and '$want_msg'; got rc=$rc, out: $out)"
    fi
}

run_dry() {
    local ver="${1:-0.5.4}"
    # No GITHUB_TOKEN, no SSH_AUTH_SOCK: the publisher must reach the dry-run
    # exit without any credential for a fixture (file://) remote. The release
    # base is version-keyed, so an unknown version finds no assets.
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN \
        PKGVER="$ver" \
        BREW_TAP_REPO="file://$tap" \
        MINIMAL_RELEASE_URL="file://$root/releases/v$ver" \
        "$script" --dry-run
}

# --- the dry run --------------------------------------------------------------

out="$(run_dry 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then ok "dry run succeeds without credentials"; else bad "dry run succeeds without credentials (rc=$rc; out: $out)"; fi
if [[ "$out" == *"nothing committed, nothing pushed"* ]]; then
    ok "dry run commits and pushes nothing"
else
    bad "dry run commits and pushes nothing (out: $out)"
fi
if grep -qE '^\+.*@@' <<<"$out"; then
    bad "rendered formula carries unrendered @@tokens@@"
else
    ok "rendered formula carries no @@tokens@@"
fi
if [[ "$out" == *'releases/download/v0.5.4/minimal-macos-arm64'* ]]; then
    ok "diff shows the stamped version"
else
    bad "diff shows the stamped version (out: $out)"
fi
if [[ "$out" == *'lib.install "libkrun-macos-arm64.dylib" => "libkrun.1.dylib"'* ]]; then
    ok "the dylib lands in the prefix's lib/ under the load command's name"
else
    bad "the dylib lands in the prefix's lib/ under the load command's name"
fi
if [[ "$out" == *'bin.install "minimal-macos-arm64" => "min"'* ]]; then
    ok "the CLI installs as bin/min (not a bin/min directory)"
else
    bad "the CLI installs as bin/min (not a bin/min directory)"
fi

# Every 64-hex digest in the diff must be one of the fixture assets'.
digests="$(for a in "${assets[@]}"; do sha256sum "$release/$a"; done | cut -d' ' -f1)"
stamped_ok=1
count=0
while IFS= read -r sha; do
    count=$((count + 1))
    grep -qx "$sha" <<<"$digests" || stamped_ok=0
done < <(grep -oE '[0-9a-f]{64}' <<<"$out" | sort -u)
if [ "$count" -eq "${#assets[@]}" ] && [ "$stamped_ok" -eq 1 ]; then
    ok "checksums in the diff are the assets' real digests"
else
    bad "checksums in the diff are the assets' real digests (found $count distinct, want ${#assets[@]})"
fi

pushed="$(git -C "$seed" fetch -q origin && git -C "$seed" rev-parse origin/main)"
seeded="$(git -C "$seed" rev-parse main)"
if [ "$pushed" = "$seeded" ]; then
    ok "the fixture remote is untouched"
else
    bad "the fixture remote is untouched (advanced to $pushed)"
fi

# --- refusals -----------------------------------------------------------------

expect 1 "not a RELEASED semver" "prerelease PKGVER is refused (Homebrew has no channels)" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=0.6.0-rc.1 BREW_TAP_REPO="file://$tap" \
        MINIMAL_RELEASE_URL="file://$root/releases/v0.6.0-rc.1" "$script" --dry-run

expect 1 "cannot download" "a missing release asset fails the run" -- run_dry 9.9.9

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
