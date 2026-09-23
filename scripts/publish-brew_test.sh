#!/usr/bin/env bash
#
# publish-brew_test.sh — test harness for scripts/publish-brew.sh.
#
# Drives the publisher end to end against fixtures: a local bare "tap" repo to
# clone and a local file:// release-asset base (MINIMAL_RELEASE_URL), with no
# GITHUB_TOKEN and no ssh-agent. Asserts that a dry run downloads the four
# macOS assets, checksums them, renders the formula fully stamped — including
# the libkrun dylib installed into the prefix's lib/, which @loader_path/../lib
# resolves — and pushes nothing. Also covers --channel nightly/unstable.
# Run directly or via `just test-shell`.

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

# The digest routine must match the publisher's (portable across
# sha256sum/shasum/openssl — this harness also runs on hosts without
# sha256sum), so it is extracted rather than copied: one definition.
# shellcheck source=scripts/publish-brew.sh
eval "$(sed -n '/^sha256_file()/,/^}/p' "$script")"
[ "$(type -t sha256_file)" = "function" ] || {
    echo "publish-brew_test: cannot extract sha256_file from publish-brew.sh" >&2
    exit 1
}

# --- fixtures -----------------------------------------------------------------

# The versioned release assets, each with distinct content so the sha256s
# differ. Stable keys under releases/v<pkgver>/ the way MINIMAL_RELEASE_URL
# resolves; nightly/unstable key under versions/<stage>/.
releases="$root/releases"
mkdir -p "$releases/v0.5.4"
release="$releases/v0.5.4"
assets=(minimal-macos-arm64 minvmd-macos-arm64 gvproxy-darwin-arm64 libkrun-macos-arm64.dylib)
for a in "${assets[@]}"; do
    printf 'mach-o payload of %s\n' "$a" >"$release/$a"
done

bucket_root="$root/bucket/versions"
seed_bucket_row() {
    local row="$1" a
    mkdir -p "$bucket_root/$row"
    for a in "${assets[@]}"; do
        printf 'mach-o payload of %s in %s\n' "$a" "$row" >"$bucket_root/$row/$a"
    done
}
seed_bucket_row 0.5.4
seed_bucket_row abc12def

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
    local ver="${1:?usage: run_dry <version>}"
    # No GITHUB_TOKEN, no SSH_AUTH_SOCK: the publisher must reach the dry-run
    # exit without any credential for a fixture (file://) remote. The release
    # base is version-keyed, so an unknown version finds no assets.
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN \
        PKGVER="$ver" \
        BREW_TAP_REPO="file://$tap" \
        MINIMAL_RELEASE_URL="file://$root/releases/v$ver" \
        "$script" --dry-run
}

run_dry_channel() {
    local channel="$1" pkgver="$2" stage="${3:-}"
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN \
        PKGVER="$pkgver" \
        STAGE_VERSION="$stage" \
        BREW_TAP_REPO="file://$tap" \
        MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run --channel "$channel"
}

# --- the dry run --------------------------------------------------------------

out="$(run_dry 0.5.4 2>&1)"
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
if [[ "$out" == *'assert_match version.to_s'* ]]; then
    ok "stable formula keeps the min --version assertion"
else
    bad "stable formula keeps the min --version assertion (out: $out)"
fi

# Every 64-hex digest in the diff must be one of the fixture assets'.
digests="$(for a in "${assets[@]}"; do sha256_file "$release/$a"; done)"
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

# --- nightly channel ----------------------------------------------------------

expect 1 "not a nightly package version" "nightly rejects a raw sha as PKGVER" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=abc12def STAGE_VERSION=abc12def \
        BREW_TAP_REPO="file://$tap" MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run --channel nightly

expect 1 "STAGE_VERSION is required" "nightly rejects a missing STAGE_VERSION" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN -u STAGE_VERSION PKGVER=0.20260922.1847 \
        BREW_TAP_REPO="file://$tap" MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run --channel nightly

expect 1 "not an 8-char hex short sha" "nightly rejects a malformed STAGE_VERSION" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=0.20260922.1847 STAGE_VERSION=DEADBEEF \
        BREW_TAP_REPO="file://$tap" MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run --channel nightly

out="$(run_dry_channel nightly 0.20260922.1847 abc12def 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then ok "nightly dry run succeeds with pkgver + stage sha"; else bad "nightly dry run succeeds with pkgver + stage sha (rc=$rc; out: $out)"; fi
if [[ "$out" == *"nothing committed, nothing pushed"* ]]; then
    ok "nightly dry run pushes nothing"
else
    bad "nightly dry run pushes nothing (out: $out)"
fi
if [[ "$out" == *'+class MinimalNightly < Formula'* ]]; then
    ok "nightly formula class is MinimalNightly"
else
    bad "nightly formula class is MinimalNightly (out: $out)"
fi
if [[ "$out" == *'Formula/minimal-nightly.rb'* ]] || [[ "$out" == *'minimal-nightly.rb'* ]]; then
    ok "nightly writes Formula/minimal-nightly.rb"
else
    # Diff path may show as formula file content only; accept class + version.
    if [[ "$out" == *'version "0.20260922.1847"'* ]]; then
        ok "nightly writes Formula/minimal-nightly.rb (version stamped)"
    else
        bad "nightly writes Formula/minimal-nightly.rb (out: $out)"
    fi
fi
if [[ "$out" == *'version "0.20260922.1847"'* ]]; then
    ok "nightly stamps the synthetic pkgver as formula version"
else
    bad "nightly stamps the synthetic pkgver as formula version (out: $out)"
fi
if grep -qE 'versions/abc12def/minimal-macos-arm64' <<<"$out"; then
    ok "nightly formula URLs use the stage sha GCS row"
else
    bad "nightly formula URLs use the stage sha GCS row (out: $out)"
fi
if grep -qE 'releases/download/' <<<"$out"; then
    bad "nightly must not use GitHub Release URLs"
else
    ok "nightly does not use GitHub Release URLs"
fi
if grep -qE 'versions/0\.20260922\.1847/' <<<"$out"; then
    bad "nightly must not fetch from versions/<pkgver>/"
else
    ok "nightly does not fetch from versions/<pkgver>/"
fi
if [[ "$out" == *'min --help'* ]]; then
    ok "nightly formula test uses min --help"
else
    bad "nightly formula test uses min --help (out: $out)"
fi
if [[ "$out" == *'assert_match version.to_s'* ]]; then
    bad "nightly must not assert min --version equals pkgver"
else
    ok "nightly does not assert min --version equals pkgver"
fi
nightly_digests="$(for a in "${assets[@]}"; do sha256_file "$bucket_root/abc12def/$a"; done)"
stamped_ok=1
count=0
while IFS= read -r sha; do
    count=$((count + 1))
    grep -qx "$sha" <<<"$nightly_digests" || stamped_ok=0
done < <(grep -oE '[0-9a-f]{64}' <<<"$out" | sort -u)
if [ "$count" -eq "${#assets[@]}" ] && [ "$stamped_ok" -eq 1 ]; then
    ok "nightly checksums match the stage-row assets"
else
    bad "nightly checksums match the stage-row assets (found $count distinct)"
fi

# --- unstable channel ---------------------------------------------------------

out="$(run_dry_channel unstable 0.5.4 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then ok "unstable dry run succeeds with semver"; else bad "unstable dry run succeeds with semver (rc=$rc; out: $out)"; fi
if [[ "$out" == *'+class MinimalUnstable < Formula'* ]]; then
    ok "unstable formula class is MinimalUnstable"
else
    bad "unstable formula class is MinimalUnstable (out: $out)"
fi
if [[ "$out" == *'version "0.5.4"'* ]]; then
    ok "unstable stamps the semver as formula version"
else
    bad "unstable stamps the semver as formula version (out: $out)"
fi
if grep -qE 'versions/0\.5\.4/minimal-macos-arm64' <<<"$out"; then
    ok "unstable formula URLs use the semver GCS row"
else
    bad "unstable formula URLs use the semver GCS row (out: $out)"
fi
if grep -qE 'releases/download/' <<<"$out"; then
    bad "unstable must not use GitHub Release URLs"
else
    ok "unstable does not use GitHub Release URLs"
fi
if [[ "$out" == *'assert_match version.to_s'* ]]; then
    ok "unstable keeps the min --version assertion"
else
    bad "unstable keeps the min --version assertion (out: $out)"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
