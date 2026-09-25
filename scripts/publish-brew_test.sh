#!/usr/bin/env bash
#
# publish-brew_test.sh — test harness for scripts/publish-brew.sh.
#
# Drives the publisher end to end against fixtures: a local bare "tap" repo to
# clone and a local file:// base (MINIMAL_RELEASE_URL for the stable release
# assets, MINIMAL_BUCKET_URL for every channel's staged row and version file),
# with no GITHUB_TOKEN and no ssh-agent. Asserts that a dry run downloads the
# four macOS assets, checksums them, renders the formula fully stamped —
# including the libkrun dylib installed into the prefix's lib/, which
# @loader_path/../lib resolves — and pushes nothing. Covers the stable formula
# (GitHub Release url) and a channel formula (bucket row url, explicit version,
# `livecheck { skip }`), the channel conflicts_with, plus the refusals.
# Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/publish-brew.sh"
[ -f "$script" ] || { echo "cannot find publish-brew.sh next to test" >&2; exit 1; }
# shellcheck disable=SC1091  # dynamic path: testlib.sh sits beside this harness
. "$here/testlib.sh"

require_tools git curl

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-brewtest)"
trap 'rm -rf "$root"' EXIT

# The digest routine must match the publisher's (portable across
# sha256sum/shasum/openssl — this harness also runs on hosts without
# sha256sum), so it is extracted rather than copied: one definition.
source_function "$script" sha256_file

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

# The channel fixture: an immutable staged row versions/<short-sha>/ holding a
# `version` file (the canonical built version) and the same four asset
# basenames. Content differs from the release assets so the digests do, too.
bucket="$root/bucket"
row="8e7e72c2"                       # 8-char lowercase-hex short sha row
canonical="0.6.0-dev.10.g8e7e72c2"   # what the row's version file holds
rowdir="$bucket/versions/$row"
mkdir -p "$rowdir"
printf '%s\n' "$canonical" >"$rowdir/version"
for a in "${assets[@]}"; do
    printf 'mach-o payload of %s at %s\n' "$a" "$row" >"$rowdir/$a"
done

# The stable rows: the promoted semver's row carries a `version` file holding
# the semver itself — the stable publisher reads and asserts it. 0.9.9 holds a
# disagreeing version for the refusal below.
mkdir -p "$bucket/versions/0.5.4"
printf '%s\n' 0.5.4 >"$bucket/versions/0.5.4/version"
mkdir -p "$bucket/versions/0.9.9"
printf '%s\n' 0.9.8 >"$bucket/versions/0.9.9/version"

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

run_dry() {
    local ver="${1:?usage: run_dry <version>}"
    # No GITHUB_TOKEN, no SSH_AUTH_SOCK: the publisher must reach the dry-run
    # exit without any credential for a fixture (file://) remote. The release
    # base is version-keyed, so an unknown version finds no assets.
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN \
        PKGVER="$ver" \
        BREW_TAP_REPO="file://$tap" \
        MINIMAL_RELEASE_URL="file://$root/releases/v$ver" \
        MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --dry-run
}

run_dry_channel() {
    local channel="${1:?usage: run_dry_channel <channel> <row>}" row="${2:?}"
    # Same no-credential shape, but the asset base is the bucket's versions/<row>.
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN \
        PKGVER="$row" \
        BREW_TAP_REPO="file://$tap" \
        MINIMAL_BUCKET_URL="file://$root/bucket" \
        "$script" --channel "$channel" --dry-run
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
if [[ "$out" == *'conflicts_with "minimal-unstable", "minimal-nightly"'* ]]; then
    ok "the stable formula conflicts with the other channel formulae"
else
    bad "the stable formula conflicts with the other channel formulae (out: $out)"
fi
# The formula installs the release dylib into its own lib/, which is the only
# place minvmd's @loader_path/../lib rpath looks, so it must not pull in a
# third-party libkrun tap (unused on disk, and it can conflict with another).
if [[ "$out" != *'slp/krun'* ]]; then
    ok "the formula does not depend on a third-party libkrun tap"
else
    bad "the formula does not depend on a third-party libkrun tap (out: $out)"
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

# --- the channel dry run ------------------------------------------------------

out="$(run_dry_channel nightly "$row" 2>&1)"
rc=$?

if [ "$rc" -eq 0 ]; then ok "nightly dry run succeeds without credentials"; else bad "nightly dry run succeeds without credentials (rc=$rc; out: $out)"; fi
if [[ "$out" == *"nothing committed, nothing pushed"* ]]; then
    ok "nightly dry run commits and pushes nothing"
else
    bad "nightly dry run commits and pushes nothing (out: $out)"
fi
if grep -qE '^\+.*@@' <<<"$out"; then
    bad "nightly formula carries unrendered @@tokens@@"
else
    ok "nightly formula carries no @@tokens@@"
fi
if [[ "$out" == *'class MinimalNightly < Formula'* ]]; then
    ok "nightly formula declares class MinimalNightly"
else
    bad "nightly formula declares class MinimalNightly (out: $out)"
fi
if [[ "$out" == *"version \"$canonical\""* ]]; then
    ok "nightly formula pins the canonical built version"
else
    bad "nightly formula pins the canonical built version (out: $out)"
fi
if [[ "$out" == *'livecheck do'* && "$out" == *'skip'* ]]; then
    ok "nightly formula skips livecheck (pinned to one staged row)"
else
    bad "nightly formula skips livecheck (out: $out)"
fi
if [[ "$out" == *"file://$root/bucket/versions/$row/minimal-macos-arm64"* ]]; then
    ok "nightly formula urls point at the bucket row"
else
    bad "nightly formula urls point at the bucket row (out: $out)"
fi
if [[ "$out" == *'b/Formula/minimal-nightly.rb'* ]]; then
    ok "the nightly formula renders to Formula/minimal-nightly.rb"
else
    bad "the nightly formula renders to Formula/minimal-nightly.rb (out: $out)"
fi
if [[ "$out" == *'conflicts_with "minimal", "minimal-unstable"'* ]]; then
    ok "the nightly formula conflicts with the other channel formulae"
else
    bad "the nightly formula conflicts with the other channel formulae (out: $out)"
fi

# Every 64-hex digest in the diff must be one of the channel row's assets'.
digests="$(for a in "${assets[@]}"; do sha256_file "$rowdir/$a"; done)"
stamped_ok=1
count=0
while IFS= read -r sha; do
    count=$((count + 1))
    grep -qx "$sha" <<<"$digests" || stamped_ok=0
done < <(grep -oE '[0-9a-f]{64}' <<<"$out" | sort -u)
if [ "$count" -eq "${#assets[@]}" ] && [ "$stamped_ok" -eq 1 ]; then
    ok "nightly checksums in the diff are the row assets' real digests"
else
    bad "nightly checksums in the diff are the row assets' real digests (found $count distinct, want ${#assets[@]})"
fi

pushed="$(git -C "$seed" fetch -q origin && git -C "$seed" rev-parse origin/main)"
if [ "$pushed" = "$seeded" ]; then
    ok "the nightly dry run left the fixture remote untouched"
else
    bad "the nightly dry run left the fixture remote untouched (advanced to $pushed)"
fi

# --- refusals -----------------------------------------------------------------

expect 1 "not a RELEASED semver" "prerelease PKGVER is refused by --channel stable" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=0.6.0-rc.1 BREW_TAP_REPO="file://$tap" \
        MINIMAL_RELEASE_URL="file://$root/releases/v0.6.0-rc.1" "$script" --dry-run

expect 1 "cannot download" "a missing row fails the run" -- run_dry 9.9.9

expect 1 "contradicts what it installs" "a stable row whose version file disagrees with the semver is refused" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=0.9.9 BREW_TAP_REPO="file://$tap" \
        MINIMAL_BUCKET_URL="file://$root/bucket" "$script" --dry-run

expect 1 "sha row, not the semver" "a semver row with --channel nightly is refused" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER=0.6.0 BREW_TAP_REPO="file://$tap" \
        MINIMAL_BUCKET_URL="file://$root/bucket" "$script" --channel nightly --dry-run

expect 1 "version file" "a channel row missing its version file is refused" -- \
    run_dry_channel nightly deadbeef

expect 1 "unknown --channel" "an unknown channel is refused" -- \
    env -u SSH_AUTH_SOCK -u GITHUB_TOKEN PKGVER="$row" BREW_TAP_REPO="file://$tap" \
        MINIMAL_BUCKET_URL="file://$root/bucket" "$script" --channel beta --dry-run

finish
