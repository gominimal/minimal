#!/usr/bin/env bash
#
# build-bep-bundle_test.sh — test harness for scripts/build-bep-bundle.sh:
# the `check-profile` gate the release runs on the bep provisioning profile,
# and the assemble, flatten and unflatten round trip.
#
# A real profile is a signed CMS blob only `security cms` on macOS decodes.
# BEP_PROFILE_DECODE=cat feeds the check plain plists instead, so the harness
# runs on any host with python3. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/build-bep-bundle.sh"
[ -f "$script" ] || { echo "cannot find build-bep-bundle.sh next to test" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "skip: build-bep-bundle_test.sh needs python3"; exit 0; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-bepbundletest)"
trap 'rm -rf "$root"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }

# profile FILE TEAM APP GROUP EXPIRY — a decoded provisioning profile.
profile() {
    cat >"$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>TeamIdentifier</key><array><string>$2</string></array>
<key>ExpirationDate</key><date>$5</date>
<key>Entitlements</key><dict>
<key>com.apple.application-identifier</key><string>$3</string>
<key>keychain-access-groups</key><array><string>$4</string></array>
</dict></dict></plist>
EOF
}

# check NAME WANT_RC WANT_TEXT FILE — run check-profile on FILE.
check() {
    local rc=0 out
    out="$(BEP_PROFILE_DECODE="cat" "$script" check-profile "$4" 3G47C5HY64 2>&1)" || rc=$?
    if [ "$rc" -eq "$2" ] && [[ "$out" == *"$3"* ]]; then
        ok "$1"
    else
        bad "$1 (rc=$rc, out: $out)"
    fi
}

# --- check-profile ------------------------------------------------------------

profile "$root/good" 3G47C5HY64 3G47C5HY64.dev.minimal.bep '3G47C5HY64.*' 2099-01-01T00:00:00Z
check "a profile for the bep App ID with the team's wildcard group passes" 0 "expires 2099" "$root/good"

profile "$root/exact" 3G47C5HY64 3G47C5HY64.dev.minimal.bep 3G47C5HY64.dev.minimal.bep 2099-01-01T00:00:00Z
check "a profile that names the bep access group itself passes" 0 "expires 2099" "$root/exact"

profile "$root/team" OTHERTEAM1 OTHERTEAM1.dev.minimal.bep 'OTHERTEAM1.*' 2099-01-01T00:00:00Z
check "a profile for another team fails" 1 "not '3G47C5HY64.dev.minimal.bep'" "$root/team"

profile "$root/app" 3G47C5HY64 3G47C5HY64.dev.minimal.minzoned '3G47C5HY64.*' 2099-01-01T00:00:00Z
check "a profile for another App ID fails" 1 "is for '3G47C5HY64.dev.minimal.minzoned'" "$root/app"

profile "$root/group" 3G47C5HY64 3G47C5HY64.dev.minimal.bep 3G47C5HY64.dev.other 2099-01-01T00:00:00Z
check "a profile without the bep access group fails" 1 "does not authorise the keychain access group" "$root/group"

profile "$root/expired" 3G47C5HY64 3G47C5HY64.dev.minimal.bep '3G47C5HY64.*' 2000-01-01T00:00:00Z
check "an expired profile fails" 1 "expired at 2000" "$root/expired"

: >"$root/empty"
check "an empty profile fails before it is decoded" 1 "no provisioning profile" "$root/empty"

# --- assemble, flatten, unflatten ---------------------------------------------

printf 'program\n' >"$root/bep"
printf 'profile\n' >"$root/profile"
"$script" assemble "$root/bep" "$root/profile" "$root/bep.app" 1.2.3 >/dev/null
if grep -q '<string>1.2.3</string>' "$root/bep.app/Contents/Info.plist" \
    && grep -q '<string>dev.minimal.bep</string>' "$root/bep.app/Contents/Info.plist"; then
    ok "assemble writes the version and the bundle identifier into Info.plist"
else
    bad "assemble did not write the version and identifier into Info.plist"
fi
if cmp -s "$root/profile" "$root/bep.app/Contents/embedded.provisionprofile"; then
    ok "assemble embeds the profile at Contents/embedded.provisionprofile"
else
    bad "assemble did not embed the profile"
fi
"$script" flatten "$root/bep.app" "$root/flat"
"$script" unflatten "$root/flat" "$root/rebuilt.app"
if diff -r "$root/bep.app" "$root/rebuilt.app" >/dev/null; then
    ok "flatten then unflatten rebuilds the same bundle"
else
    bad "the rebuilt bundle differs from the assembled one"
fi
if [ -x "$root/rebuilt.app/Contents/MacOS/bep" ]; then
    ok "unflatten leaves the program executable"
else
    bad "unflatten left the program without +x"
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
