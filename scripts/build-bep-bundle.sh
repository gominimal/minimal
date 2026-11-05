#!/usr/bin/env bash
#
# build-bep-bundle.sh — assemble bep.app, the macOS app bundle the Box Egress
# Proxy ships in, and convert it to and from the flat file names a release
# carries.
#
# WHY: a release `bep` keeps its keys in the Secure Enclave, in the
# data-protection keychain under the access group 3G47C5HY64.dev.minimal.bep
# (crates/bep/src/keys.rs, #2812). macOS grants that access group only to a
# program signed with the `keychain-access-groups` entitlement, and honours
# that entitlement only when a provisioning profile authorises it. A
# provisioning profile is honoured only inside an app bundle, at
# Contents/embedded.provisionprofile. A bare `bep` signed with the Developer
# ID gets an exportable key in the login keychain, which a release `bep`
# refuses (#2436).
#
# The bundle is three files before it is signed:
#
#   bep.app/Contents/Info.plist                packaging/macos/bep/Info.plist
#   bep.app/Contents/MacOS/bep                 the program
#   bep.app/Contents/embedded.provisionprofile the Developer ID profile
#
# Signing adds Contents/_CodeSignature/CodeResources, and stapling a
# notarization ticket adds Contents/CodeResources. This script never signs:
# the release workflow signs the bundle `assemble` wrote, with
# packaging/macos/bep/bep.entitlements. A debug `bep` needs no bundle, as it
# keeps its keys in the login keychain.
#
# A release carries flat files, not directories, so `flatten` copies each
# bundle file to the flat name below and `unflatten` rebuilds the bundle from
# them. `table` prints the mapping, one `<path in the bundle><TAB><flat name>`
# line per file: scripts/stage-release.sh's bep rows install the same flat
# names at the same paths under bin/bep.app, and scripts/stage-release_test.sh
# fails when the two disagree.
#
# `check-profile` checks a Developer ID provisioning profile before it goes
# into the bundle: its team, its application identifier, that it authorises
# the keychain access group, that it runs on any Mac (a Developer ID profile,
# not a development one), and that it has not expired. An expired profile,
# or one for another App ID, makes a bep that macOS refuses to start. It
# decodes the profile with `security cms -D -i`. BEP_PROFILE_DECODE replaces
# that command, so scripts/build-bep-bundle_test.sh can feed it plain plists.
#
# Usage:
#   scripts/build-bep-bundle.sh check-profile PROFILE TEAM
#   scripts/build-bep-bundle.sh assemble BEP PROFILE OUT.app [VERSION]
#   scripts/build-bep-bundle.sh flatten APP OUTDIR
#   scripts/build-bep-bundle.sh unflatten INDIR OUT.app
#   scripts/build-bep-bundle.sh table
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"

# <path in the bundle>|<flat name>|<required: yes, or no for a file only a
# signed or a stapled bundle has>
FILES=(
  "Contents/MacOS/bep|bep-macos-arm64|yes"
  "Contents/Info.plist|bep-macos-arm64-Info.plist|yes"
  "Contents/embedded.provisionprofile|bep-macos-arm64-profile|yes"
  "Contents/_CodeSignature/CodeResources|bep-macos-arm64-CodeSignature|no"
  "Contents/CodeResources|bep-macos-arm64-ticket|no"
)

die() {
  echo "$0: $*" >&2
  exit 1
}

# copy_file SOURCE DEST REQUIRED — copy one bundle file, making DEST's
# directory. A file that is not required and not there is skipped.
copy_file() {
  if [ ! -f "$1" ]; then
    [ "$3" = no ] || die "missing $1"
    return 0
  fi
  mkdir -p "$(dirname "$2")"
  cp "$1" "$2"
}

case "${1:-}" in
  check-profile)
    [ $# = 3 ] || die "usage: $0 check-profile PROFILE TEAM"
    [ -s "$2" ] || die "no provisioning profile at $2"
    decoded="$(mktemp)"
    trap 'rm -f "$decoded"' EXIT
    # shellcheck disable=SC2086 # the decoder is a command and its arguments
    ${BEP_PROFILE_DECODE:-security cms -D -i} "$2" >"$decoded" \
      || die "could not decode the provisioning profile $2"
    python3 - "$decoded" "$3" <<'EOF'
import datetime, plistlib, sys
path, team = sys.argv[1], sys.argv[2]
want_app = team + ".dev.minimal.bep"
with open(path, "rb") as f:
    profile = plistlib.load(f)
ents = profile.get("Entitlements", {})
got_team = (profile.get("TeamIdentifier") or [""])[0]
got_app = ents.get("com.apple.application-identifier", "")
groups = ents.get("keychain-access-groups", [])
expires = profile.get("ExpirationDate")
print(f"profile: team {got_team}, app {got_app}, keychain groups {groups}, expires {expires}")
if got_team != team or got_app != want_app:
    sys.exit(f"the profile is for '{got_app}' in team '{got_team}', not '{want_app}'")
if want_app not in groups and team + ".*" not in groups:
    sys.exit(f"the profile does not authorise the keychain access group {want_app}")
# A Developer ID profile runs on any Mac. A development profile lists the
# Macs it runs on, and bep.app would not start anywhere else.
if profile.get("ProvisionsAllDevices") is not True or "ProvisionedDevices" in profile:
    sys.exit("the profile is not a Developer ID profile: it does not provision all devices")
if not isinstance(expires, datetime.datetime):
    sys.exit("the profile has no expiry date")
if expires.tzinfo is None:
    expires = expires.replace(tzinfo=datetime.timezone.utc)
if expires <= datetime.datetime.now(datetime.timezone.utc):
    sys.exit(f"the profile expired at {expires}")
EOF
    ;;
  assemble)
    if [ $# -lt 4 ] || [ $# -gt 5 ]; then
      die "usage: $0 assemble BEP PROFILE OUT.app [VERSION]"
    fi
    program="$2"
    profile="$3"
    app="$4"
    version="${5:-0.0.0}"
    [ -f "$program" ] || die "no program at $program"
    [ -s "$profile" ] || die "no provisioning profile at $profile"
    case "$version" in
      *[!A-Za-z0-9._+-]*) die "version '$version' holds a character outside [A-Za-z0-9._+-]" ;;
    esac
    rm -rf "$app"
    mkdir -p "$app/Contents/MacOS"
    sed "s/@VERSION@/$version/g" "$here/packaging/macos/bep/Info.plist" >"$app/Contents/Info.plist"
    cp "$program" "$app/Contents/MacOS/bep"
    chmod 0755 "$app/Contents/MacOS/bep"
    cp "$profile" "$app/Contents/embedded.provisionprofile"
    echo "wrote $app"
    ;;
  flatten)
    [ $# = 3 ] || die "usage: $0 flatten APP OUTDIR"
    mkdir -p "$3"
    for entry in "${FILES[@]}"; do
      IFS='|' read -r path flat required <<<"$entry"
      copy_file "$2/$path" "$3/$flat" "$required"
    done
    ;;
  unflatten)
    [ $# = 3 ] || die "usage: $0 unflatten INDIR OUT.app"
    rm -rf "$3"
    for entry in "${FILES[@]}"; do
      IFS='|' read -r path flat required <<<"$entry"
      copy_file "$2/$flat" "$3/$path" "$required"
    done
    chmod 0755 "$3/Contents/MacOS/bep"
    ;;
  table)
    for entry in "${FILES[@]}"; do
      IFS='|' read -r path flat _ <<<"$entry"
      printf '%s\t%s\n' "$path" "$flat"
    done
    ;;
  *)
    die "usage: $0 check-profile|assemble|flatten|unflatten|table (see the header)"
    ;;
esac
