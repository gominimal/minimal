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
# Usage:
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
    die "usage: $0 assemble|flatten|unflatten|table (see the header)"
    ;;
esac
