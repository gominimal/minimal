#!/usr/bin/env bash
#
# build-app-bundle.sh — assemble Minimal.app, the macOS app bundle the
# box-name service ships in, and convert it to and from the flat file names
# a release carries.
#
# WHY: macOS lists every launchd job under System Settings > General > Login
# Items & Extensions. A job whose program is a bare file is listed under its
# developer's name with a placeholder icon, and one whose program is unsigned
# is listed as an item from an unidentified developer. A job is listed under
# an app's name and icon only when its program belongs to an app bundle
# signed with the vendor's Developer ID. So `minzoned` ships inside this
# bundle, `min finalize-install` copies the bundle to a root-owned path, and
# both launchd jobs it installs run the program inside that copy.
#
# The bundle is three files before it is signed:
#
#   Minimal.app/Contents/Info.plist              packaging/macos/Info.plist
#   Minimal.app/Contents/MacOS/minzoned          the program
#   Minimal.app/Contents/Resources/AppIcon.icns  packaging/macos/AppIcon.icns
#
# Signing adds Contents/_CodeSignature/CodeResources, and stapling a
# notarization ticket adds Contents/CodeResources. This script never signs:
# the release workflow signs the bundle `assemble` wrote, and a local bundle
# stays unsigned, which a debug `min` accepts.
#
# A release carries flat files, not directories, so `flatten` copies each
# bundle file to the flat name below and `unflatten` rebuilds the bundle from
# them. `table` prints the mapping, one `<path in the bundle><TAB><flat name>`
# line per file: scripts/stage-release.sh's darwin rows install the same flat
# names at the same paths, and scripts/stage-release_test.sh fails when the
# two disagree.
#
# Usage:
#   scripts/build-app-bundle.sh assemble MINZONED OUT.app [VERSION]
#   scripts/build-app-bundle.sh flatten APP OUTDIR
#   scripts/build-app-bundle.sh unflatten INDIR OUT.app
#   scripts/build-app-bundle.sh table
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"

# <path in the bundle>|<flat name>|<required: yes, or no for a file only a
# signed or a stapled bundle has>
FILES=(
  "Contents/MacOS/minzoned|minzoned-macos-arm64|yes"
  "Contents/Info.plist|minzoned-macos-arm64-Info.plist|yes"
  "Contents/Resources/AppIcon.icns|minzoned-macos-arm64-AppIcon.icns|yes"
  "Contents/_CodeSignature/CodeResources|minzoned-macos-arm64-CodeSignature|no"
  "Contents/CodeResources|minzoned-macos-arm64-ticket|no"
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
    if [ $# -lt 3 ] || [ $# -gt 4 ]; then
      die "usage: $0 assemble MINZONED OUT.app [VERSION]"
    fi
    program="$2"
    app="$3"
    version="${4:-0.0.0}"
    [ -f "$program" ] || die "no program at $program"
    case "$version" in
      *[!A-Za-z0-9._+-]*) die "version '$version' holds a character outside [A-Za-z0-9._+-]" ;;
    esac
    rm -rf "$app"
    mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
    sed "s/@VERSION@/$version/g" "$here/packaging/macos/Info.plist" >"$app/Contents/Info.plist"
    cp "$program" "$app/Contents/MacOS/minzoned"
    chmod 0755 "$app/Contents/MacOS/minzoned"
    cp "$here/packaging/macos/AppIcon.icns" "$app/Contents/Resources/AppIcon.icns"
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
    chmod 0755 "$3/Contents/MacOS/minzoned"
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
