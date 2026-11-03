#!/usr/bin/env bash
#
# build-app-icon.sh — render packaging/macos/AppIcon.icns from its SVG source.
#
# WHY: macOS shows a Background Items row (System Settings > General > Login
# Items & Extensions) with the icon of the app bundle its launchd job belongs
# to, and nothing at all for a bare program. The box-name service `min
# finalize-install` installs ships in an app bundle for that reason
# (scripts/build-app-bundle.sh), and this .icns is the icon the bundle carries. This
# script is the one way that file is made: the .icns is committed beside its
# source so every host sees the same bytes, and a change to the source is
# re-rendered here, never edited by hand.
#
# The source composes docs/public/minimal-mark-light.svg on the macOS icon
# grid: a 1024 canvas, the 824-point rounded square Apple's template uses,
# the mark light on the brand's dark ground. Every size the iconset needs is
# rendered from that one SVG (rsvg-convert), then packed with iconutil.
#
# Usage: scripts/build-app-icon.sh [SOURCE.svg] [OUT.icns]
#   Defaults: packaging/macos/app-icon.svg -> packaging/macos/AppIcon.icns.
#   Needs rsvg-convert (`brew install librsvg`) and iconutil (Xcode CLT).
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
source_svg="${1:-$here/packaging/macos/app-icon.svg}"
out_icns="${2:-$here/packaging/macos/AppIcon.icns}"

for tool in rsvg-convert iconutil; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$0: $tool is not on PATH" >&2; exit 1; }
done
[ -f "$source_svg" ] || { echo "$0: no source at $source_svg" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
iconset="$work/AppIcon.iconset"
mkdir "$iconset"

for size in 16 32 128 256 512; do
  double=$((size * 2))
  rsvg-convert -w "$size" -h "$size" "$source_svg" -o "$iconset/icon_${size}x${size}.png"
  rsvg-convert -w "$double" -h "$double" "$source_svg" -o "$iconset/icon_${size}x${size}@2x.png"
done
iconutil -c icns "$iconset" -o "$out_icns"
echo "wrote $out_icns"
