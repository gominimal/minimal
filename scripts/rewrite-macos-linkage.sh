#!/usr/bin/env bash
# Rewrite a minvmd binary's libkrun linkage for the SHIPPED layout, then
# verify the result.
#
# Homebrew's libkrun bakes an ABSOLUTE install name into minvmd; rewrite it so
# minvmd resolves @rpath/libkrun.1.dylib via an @loader_path/../lib rpath —
# the layout the installer drops (bin/minvmd beside lib/libkrun.1.dylib).
# build.rs bakes a bin-relative @loader_path rpath for development; that entry
# is retargeted (not appended to), so no bare @loader_path remains.
#
# Verifies afterwards that:
#   - libkrun resolves via @rpath (the rewrite stuck)
#   - the @loader_path/../lib rpath is present and the bare @loader_path is gone
#   - every other dependency is a system library (/usr/lib, /System) — a stray
#     /opt/homebrew dep would fail to load off the build host
#
# Signing is the caller's job: the release pipeline signs with Developer ID as
# the last mutation before upload; CI checks can run this on a throwaway copy.
#
# Usage: scripts/rewrite-macos-linkage.sh <minvmd-binary>
set -euo pipefail

BIN="${1:?usage: rewrite-macos-linkage.sh <minvmd-binary>}"

# NR>1 skips otool's header line, which is the binary's own path and would
# false-match when the binary sits under a path containing "libkrun" (e.g. a
# throwaway CI copy). `|| true` keeps pipefail from aborting before the
# diagnostic below when otool itself fails (not a Mach-O binary).
current="$(otool -L "$BIN" | awk 'NR>1 && /libkrun/ {print $1; exit}' || true)"
if [ -z "$current" ]; then
  echo "::error::$BIN has no libkrun load command; did it link the stub?" >&2
  exit 1
fi
install_name_tool -change "$current" @rpath/libkrun.1.dylib "$BIN"
# Idempotent: only retarget when the bare dev rpath is still present —
# install_name_tool -rpath errors if the old entry is missing, which would
# hard-fail a re-run on an already-rewritten binary. (-change above is
# naturally a no-op when `current` is already @rpath/libkrun.1.dylib.)
if otool -l "$BIN" | awk '$1=="path" {print $2}' | grep -qx '@loader_path'; then
  install_name_tool -rpath @loader_path @loader_path/../lib "$BIN"
fi

otool -L "$BIN"
if ! otool -L "$BIN" | grep -q '@rpath/libkrun\.1\.dylib'; then
  echo "::error::$BIN does not reference @rpath/libkrun.1.dylib; the shipped dylib will not be found" >&2
  exit 1
fi
# The shipped dylib lives in lib/ (a sibling of bin/), so the
# @loader_path -> @loader_path/../lib retarget above must have stuck; without
# it dyld never looks one dir up from bin/minvmd and the load fails at
# runtime. Pull just the LC_RPATH `path` values so the checks match exact
# entries, not substrings.
otool -l "$BIN" | grep -A2 LC_RPATH
rpaths="$(otool -l "$BIN" | awk '$1=="path" && $2 ~ /@loader_path/ {print $2}')"
if ! printf '%s\n' "$rpaths" | grep -qx '@loader_path/../lib'; then
  echo "::error::$BIN is missing the @loader_path/../lib rpath; lib/libkrun.1.dylib will not be found" >&2
  exit 1
fi
if printf '%s\n' "$rpaths" | grep -qx '@loader_path'; then
  echo "::error::$BIN still has a bare @loader_path rpath; the lib retarget did not replace it" >&2
  exit 1
fi
bad="$(otool -L "$BIN" | tail -n +2 | awk '{print $1}' \
  | grep -vE '^(/usr/lib/|/System/|@rpath/libkrun\.1\.dylib$)' || true)"
if [ -n "$bad" ]; then
  echo "::error::$BIN links unexpected non-system libraries:" >&2
  printf '%s\n' "$bad" >&2
  exit 1
fi
echo "linkage rewrite OK: $BIN"
