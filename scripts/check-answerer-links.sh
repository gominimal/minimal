#!/usr/bin/env bash
# Check that the box-zone answerer program links only system libraries.
#
# The privileged step copies `min-answerer` to a root-owned path, and the
# service manager runs that copy. A library the copy resolves at load time
# from a user-writable dir (libkrun through an `@rpath`/`$ORIGIN` entry, say)
# would let whoever can write there run code in the service, so:
#
#   macOS  every `otool -L` entry is under /usr/lib or /System, and the
#          binary carries no LC_RPATH load command at all (`otool -l`).
#   Linux  every `ldd` entry resolves under /lib, /lib64, /usr/lib or
#          /usr/lib64 (multiarch subdirs included) or is the vDSO, and the
#          binary carries no RPATH or RUNPATH entry at all (`readelf -d`).
#
# Every offender is named.
#
# Usage: scripts/check-answerer-links.sh <path to min-answerer>
set -euo pipefail

bin="${1:?usage: $0 <path to min-answerer>}"
if [ ! -x "$bin" ]; then
  echo "check-answerer-links: no executable at $bin (run 'just answerer-build')" >&2
  exit 1
fi

bad=""
offend() { bad="${bad}$1
"; }

case "$(uname -s)" in
  Darwin)
    listing="$(otool -L "$bin")"
    echo "$listing"
    # The first line names the binary itself; every other line is a load
    # command: `<path> (compatibility version ...)`.
    while IFS= read -r line; do
      dep="$(printf '%s\n' "$line" | sed -n 's/^[[:space:]]*\([^ ]*\) (.*/\1/p')"
      [ -n "$dep" ] || continue
      case "$dep" in
        /usr/lib/* | /System/*) ;;
        *) offend "linked library outside /usr/lib and /System: $dep" ;;
      esac
    done < <(printf '%s\n' "$listing" | tail -n +2)
    # Any LC_RPATH at all is a search path the loader would consult.
    while IFS= read -r rpath; do
      offend "LC_RPATH load command: $rpath"
    done < <(otool -l "$bin" | awk '
      /cmd LC_RPATH/ { want = 1; next }
      want && $1 == "path" { print $2; want = 0 }
    ')
    ;;
  Linux)
    listing="$(ldd "$bin" 2>&1 || true)"
    echo "$listing"
    case "$listing" in
      *"not a dynamic executable"* | *"statically linked"*) ;;
      *)
        while IFS= read -r line; do
          case "$line" in
            *linux-vdso.so.* | *linux-gate.so.*) continue ;;
            *"=> not found"*) offend "unresolved library: ${line#"${line%%[![:space:]]*}"}"; continue ;;
          esac
          path="$(printf '%s\n' "$line" | sed -n 's/.*=> \(\/[^ ]*\) .*/\1/p')"
          [ -n "$path" ] || path="$(printf '%s\n' "$line" | sed -n 's/^[[:space:]]*\(\/[^ ]*\) .*/\1/p')"
          [ -n "$path" ] || continue
          # /lib, /lib64, /usr/lib, /usr/lib64, and their multiarch
          # subdirs (/lib/aarch64-linux-gnu/...) all sit under these.
          case "$path" in
            /lib/* | /lib64/* | /usr/lib/* | /usr/lib64/*) ;;
            *) offend "linked library outside the system library dirs: $path" ;;
          esac
        done <<<"$listing"
        ;;
    esac
    # Any RPATH or RUNPATH at all is a search path the loader would consult.
    while IFS= read -r entry; do
      offend "dynamic section entry: $entry"
    done < <(readelf -d "$bin" 2>/dev/null | grep -E '\((RPATH|RUNPATH)\)' | sed 's/^[[:space:]]*//')
    ;;
  *)
    echo "check-answerer-links: no check for $(uname -s)" >&2
    exit 1
    ;;
esac

if [ -n "$bad" ]; then
  echo "check-answerer-links: $bin may load code from outside the system paths:" >&2
  printf '%s' "$bad" | sed 's/^/  /' >&2
  exit 1
fi
echo "check-answerer-links: $bin links only system libraries and carries no rpath"
