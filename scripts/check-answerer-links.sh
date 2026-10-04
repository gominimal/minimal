#!/usr/bin/env bash
# Check that the box-zone answerer program links only system libraries.
#
# The privileged step copies `min-answerer` to a root-owned path, and the
# service manager runs that copy. A library the copy resolves at load time
# from a user-writable dir (libkrun through an `@rpath`/`$ORIGIN` entry, say)
# would let whoever can write there run code in the service, so every load
# command must name a system path:
#
#   macOS  `otool -L`: /usr/lib/ or /System/ only.
#   Linux  `ldd`: a static binary, or libraries resolved under /lib, /lib64,
#          /usr/lib or /usr/lib64 only (the vDSO and the loader included).
#
# Usage: scripts/check-answerer-links.sh <path to min-answerer>
set -euo pipefail

bin="${1:?usage: $0 <path to min-answerer>}"
if [ ! -x "$bin" ]; then
  echo "check-answerer-links: no executable at $bin (run 'just answerer-build')" >&2
  exit 1
fi

bad=""
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
        *) bad="${bad}${dep}
" ;;
      esac
    done < <(printf '%s\n' "$listing" | tail -n +2)
    ;;
  Linux)
    listing="$(ldd "$bin" 2>&1 || true)"
    echo "$listing"
    case "$listing" in
      *"not a dynamic executable"* | *"statically linked"*) ;;
      *)
        while IFS= read -r line; do
          # `name => /path (addr)`, `/path (addr)`, or `linux-vdso.so.1 (addr)`.
          case "$line" in
            *"=> not found"*) bad="${bad}${line}
"; continue ;;
          esac
          path="$(printf '%s\n' "$line" | sed -n 's/.*=> \(\/[^ ]*\) .*/\1/p')"
          [ -n "$path" ] || path="$(printf '%s\n' "$line" | sed -n 's/^[[:space:]]*\(\/[^ ]*\) .*/\1/p')"
          [ -n "$path" ] || continue # the vDSO: no path on disk
          case "$path" in
            /lib/* | /lib64/* | /usr/lib/* | /usr/lib64/*) ;;
            *) bad="${bad}${path}
" ;;
          esac
        done <<<"$listing"
        ;;
    esac
    ;;
  *)
    echo "check-answerer-links: no check for $(uname -s)" >&2
    exit 1
    ;;
esac

if [ -n "$bad" ]; then
  echo "check-answerer-links: $bin links libraries outside the system paths:" >&2
  printf '%s' "$bad" | sed 's/^/  /' >&2
  exit 1
fi
echo "check-answerer-links: $bin links only system libraries"
