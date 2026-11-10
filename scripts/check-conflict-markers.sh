#!/usr/bin/env bash
#
# check-conflict-markers.sh — fail when a tracked text file holds a conflict
# marker. A backport with a conflict commits its markers to a draft PR, and
# this keeps them from merging.
#
# It looks for the opening, base and closing markers at the start of a line. A
# lone `=======` is left out, because it is also a Markdown heading underline.
#
# It cannot see a modify/delete conflict, which leaves no markers.
#
# Usage: scripts/check-conflict-markers.sh
#
# Run it from the root of a checkout. Exits 1 and lists the lines it found.

set -euo pipefail

# git grep exits 1 on no match, and above 1 on an error.
status=0
git grep -nIE '^(<{7}|\|{7}|>{7})( |$)' || status=$?

case "$status" in
    0)
        echo "conflict markers found: resolve them before this merges" >&2
        exit 1
        ;;
    1) echo "no conflict markers" ;;
    *) exit "$status" ;;
esac
