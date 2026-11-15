#!/usr/bin/env bash
#
# backport-title-guard.sh — refuse a pull request whose subject would force a
# release line to the next minor.
#
# scripts/next-version.sh requires a minor for a `feat` subject, and for a
# breaking change under any type. A backport that lands either on a line fails
# the version check there, and the line cannot drop the commit.
#
# Usage: scripts/backport-title-guard.sh <title> [<commit-message-file>]
#
# <title> is the source PR title, which the backport PR copies. The optional
# file holds the source commit's full message. Its `BREAKING CHANGE:` footer
# survives a retitle, because the squash on the line copies the message.
#
# Exits 0 when the backport can go ahead. Exits 1 and prints the reason when it
# cannot. backport-title-guard_test.sh checks this against next-version.sh.

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <title> [<commit-message-file>]" >&2
    exit 2
fi

title="$1"
message_file="${2:-}"

# The same pattern as next-version.sh.
subject_re='^([a-z]+)(\(([^)]*)\))?(!)?:[[:space:]]+(.+)$'

if [[ "$title" =~ $subject_re ]]; then
    if [ -n "${BASH_REMATCH[4]}" ]; then
        echo "The title marks a breaking change, which forces the line to the next minor. If it is safe on the line, retitle the source PR as \`fix\`, then remove the backport label and add it again."
        exit 1
    fi
    if [ "${BASH_REMATCH[1]}" = feat ]; then
        echo "The title is a \`feat\`, which forces the line to the next minor. If it is safe on the line, retitle the source PR as \`fix\`, then remove the backport label and add it again."
        exit 1
    fi
fi

# The first line is the subject, which next-version.sh does not read for a footer.
if [ -n "$message_file" ] && sed 1d "$message_file" | grep -Eq '^BREAKING[ -]CHANGE: '; then
    echo "The source commit has a \`BREAKING CHANGE\` footer, which forces the line to the next minor. A retitle does not remove it. Backport this by hand without the footer."
    exit 1
fi
