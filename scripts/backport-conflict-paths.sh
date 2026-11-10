#!/usr/bin/env bash
#
# backport-conflict-paths.sh — print the paths that conflict when a commit is
# picked onto a commit, one per line.
#
# korthout/backport-action commits a conflict as it stands and reports no
# paths. A modify/delete conflict leaves no markers, so grepping the commit
# misses it. This repeats the pick with no commit and asks git.
#
# Usage: scripts/backport-conflict-paths.sh <onto> <commit>
#
# <onto> is the parent of the action's BACKPORT-CONFLICT commit. Run this in a
# clean checkout. It leaves HEAD detached at <onto>. It exits 1 when the pick
# fails for any reason other than a conflict.

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <onto> <commit>" >&2
    exit 2
fi

git switch --quiet --detach "$1"
# A conflict exits non-zero, which is the expected result here. Any other
# failure, such as a missing commit, leaves no unmerged path, and must not read
# as a pick with no conflicts.
status=0
git cherry-pick --no-commit "$2" >/dev/null 2>&1 || status=$?
conflicted="$(git diff --name-only --diff-filter=U)"
git reset --quiet --hard
if [ "$status" -ne 0 ] && [ -z "$conflicted" ]; then
    echo "cherry-pick of $2 onto $1 failed without a conflict" >&2
    exit 1
fi
[ -z "$conflicted" ] || printf '%s\n' "$conflicted"
