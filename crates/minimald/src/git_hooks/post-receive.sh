#!/bin/sh
# Check out each pushed branch into the session worktree. The dirty-worktree
# gate lives in pre-receive (R3.3): a push that reaches here either had a
# clean worktree or carried `-o force-checkout`, so `checkout -f` discarding
# uncommitted tracked-file modifications is the requested semantics. Recovery
# from a mid-checkout failure is git-level: re-run the push.
GIT_DIR_ABS=$(pwd -P)
WORK_TREE=$(dirname "$GIT_DIR_ABS")
unset GIT_DIR GIT_WORK_TREE GIT_QUARANTINE_PATH
g() { git --git-dir="$GIT_DIR_ABS" --work-tree="$WORK_TREE" "$@"; }

status=0
while read -r old new ref; do
    case "$ref" in refs/heads/*) ;; *) continue ;; esac
    branch=${ref#refs/heads/}
    if ! g checkout -f "$branch"; then
        echo "error: checkout of $branch failed; re-run the push to retry" >&2
        status=1
    fi
done
exit $status
