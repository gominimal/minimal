#!/bin/sh
# Reject a branch push into a dirty session worktree unless the client passed
# `git push -o force-checkout` (R3.3). Running in pre-receive — before refs
# update — makes the rejection loud on the client: `! [remote rejected]
# (pre-receive hook declined)` and a non-zero `git push` exit, instead of the
# old post-receive silent skip. Requires the server to advertise push options
# (receive.advertisePushOptions=true).
#
# "Dirty" matches the historical gate: uncommitted changes to tracked files
# (staged or unstaged). Untracked files never block a push, and the eventual
# `checkout -f` leaves them alone — collisions with untracked files are a
# pre-existing residual risk, unchanged here.
GIT_DIR_ABS=$(pwd -P)
WORK_TREE=$(dirname "$GIT_DIR_ABS")
unset GIT_DIR GIT_WORK_TREE GIT_QUARANTINE_PATH
g() { git --git-dir="$GIT_DIR_ABS" --work-tree="$WORK_TREE" "$@"; }

i=0
while [ "$i" -lt "${GIT_PUSH_OPTION_COUNT:-0}" ]; do
    eval "opt=\${GIT_PUSH_OPTION_$i}"
    [ "$opt" = "force-checkout" ] && exit 0
    i=$((i + 1))
done

touches_branch=0
while read -r old new ref; do
    case "$ref" in refs/heads/*) touches_branch=1 ;; esac
done
[ "$touches_branch" -eq 0 ] && exit 0

if ! g diff --quiet || ! g diff --cached --quiet; then
    echo "error: session worktree has uncommitted changes; push rejected to protect them." >&2
    echo "hint: commit or stash them in the session, or force the checkout (DISCARDS those changes):" >&2
    echo "hint:   git push -o force-checkout <remote> <branch>" >&2
    exit 1
fi
exit 0
