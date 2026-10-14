#!/usr/bin/env bash
# What this branch changed, for the gates that grade a change: the base ref,
# the changed Rust lines, the untracked Rust files and the crates they belong
# to. Sourced by scripts/clippy-strict.sh and by scripts/metrics/run.sh (gate
# and diff modes), so the two gates answer "which lines are yours" the same
# way; scripts/metrics/changed_lines.py parses what these write.
#
# Source it from the repository root: every function runs git against the
# current directory. It defines functions and nothing else.

# changed_lines_base [BASE]: print the ref to grade against. An explicit BASE
# is printed as given; otherwise the merge-base with `origin/main`.
changed_lines_base() {
    local base="${1:-}"
    if [ -z "$base" ]; then
        # `origin/main`, not the local `main`. A branch that merges `origin/main`
        # leaves the local ref where it was — agent sandboxes and worktrees never
        # check main out at all — and the merge-base against a ref that stale
        # predates the main commits the branch merged in, so every line of those
        # commits reads as a line this branch changed. The gate then reports
        # diagnostics on other people's code, under a heading saying they are
        # yours. That is what it looked like: on the branch adding this comment,
        # a local `main` ten commits behind turned a change touching no Rust at
        # all into 14 changed Rust files across `minimald`, `sessions` and
        # `switch`.
        #
        # The remote ref is the safe one by construction: `origin/main` cannot be
        # behind anything the branch merged, because merging it required fetching
        # it first, and a fetch only moves it forward. Stale means the base is
        # merely older than the newest main, never older than this branch's own
        # first commit. The local ref is kept as a fallback for a clone with no
        # remote.
        base="$(git merge-base origin/main HEAD 2>/dev/null || git merge-base main HEAD)"
    fi
    printf '%s\n' "$base"
}

# changed_lines_diff <merge_base> <out_file>: the unified diff, zero context,
# of the Rust files changed since <merge_base>, written to <out_file>.
#
# -U0 gives one hunk per contiguous edit, so each hunk header is one range of
# changed lines in the new revision; a zero-length new range is a pure
# deletion, which has no lines to report on. The comparison is against the
# working tree, not HEAD: these gates are meant to run before committing, so
# an uncommitted edit has to count. Diffing from the merge-base keeps the base
# branch's own commits out of the comparison.
# --no-ext-diff/--no-textconv keep this parseable when a developer has a diff
# renderer (e.g. difftastic) or textconv configured, which would otherwise
# replace the hunk headers.
changed_lines_diff() {
    git diff -U0 --no-color --no-ext-diff --no-textconv --diff-filter=d \
        "$1" -- '*.rs' > "$2"
}

# changed_lines_untracked <out_file>: the untracked Rust files, one path per
# line. A brand-new file is untracked, so it does not appear in the diff;
# every line of it is new.
changed_lines_untracked() {
    git ls-files --others --exclude-standard -- '*.rs' > "$1"
}

# changed_crates <merge_base> <untracked_file>: the crates the changed files
# belong to, one name per line out of `crates/<name>/...`; other paths are
# ignored. Deleted paths are filtered out, or a crate the branch removed would
# reach `cargo clippy -p` and fail the run before the remaining change was
# checked. Paths outside `crates/` leave the list empty, which callers read as
# "the workspace".
changed_crates() {
    { git diff --name-only --no-ext-diff --diff-filter=d "$1" -- '*.rs'
      cat "$2"; } \
        | sed -n 's|^crates/\([^/][^/]*\)/.*|\1|p' | sort -u
}
