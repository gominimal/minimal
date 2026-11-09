#!/usr/bin/env bash
#
# merge-back.sh — bring a promoted release line into the history of main, so
# that git describe and the version check on main see its tag.
#
# The merge uses the `ours` strategy, which keeps the tree of main and drops
# any change that only the line has. So it first asks `git cherry` for the line
# commits with no identical patch on main, and stops if there are any.
#
# Usage:
#   scripts/merge-back.sh check <version> [<reviewed-sha>...]
#   scripts/merge-back.sh merge <version> [<reviewed-sha>...]
#
# <version> is X.Y.Z, which names the tag vX.Y.Z and the line release/X.Y.x. A
# reviewed sha is a line commit that a person checked: main has its fix, or
# main does not need it, such as a version bump.
#
# `check` exits 0 when the merge can go ahead, and 3 when it cannot. On 3 it
# prints the unported commits as a Markdown list. `merge` makes the same check,
# then merges and pushes to main, without force. Git identity comes from the
# environment. Any other exit code is an error.

set -euo pipefail

usage() {
    echo "usage: $0 check|merge <version> [<reviewed-sha>...]" >&2
    exit 2
}

# unported — print the line commits that no reviewed sha covers.
unported() {
    local sha reviewed
    git cherry origin/main "origin/$line" | sed -n 's/^+ //p' | while read -r sha; do
        for reviewed in ${reviewed_shas[@]+"${reviewed_shas[@]}"}; do
            [ "$sha" = "$reviewed" ] && continue 2
        done
        printf '%s\n' "$sha"
    done
}

# describe <sha> — one Markdown list item. A commit whose `cherry-pick -x`
# source is on main is usually a pick with resolved conflicts, so say so.
describe() {
    local sha="$1" note="" picked
    for picked in $(git log -1 --format=%B "$sha" | sed -n 's/^(cherry picked from commit \([0-9a-f]\{40\}\))$/\1/p'); do
        if git merge-base --is-ancestor "$picked" origin/main 2>/dev/null; then
            note=" (picked from \`${picked:0:10}\`, which is on main)"
        fi
    done
    printf -- '- %s %s%s\n' "\`$sha\`" "$(git log -1 --format=%s "$sha")" "$note"
}

main() {
    [ "$#" -ge 2 ] || usage
    local mode="$1" version="$2"
    shift 2
    case "$mode" in check | merge) ;; *) usage ;; esac

    if ! [[ "$version" =~ ^([0-9]+\.[0-9]+)\.[0-9]+$ ]]; then
        echo "not a final version: $version" >&2
        exit 2
    fi
    line="release/${BASH_REMATCH[1]}.x"
    local tag="v$version"

    # --force replaces a stale local tag of the same name.
    git fetch --quiet --force origin \
        "main:refs/remotes/origin/main" \
        "$line:refs/remotes/origin/$line" \
        tag "$tag"

    if ! git merge-base --is-ancestor "$tag" "origin/$line"; then
        echo "$tag is not on $line" >&2
        exit 1
    fi

    if git merge-base --is-ancestor "origin/$line" origin/main; then
        echo "$line is already on main: nothing to do" >&2
        exit 0
    fi

    reviewed_shas=()
    local sha
    for sha in "$@"; do
        if ! [[ "$sha" =~ ^[0-9a-f]{7,40}$ ]]; then
            echo "not a commit sha: $sha" >&2
            exit 2
        fi
        reviewed_shas+=("$(git rev-parse --verify "$sha^{commit}")")
    done

    local blocked
    blocked="$(unported)"
    if [ -n "$blocked" ]; then
        while read -r sha; do describe "$sha"; done <<<"$blocked"
        exit 3
    fi

    [ "$mode" = merge ] || exit 0

    git switch --quiet --detach origin/main
    git merge --quiet --no-edit -s ours -m "Merge branch '$line' into main" "origin/$line"

    git merge-base --is-ancestor "$tag" HEAD
    [ "$(git rev-parse 'HEAD^{tree}')" = "$(git rev-parse 'origin/main^{tree}')" ]

    git push origin HEAD:refs/heads/main
}

main "$@"
