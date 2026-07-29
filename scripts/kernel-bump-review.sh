#!/usr/bin/env bash
#
# kernel-bump-review.sh — show a reviewer the stable-kernel commits a guest
# kernel bump drags into the subsystems this project's guest depends on.
#
# WHY
#
# The guest kernel is pinned in gominimal/pkgs (packages/virtio-linux/build.ncl,
# `let version = "..."`) and reaches this repo when `.minimal/minimal.toml`'s
# `locked_commit` moves. A point-release bump can span thousands of commits, so
# in practice nobody reads it, and a semantic change to the guest's control
# plane lands unreviewed. That is how 6.12.43 -> 6.12.94 shipped a4f0b001782b
# ("vsock/virtio: reset connection on receiving queue overflow"), which turned a
# silently-dropped packet into a fatal connection reset and broke every sizeable
# `min session activate` for three weeks. The commit is public, its subject says exactly
# what it does, and it sits in net/vmw_vsock/ — the subtree the entire guest
# control plane rides on. A mechanical diff was all that was needed to catch it,
# with no VM and no test run. This is that diff.
#
# WHICH SUBTREES, AND WHY
#
# A wide net is worse than none: a reviewer learns to skip a report that is
# mostly noise. The default set is only what the guest cannot boot or be driven
# without, and each entry earns its place:
#
#   net/vmw_vsock/                  every RPC, attach/PTY stream and file upload
#                                   rides AF_VSOCK; the virtio transport lives
#                                   here. The root cause above landed here.
#   include/linux/virtio_vsock.h    credit accounting, buffer/packet limits and
#   include/uapi/linux/virtio_vsock.h  the wire protocol constants shared with
#                                   the host-side device. Tiny, high signal.
#   drivers/virtio/                 virtio core: virtqueue/vring, feature
#                                   negotiation, DMA — under every device below.
#   drivers/char/virtio_console.c   the guest boots `console=hvc0`; all guest
#                                   boot and minimald logs leave over it, so its
#                                   loss/backpressure behaviour decides whether
#                                   a guest-side hang is diagnosable at all.
#   drivers/block/virtio_blk.c      the ext4 root disk and the persistent data
#                                   volume are virtio-blk (krun_add_disk2/3);
#                                   sparse/discard behaviour is load-bearing.
#
# Deliberately NOT in the default set:
#
#   drivers/vhost/vsock.c   the HOST-side vhost-vsock driver. libkrun implements
#                           virtio-vsock in userspace and minvmd bridges it to a
#                           host unix socket (krun_add_vsock_port2), so this
#                           driver is never loaded on either side of our stack.
#                           --wide includes it anyway as a cross-check, since a
#                           vsock semantics change is often mirrored here.
#   drivers/net/virtio_net.c  guest egress (gvproxy) rides it, but it is behind
#                           the networking-proxy feature and off the control
#                           plane. --wide includes it.
#   fs/fuse/virtio_fs.c     not used: the rootfs is a raw ext4 disk, not virtiofs.
#   arch/, mm/, sched/, …   real, but any bump touches thousands of these lines;
#                           including them is how a report becomes wallpaper.
#
# WHERE THE DATA COMES FROM
#
# The stable tree, via the GitHub API. torvalds/linux does NOT carry v6.12.x
# tags — querying it returns 404, and a 404 through `curl` is indistinguishable
# from "no matching commits". Every request here is checked and every failure is
# fatal: a tripwire that reports "no changes" when it cannot reach the source is
# worse than no tripwire.
#
# HOW THE RANGE IS COMPUTED
#
# Both tags are resolved to commits, then each subtree is queried with a
# committer-date window (since = old tag, until = new tag) on the new tag's
# history. A stable branch is a linear sequence of cherry-picks whose committer
# dates rise monotonically, so the window is exact. Its one imprecision is
# benign: a commit sharing the old tag's exact timestamp is reported once too
# often, never once too few. The size of the full range is reported alongside,
# so "0 commits" is always distinguishable from "0 commits looked at".
#
# That reasoning holds only while the old tag is an ancestor of the new one, so
# both versions must name the same stable branch; a cross-series pair (6.6.94 ->
# 6.12.94) is refused rather than reported on. Review a series bump one branch
# at a time.
#
# OUTPUT
#
#   ! <stable-sha> <upstream-sha> <date> <subject>
#
# `!` marks a subject matching a behavioural keyword (reset, drop, overflow,
# credit, backpressure, queue, fatal) — read those before the pin lands.
# <upstream-sha> is the mainline commit the stable patch backports, taken from
# the "commit <sha> upstream." line; `-` when there is none. Browse any commit
# at https://github.com/gregkh/linux/commit/<sha>.
#
# Usage:
#   scripts/kernel-bump-review.sh <old-version> <new-version>
#   scripts/kernel-bump-review.sh --pkgs DIR [old-ref] [new-ref]
#
# Options:
#   --pkgs DIR       Read both versions from a gominimal/pkgs checkout instead
#                    of the command line: `let version` in build.ncl at each ref
#                    (default refs: origin/main and HEAD — i.e. what a pkgs pull
#                    request changes). For a `locked_commit` bump in this repo,
#                    pass the two pinned commits as the refs.
#   --wide           Add the host-side/non-control-plane paths listed above.
#   --fail-on-flag   Exit 2 when any commit is flagged (for a future CI gate).
#   -h, --help       Show this help
#
# Examples:
#   scripts/kernel-bump-review.sh 6.12.43 6.12.94
#   scripts/kernel-bump-review.sh --pkgs ~/code/pkgs
#   scripts/kernel-bump-review.sh --pkgs ~/code/pkgs c854d6b1 8f2a91c4
#
# Requires: an authenticated `gh` (public data; any token works), and `git` for
# --pkgs. No kernel checkout, no VM, no network beyond api.github.com.
set -euo pipefail

# The stable tree. Do not point this at torvalds/linux (see above).
REPO="gregkh/linux"
NCL_PATH="packages/virtio-linux/build.ncl"

# Subject keywords that separate "a behaviour changed" from "a typo was fixed".
# Matched case-insensitively against the subject only.
FLAG_RE='reset|drop|overflow|credit|backpressure|queue|fatal'

# The guest's load-bearing surface. Rationale in the header — keep it earned.
CORE_PATHS=(
    net/vmw_vsock
    include/linux/virtio_vsock.h
    include/uapi/linux/virtio_vsock.h
    drivers/virtio
    drivers/char/virtio_console.c
    drivers/block/virtio_blk.c
)
WIDE_PATHS=(
    drivers/vhost/vsock.c
    drivers/net/virtio_net.c
)

die() {
    printf 'kernel-bump-review: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '/^# Usage:/,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

WIDE=0
FAIL_ON_FLAG=0
PKGS_DIR=""
ARG1=""
ARG2=""
NARG=0

while [ $# -gt 0 ]; do
    case "$1" in
        --pkgs)
            # Guard $2: under `set -u` a trailing valueless flag would abort
            # with an unbound-variable error instead of a usable message.
            [ $# -ge 2 ] || die "missing value for $1"
            PKGS_DIR="$2"
            shift 2 ;;
        --wide)         WIDE=1; shift ;;
        --fail-on-flag) FAIL_ON_FLAG=1; shift ;;
        -h|--help)      usage 0 ;;
        -*)             die "unknown argument: $1 (try --help)" ;;
        *)
            NARG=$((NARG + 1))
            case "$NARG" in
                1) ARG1="$1" ;;
                2) ARG2="$1" ;;
                *) die "unexpected argument: $1 (try --help)" ;;
            esac
            shift ;;
    esac
done

command -v gh >/dev/null 2>&1 || die "gh not found (needed for the GitHub API)"

# `let version = "6.12.94" in` -> 6.12.94, at a given ref of the pkgs checkout.
version_at_ref() {
    local ref="$1" blob ver
    blob=$(git -C "$PKGS_DIR" show "$ref:$NCL_PATH" 2>&1) \
        || die "cannot read $NCL_PATH at '$ref' in $PKGS_DIR: $blob"
    ver=$(printf '%s\n' "$blob" | sed -n 's/^let version = "\([^"]*\)".*/\1/p' | head -1)
    [ -n "$ver" ] || die "no 'let version = \"...\"' line in $NCL_PATH at '$ref'"
    printf '%s' "$ver"
}

if [ -n "$PKGS_DIR" ]; then
    command -v git >/dev/null 2>&1 || die "git not found (needed for --pkgs)"
    [ -d "$PKGS_DIR" ] || die "--pkgs: not a directory: $PKGS_DIR"
    git -C "$PKGS_DIR" rev-parse --git-dir >/dev/null 2>&1 \
        || die "--pkgs: not a git checkout: $PKGS_DIR"
    OLD_VERSION=$(version_at_ref "${ARG1:-origin/main}")
    NEW_VERSION=$(version_at_ref "${ARG2:-HEAD}")
    printf 'kernel-bump-review: %s in %s: %s -> %s (%s -> %s)\n' \
        "$NCL_PATH" "$PKGS_DIR" "${ARG1:-origin/main}" "${ARG2:-HEAD}" \
        "$OLD_VERSION" "$NEW_VERSION" >&2
else
    [ "$NARG" -eq 2 ] || usage 2
    OLD_VERSION="$ARG1"
    NEW_VERSION="$ARG2"
fi

[ "$OLD_VERSION" != "$NEW_VERSION" ] \
    || die "both versions are $OLD_VERSION — nothing to review"

# Stable tags are digits and dots. Refuse anything else rather than paste it
# into an API path.
for v in "$OLD_VERSION" "$NEW_VERSION"; do
    case "${v#v}" in
        ""|*[!0-9.]*) die "'$v' is not a stable kernel version (expected e.g. 6.12.94)" ;;
    esac
done

OLD_TAG="v${OLD_VERSION#v}"
NEW_TAG="v${NEW_VERSION#v}"

# Both tags have to sit on the same stable branch. The scan below walks the NEW
# tag's history through a committer-date window, which equals "the diff between
# the tags" only while the old tag is an ancestor of the new one. Across series
# they are not: `compare v6.6.94...v6.12.94` reports status=diverged, behind_by
# 17883, with a merge base back in 2023 — so the window keeps the handful of
# 6.12.y commits that happen to fall inside it and silently drops everything the
# intervening series carried. That yields a short, plausible, wrong report,
# which is the exact failure this tool exists to prevent. Refuse instead.
series_of() {
    local v="${1#v}" rest
    rest="${v#*.}"
    printf '%s.%s' "${v%%.*}" "${rest%%.*}"
}
OLD_SERIES=$(series_of "$OLD_VERSION")
NEW_SERIES=$(series_of "$NEW_VERSION")
[ "$OLD_SERIES" = "$NEW_SERIES" ] \
    || die "$OLD_TAG and $NEW_TAG are on different stable branches ($OLD_SERIES.y vs $NEW_SERIES.y).
  This tool reviews one stable branch at a time: the range is a committer-date
  window over the new tag's history, which is only the true diff when the old
  tag is an ancestor of the new one. A cross-series report would understate the
  change. Review the bump one series at a time."

# "<sha>\t<committer-date>" for a tag, or a loud death. This is the request that
# catches a wrong repo, a nonexistent version, a typo, or no network.
resolve_tag() {
    local tag="$1" out
    out=$(gh api "repos/$REPO/commits/$tag" --jq '[.sha, .commit.committer.date] | @tsv' 2>&1) \
        || die "cannot resolve $tag in $REPO ($out)
  Does $REPO carry stable tags? torvalds/linux does not — only the stable
  mirror (gregkh/linux) has v6.12.x. Also check \`gh auth status\`."
    printf '%s' "$out"
}

# Assign first: a `die` inside $( ) only kills the subshell, so the failure has
# to be caught by the assignment's exit status (set -e) rather than swallowed by
# a surrounding redirect.
OLD_META=$(resolve_tag "$OLD_TAG")
NEW_META=$(resolve_tag "$NEW_TAG")
IFS=$'\t' read -r OLD_SHA OLD_DATE <<<"$OLD_META"
IFS=$'\t' read -r NEW_SHA NEW_DATE <<<"$NEW_META"

# Ordering is a real mistake mode (a reviewer pastes the versions the way the
# diff shows them, new first) and it silently yields an empty report.
[[ "$OLD_DATE" < "$NEW_DATE" ]] \
    || die "$OLD_TAG ($OLD_DATE) is not older than $NEW_TAG ($NEW_DATE) — arguments reversed?"

# Independent proof the range is real, so "no commits in these subtrees" can
# never be confused with "the query found nothing at all". per_page=1 keeps the
# response small; total_commits counts the whole range regardless.
RANGE_TOTAL=$(gh api "repos/$REPO/compare/$OLD_TAG...$NEW_TAG?per_page=1" --jq '.total_commits' 2>&1) \
    || die "cannot compare $OLD_TAG...$NEW_TAG in $REPO ($RANGE_TOTAL)"
[ "$RANGE_TOTAL" -gt 0 ] 2>/dev/null \
    || die "$OLD_TAG...$NEW_TAG spans $RANGE_TOTAL commits — refusing to report on an empty range"

PATHS=("${CORE_PATHS[@]}")
SCOPE="core"
if [ "$WIDE" -eq 1 ]; then
    PATHS+=("${WIDE_PATHS[@]}")
    SCOPE="wide"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

printf '\n== kernel bump review: %s %s -> %s ==\n\n' "$REPO" "$OLD_TAG" "$NEW_TAG"
printf '  old  %-10s %s  %s\n' "$OLD_TAG" "${OLD_SHA:0:12}" "$OLD_DATE"
printf '  new  %-10s %s  %s\n' "$NEW_TAG" "${NEW_SHA:0:12}" "$NEW_DATE"
printf '  range spans %s commits; scanning the %s subtree set\n' "$RANGE_TOTAL" "$SCOPE"
printf '  columns: [!] <stable-sha> <upstream-sha> <date> <subject>\n'
printf '  browse:  https://github.com/%s/commit/<stable-sha>\n' "$REPO"

TOTAL=0
FLAGGED=0
: >"$TMP/summary"

for path in "${PATHS[@]}"; do
    # One TSV line per commit touching $path in the range: stable sha, date,
    # the mainline sha it backports ("commit <sha> upstream."), subject.
    gh api --paginate -X GET "repos/$REPO/commits" \
        -f sha="$NEW_SHA" \
        -f path="$path" \
        -f since="$OLD_DATE" \
        -f until="$NEW_DATE" \
        -f per_page=100 \
        --jq '.[] | [
                .sha[0:12],
                .commit.committer.date[0:10],
                ((.commit.message | capture("commit (?<u>[0-9a-f]{40}) upstream") | .u[0:12]) // "-"),
                (.commit.message | split("\n")[0])
              ] | @tsv' >"$TMP/commits" \
        || die "commit query failed for $path in $REPO (see the error above)"

    n=0
    nf=0
    : >"$TMP/body"
    while IFS=$'\t' read -r sha when upstream subject; do
        [ -n "$sha" ] || continue
        n=$((n + 1))
        mark=' '
        if printf '%s' "$subject" | grep -Eqi "$FLAG_RE"; then
            mark='!'
            nf=$((nf + 1))
        fi
        printf '  %s  %s  %-12s  %s  %s\n' "$mark" "$sha" "$upstream" "$when" "$subject" >>"$TMP/body"
    done <"$TMP/commits"

    printf '\n-- %s (%d commits, %d flagged) --\n' "$path" "$n" "$nf"
    if [ "$n" -eq 0 ]; then
        printf '  (no changes in range)\n'
    fi
    cat "$TMP/body"

    printf '  %-34s %4d commits %4d flagged\n' "$path" "$n" "$nf" >>"$TMP/summary"
    TOTAL=$((TOTAL + n))
    FLAGGED=$((FLAGGED + nf))
done

printf '\n== summary ==\n\n'
cat "$TMP/summary"
printf '  %-34s %4d commits %4d flagged\n' "TOTAL" "$TOTAL" "$FLAGGED"
printf '\n'

if [ "$TOTAL" -eq 0 ]; then
    printf 'kernel-bump-review: %s commits in %s...%s, none touching the %s subtrees.\n' \
        "$RANGE_TOTAL" "$OLD_TAG" "$NEW_TAG" "$SCOPE" >&2
    printf '  Possible for adjacent point releases; suspicious for a long jump.\n' >&2
fi

if [ "$FLAGGED" -gt 0 ]; then
    printf '  %d commit(s) marked [!]: a behavioural keyword (%s)\n' "$FLAGGED" "$FLAG_RE"
    printf '  in the subject. Read those before landing the bump.\n\n'
    if [ "$FAIL_ON_FLAG" -eq 1 ]; then
        exit 2
    fi
fi

exit 0
