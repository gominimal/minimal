#!/usr/bin/env bash
# Publish one snapshot to the metrics history ref (spec 31, QM-014).
#
# The history is the orphan branch `metrics-data`: `history/<date>-<sha7>.json`
# per nightly run plus a README, nothing else, unprotected, and never main.
# The gate reads its baseline from there (`git show origin/metrics-data:...`),
# so a change cannot edit the numbers it is graded against (QM-009), and the
# repository rule that nothing commits to main outside a reviewed pull request
# holds without a bot token or a code-owner carve-out.
#
# Usage: scripts/metrics/publish-snapshot.sh <snapshot.json> [--remote origin]
#        [--branch metrics-data] [--date YYYY-MM-DD] [--dry-run]
#
# Fetches the branch (creates the orphan when the remote has none), copies the
# snapshot in under the date and the snapshot's own sha7, prunes with
# scripts/metrics/prune.py, commits with the identity in GIT_AUTHOR_NAME /
# GIT_AUTHOR_EMAIL (the Actions bot by default) and pushes `HEAD:<branch>`
# from a temporary worktree. The checked-out branch is never touched. A
# snapshot whose mode is not `full`, or whose tree was dirty, is refused: a
# darwin or a partial run is not the history (QM-013).
set -euo pipefail

snapshot="${1:-}"
[ -n "$snapshot" ] || { echo "usage: $0 <snapshot.json> [--remote R] [--branch B] [--date D] [--dry-run]" >&2; exit 1; }
shift
remote=origin branch=metrics-data date="" dry_run=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --remote) remote="$2"; shift 2 ;;
        --branch) branch="$2"; shift 2 ;;
        --date) date="$2"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        *) echo "publish-snapshot: unknown argument '$1'" >&2; exit 1 ;;
    esac
done
[ -f "$snapshot" ] || { echo "publish-snapshot: no such file $snapshot" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "publish-snapshot: python3 is required" >&2; exit 127; }

root="$(git rev-parse --show-toplevel)"
here="$(cd "$(dirname "$0")" && pwd)"
snapshot="$(cd "$(dirname "$snapshot")" && pwd)/$(basename "$snapshot")"

# Refuse what is not history. The checks are the snapshot's own fields, so a
# caller cannot publish a darwin run by naming the file differently.
#
# The snapshot is untrusted input: in CI it is an artifact of the collector
# job, which ran the tree's build scripts and tools from crates.io, and this
# script runs with a write token. So every field that reaches a path or a git
# command is checked against its exact shape here, in one place, before use:
# a `sha7` of `../x` would otherwise put the file outside history/.
sha7="$(python3 - "$snapshot" <<'PY'
import json, re, sys
try:
    s = json.load(open(sys.argv[1]))
    mode, dirty, sha7 = s["run"]["mode"], s["git"]["dirty"], s["git"]["sha7"]
except (OSError, ValueError, KeyError, TypeError) as e:
    print(f"publish-snapshot: not a snapshot: {e}", file=sys.stderr); sys.exit(1)
if mode != "full":
    print(f"publish-snapshot: refusing a {mode!r} snapshot; only a full run is history", file=sys.stderr); sys.exit(2)
if dirty is not False:
    print("publish-snapshot: refusing a snapshot of a dirty tree", file=sys.stderr); sys.exit(2)
if not isinstance(sha7, str) or not re.fullmatch(r"[0-9a-f]{7}", sha7):
    print(f"publish-snapshot: refusing git.sha7 {sha7!r}; want seven lowercase hex digits", file=sys.stderr); sys.exit(2)
print(sha7)
PY
)" || exit $?
# The snapshot must measure the commit this checkout is on: in CI the publish
# job checks out the run's own commit, so an artifact naming another commit
# was not made by this run's collector and is not published.
case "$(git -C "$root" rev-parse HEAD)" in
    "$sha7"*) ;;
    *) echo "publish-snapshot: refusing git.sha7 '$sha7'; this checkout is at $(git -C "$root" rev-parse --short=7 HEAD)" >&2
       exit 2 ;;
esac
[ -n "$date" ] || date="$(date -u +%Y-%m-%d)"
# [[ =~ ]] anchors the whole string; grep -x would pass one good line of many.
# The shape check comes first so only digits and dashes reach Python, which
# then refuses a date that is not on the calendar (prune.py would skip it).
if ! [[ "$date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] \
    || ! python3 -c 'import datetime, sys; datetime.date.fromisoformat(sys.argv[1])' "$date" 2>/dev/null; then
    echo "publish-snapshot: refusing date '$date'; want a real YYYY-MM-DD date" >&2
    exit 2
fi
name="$date-$sha7.json"

work="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-publish)"
trap 'cd "$root" && git worktree remove --force "$work/wt" 2>/dev/null || true; rm -rf "$work"' EXIT

cd "$root"
if git fetch --quiet "$remote" "$branch" 2>/dev/null; then
    git worktree add --quiet --detach "$work/wt" FETCH_HEAD
else
    # First run: an orphan with nothing of main's history in it, so the data
    # branch stays small and a `git log` on it is only snapshots.
    git worktree add --quiet --detach "$work/wt" HEAD
    git -C "$work/wt" checkout --quiet --orphan "$branch"
    git -C "$work/wt" rm -rfq . >/dev/null 2>&1 || true
    cat > "$work/wt/README.md" <<'EOF'
# metrics-data

The quality-metrics history of `gominimal/minimal` (spec 31). One snapshot per
nightly run under `history/`, named by date and short commit, written by
`scripts/metrics/publish-snapshot.sh` from the nightly workflow. Nothing else
lives here, and nothing here is edited by hand: the gate reads the newest
snapshot as its baseline, and the dashboard reads them all.
EOF
fi
mkdir -p "$work/wt/history"
cp "$snapshot" "$work/wt/history/$name"
python3 "$here/prune.py" "$work/wt/history" >/dev/null

git -C "$work/wt" add -A
if git -C "$work/wt" diff --cached --quiet; then
    echo "publish-snapshot: $name already in $branch; nothing to publish"
    exit 0
fi
export GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-github-actions[bot]}"
export GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-41898282+github-actions[bot]@users.noreply.github.com}"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
git -C "$work/wt" commit --quiet -m "metrics: snapshot $name"
if [ "$dry_run" -eq 1 ]; then
    echo "publish-snapshot: would push $(git -C "$work/wt" rev-parse --short HEAD) to $remote $branch ($name)"
    exit 0
fi
# Only ever this ref. A refspec with the branch on both sides cannot land on
# main whatever HEAD is.
git -C "$work/wt" push --quiet "$remote" "HEAD:refs/heads/$branch"
echo "publish-snapshot: pushed $name to $remote/$branch"
