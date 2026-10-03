#!/usr/bin/env bash
#
# cancel-stale-queue-runs_test.sh — test harness for
# scripts/cancel-stale-queue-runs.sh.
#
# Points the script at a stub `gh` backed by a directory (no network, no
# auth) and asserts the contract: a merge_group run whose head is not a live
# queue entry is cancelled, a live one is kept, a run of any other event or
# branch is never touched, an empty queue makes every group run stale, a
# failed, null or truncated queue answer cancels nothing, and a dry run
# cancels nothing. Run directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/cancel-stale-queue-runs.sh"
[ -f "$script" ] || { echo "cannot find cancel-stale-queue-runs.sh next to test" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq not installed — skipping cancel-stale-queue-runs_test.sh"; exit 0; }

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-janitortest)"
trap 'rm -rf "$root"' EXIT

# The stub serves runs-<status>.jsonl for a run listing, queue.json for the
# GraphQL query (exit 1 when queue.fail exists), refuses a cancel with the
# message in cancel-err-<id> when that file exists, and records each
# cancelled run id in cancelled.
stub="$root/gh"
cat >"$stub" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
d="$STUB_DIR"
args="$*"
case "$args" in
    *"api graphql"*)
        [ -e "$d/queue.fail" ] && exit 1
        cat "$d/queue.json" ;;
    *"-X POST"*"/cancel"*)
        id="${args##*/runs/}"; id="${id%%/cancel*}"
        if [ -f "$d/cancel-err-$id" ]; then cat "$d/cancel-err-$id" >&2; exit 1; fi
        echo "$id" >>"$d/cancelled" ;;
    *"/runs?"*)
        status="${args##*status=}"; status="${status%%&*}"
        [ -f "$d/runs-$status.jsonl" ] && cat "$d/runs-$status.jsonl"
        : ;;
    *) echo "stub gh: unexpected call: $*" >&2; exit 2 ;;
esac
STUB
chmod +x "$stub"

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "ok   - $1"; }
bad() { fail=$((fail + 1)); echo "FAIL - $1"; }

run_n=0
# fresh — a clean stub directory for one case.
fresh() {
    run_n=$((run_n + 1))
    STUB_DIR="$root/case$run_n"
    export STUB_DIR
    mkdir -p "$STUB_DIR"
}
# run_obj <id> <sha> <branch> [event]
run_obj() {
    printf '{"id":%s,"head_sha":"%s","head_branch":"%s","event":"%s"}\n' "$1" "$2" "$3" "${4:-merge_group}"
}
# queue <sha...> — a live queue holding entries with these head SHAs.
queue() {
    local nodes="" s
    for s in "$@"; do nodes+="${nodes:+,}{\"headCommit\":{\"oid\":\"$s\"}}"; done
    printf '{"data":{"repository":{"mergeQueue":{"entries":{"pageInfo":{"hasNextPage":false},"nodes":[%s]}}}}}\n' \
        "$nodes" >"$STUB_DIR/queue.json"
}
janitor() {
    GH="$stub" "$script" --repo acme/widgets "$@" 2>"$STUB_DIR/stderr"
}
cancelled() { sort -n "$STUB_DIR/cancelled" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }

Q=gh-readonly-queue/main

# 1. Stale group runs are cancelled, live ones kept, other events and other
#    branches never touched; queued and in_progress listings both count.
fresh
{ run_obj 1 aaa "$Q/pr-1-x"; run_obj 2 bbb "$Q/pr-2-y"; run_obj 3 ccc feature pull_request; } >"$STUB_DIR/runs-queued.jsonl"
{ run_obj 4 ddd "$Q/pr-4-z"; run_obj 5 eee gh-readonly-queue/release/x/pr-5-q; } >"$STUB_DIR/runs-in_progress.jsonl"
queue bbb
if janitor --execute >/dev/null && [ "$(cancelled)" = "1 4" ]; then
    ok "stale group runs cancelled; live, non-merge_group and other-branch runs kept"
else
    bad "expected cancels '1 4', got '$(cancelled)'"
fi

# 2. An empty queue makes every group run stale; a run listed under two
#    statuses is cancelled once.
fresh
run_obj 7 aaa "$Q/pr-7-x" >"$STUB_DIR/runs-queued.jsonl"
cp "$STUB_DIR/runs-queued.jsonl" "$STUB_DIR/runs-pending.jsonl"
queue
if janitor --execute >/dev/null && [ "$(cancelled)" = "7" ]; then
    ok "an empty queue makes every group run stale, each cancelled once"
else
    bad "expected cancels '7', got '$(cancelled)'"
fi

# 3. Dry run cancels nothing but reports the stale run.
fresh
run_obj 8 aaa "$Q/pr-8-x" >"$STUB_DIR/runs-queued.jsonl"
queue
out="$(janitor)"
if [ -z "$(cancelled)" ] && grep -q 'would cancel: 8 aaa' <<<"$out"; then
    ok "dry run reports the stale run and cancels nothing"
else
    bad "dry run: cancels '$(cancelled)', output: $out"
fi

# 4. A run that finished before its cancel (HTTP 409) is not a failure.
fresh
{ run_obj 10 aaa "$Q/pr-10-x"; run_obj 11 bbb "$Q/pr-11-y"; } >"$STUB_DIR/runs-queued.jsonl"
queue
echo "gh: Cannot cancel a workflow run that is completed. (HTTP 409)" >"$STUB_DIR/cancel-err-10"
if out="$(janitor --execute)" && [ "$(cancelled)" = "11" ] && grep -q 'already finished: 10' <<<"$out"; then
    ok "a run that already finished is reported and the janitor exits 0"
else
    bad "409 case: cancels '$(cancelled)', output: $out"
fi

# 5. Any other refused cancel still lets the rest run, then fails the run.
fresh
{ run_obj 12 aaa "$Q/pr-12-x"; run_obj 13 bbb "$Q/pr-13-y"; } >"$STUB_DIR/runs-queued.jsonl"
queue
echo "gh: Resource not accessible by integration (HTTP 403)" >"$STUB_DIR/cancel-err-12"
if ! janitor --execute >/dev/null && [ "$(cancelled)" = "13" ]; then
    ok "a refused cancel (403) exits non-zero after cancelling the rest"
else
    bad "403 case: cancels '$(cancelled)'"
fi

# 6–10. A failed, errored, null, truncated or head-less queue answer cancels
#       nothing.
for kind in fail errors null truncated headless; do
    fresh
    run_obj 9 aaa "$Q/pr-9-x" >"$STUB_DIR/runs-queued.jsonl"
    case "$kind" in
        fail)      touch "$STUB_DIR/queue.fail" ;;
        errors)    echo '{"errors":[{"message":"nope"}],"data":null}' >"$STUB_DIR/queue.json" ;;
        null)      echo '{"data":{"repository":{"mergeQueue":null}}}' >"$STUB_DIR/queue.json" ;;
        truncated) echo '{"data":{"repository":{"mergeQueue":{"entries":{"pageInfo":{"hasNextPage":true},"nodes":[]}}}}}' >"$STUB_DIR/queue.json" ;;
        headless)  echo '{"data":{"repository":{"mergeQueue":{"entries":{"pageInfo":{"hasNextPage":false},"nodes":[{"headCommit":null}]}}}}}' >"$STUB_DIR/queue.json" ;;
    esac
    if ! janitor --execute >/dev/null && [ -z "$(cancelled)" ]; then
        ok "the $kind queue answer exits non-zero and cancels nothing"
    else
        bad "the $kind queue answer: cancels '$(cancelled)'"
    fi
done

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
