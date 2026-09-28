#!/usr/bin/env bash
# Strict Clippy gate, scoped to the lines this branch changed.
#
# The lints below are the ones the workspace is not yet clean for. They cannot
# live in [workspace.lints] yet: CI's clippy job runs `-D warnings`, which
# promotes a `warn` lint into a hard error, so enabling one with any surviving
# hit would fail every PR. Reporting them on changed lines only lets the
# strictness land now — new and edited code is held to the standard — without
# turning the existing sites into build failures. Move a lint into
# [workspace.lints.clippy] once its count reaches zero.
#
# Because the flags are passed on the command line rather than in Cargo.toml,
# plain `cargo clippy` / `just clippy` is unaffected and `just ci` stays green.
#
# Cost: Clippy cannot lint a subset of lines, so the whole selected crates are
# compiled and the filter below discards what did not change. The selection is
# therefore the crates the changed files belong to, not the workspace, so a
# short-lived sandbox does not pay for every crate.
#
# Usage: scripts/clippy-strict.sh [BASE] [CARGO_SCOPE...]
#
# CLIPPY_STRICT_REPORT_ONLY=1 prints the diagnostics and exits 0. `just fix` sets
# it, because that recipe is the mid-edit loop and a hit there is information
# rather than a stop: the round's directive bounds what the change may touch, and
# a gate that fails inside the innermost loop argues for editing past it. `just
# ci` runs without it, which is where "before opening a PR" owns the decision.
# Under it the script never exits non-zero: a build or tooling failure is
# printed with its exit code and demoted too, because `just fix` is an autofix
# loop that must be safe to run any number of times and must never stop on the
# gate. Without it every failure is fatal, so `just ci` still cannot pass on a
# gate that did not run.
#
# BASE defaults to the merge-base with `origin/main`; only diagnostics whose
# primary span falls on a line added or changed since BASE are reported. Edits
# that are not committed yet count, as do untracked files. Any further arguments
# are passed to `cargo clippy` as the crate scope, overriding the derived one
# (the justfile pins it on macOS, where the Linux-only crates do not build).
set -euo pipefail

# A failure to run the gate at all. Enforcing, it is fatal with its own exit
# code; report-only, it is said and demoted, so `just fix` never stops here.
report_only_exit() {
    if [ -n "${CLIPPY_STRICT_REPORT_ONLY:-}" ]; then
        echo "clippy-strict: did not run to completion (exit $1); nothing enforced" \
            "here, \`just ci\` is the gate" >&2
        exit 0
    fi
    exit "$1"
}

lints=(
    clippy::string_slice
    clippy::indexing_slicing
    clippy::unwrap_used
    clippy::panic
    clippy::todo
    clippy::unimplemented
    clippy::unreachable
    clippy::get_unwrap
    clippy::unwrap_in_result
    clippy::panic_in_result_fn
    clippy::let_underscore_must_use
    clippy::unused_result_ok
    clippy::map_err_ignore
    clippy::assertions_on_result_states
    clippy::large_futures
    clippy::mem_forget
    clippy::undocumented_unsafe_blocks
    clippy::multiple_unsafe_ops_per_block
    clippy::unnecessary_safety_comment
    clippy::cast_sign_loss
    clippy::allow_attributes
    clippy::allow_attributes_without_reason
)

cd "$(git rev-parse --show-toplevel)"

base="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi
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

explicit_scope=("$@")

lint_args=()
for lint in "${lints[@]}"; do
    lint_args+=(-W "$lint")
done

diff_file="$(mktemp)"
out_file="$(mktemp)"
err_file="$(mktemp)"
untracked_file="$(mktemp)"
trap 'rm -f "$diff_file" "$out_file" "$err_file" "$untracked_file"' EXIT

# Changed lines in the new revision, as "path<TAB>start<TAB>end" (1-based,
# inclusive). -U0 gives one hunk per contiguous edit; a zero-length new range is
# a pure deletion, which has no lines to report on. The comparison is against
# the working tree, not HEAD: this gate is meant to run before committing, so an
# uncommitted edit has to count. Diffing from the merge-base keeps the base
# branch's own commits out of the comparison.
# --no-ext-diff/--no-textconv keep this parseable when a developer has a diff
# renderer (e.g. difftastic) or textconv configured, which would otherwise
# replace the hunk headers.
merge_base="$(git merge-base "$base" HEAD)"
git diff -U0 --no-color --no-ext-diff --no-textconv --diff-filter=d \
    "$merge_base" -- '*.rs' > "$diff_file"

# A brand-new file is untracked, so it does not appear in the diff above.
git ls-files --others --exclude-standard -- '*.rs' > "$untracked_file"

if [ ! -s "$diff_file" ] && [ ! -s "$untracked_file" ]; then
    echo "clippy-strict: no Rust changes since ${base}"
    exit 0
fi

# The crates the changed files belong to, one name per line out of
# `crates/<name>/...` with other paths ignored. This drives the scope, and it
# also lets the gate say what a pinned scope leaves out. Deleted paths are
# filtered out, or a crate the branch removed would reach `cargo clippy -p` and
# fail the run before the remaining change was checked. Selecting crates is the
# difference between a few minutes and a cold workspace build; `-p` still checks
# every dependency of those crates, so a warning in a shared crate is caught.
# Paths outside `crates/` leave the list empty, which falls back to the
# workspace.
# shellcheck disable=SC2086
changed_crates=$( { git diff --name-only --no-ext-diff --diff-filter=d \
                        "$merge_base" -- '*.rs'
                    cat "$untracked_file"; } \
    | sed -n 's|^crates/\([^/][^/]*\)/.*|\1|p' | sort -u )

# An explicit scope wins: macOS pins one because the Linux-only crates do not
# build there.
cargo_scope=("${explicit_scope[@]}")
if [ "${#cargo_scope[@]}" -eq 0 ]; then
    # shellcheck disable=SC2086
    for crate in $changed_crates; do
        cargo_scope+=(-p "$crate")
    done
fi
if [ "${#cargo_scope[@]}" -eq 0 ]; then
    cargo_scope=(--workspace)
fi

# A pinned scope is narrower than the change. Say so: "a gate that silently
# narrows itself is worse than one that says what it covers"
# (.minimal/minimal.toml). The Linux lanes are what cover the rest.
uncovered=""
if [ "${#explicit_scope[@]}" -gt 0 ]; then
    # shellcheck disable=SC2086
    for crate in $changed_crates; do
        case " ${explicit_scope[*]} " in
            *" -p $crate "*) ;;
            *) uncovered="$uncovered $crate" ;;
        esac
    done
fi
if [ -n "$uncovered" ]; then
    echo "clippy-strict: scope pinned to ${explicit_scope[*]};" \
        "changed crates not covered here:$uncovered" >&2
fi
echo "clippy-strict: scope ${cargo_scope[*]}" >&2

# -W lints never fail the run, so a non-zero exit here is a build or tooling
# failure (a compile error, a stale Cargo.lock under --locked, no toolchain).
# Surface it instead of letting the empty JSON stream read as clean.
status=0
cargo clippy "${cargo_scope[@]}" --all-targets --locked --message-format=json -- \
    "${lint_args[@]}" > "$out_file" 2> "$err_file" || status=$?
if [ "$status" -ne 0 ]; then
    echo "clippy-strict: cargo clippy failed (exit ${status})" >&2
    cat "$err_file" >&2
    report_only_exit "$status"
fi

# HITS_EXIT, and only HITS_EXIT, is the filter saying it found something. Any
# other non-zero is the filter itself failing — no python3 on PATH, a crash in
# it — and is said as such rather than read as clean: enforcing, it is fatal;
# report-only, it is printed and demoted like everything else.
HITS_EXIT=2
hits_status=0
python3 - "$HITS_EXIT" "$out_file" "$diff_file" "$untracked_file" "${lints[@]}" <<'PY' || hits_status=$?
import json
import sys

hits_exit = int(sys.argv[1])
out_path, diff_path, untracked_path = sys.argv[2], sys.argv[3], sys.argv[4]
strict = set(sys.argv[5:])

# path -> [(start, end)] of lines added or changed in the new revision.
changed = {}
current = None
for raw in open(diff_path, encoding="utf-8", errors="replace"):
    if raw.startswith("+++ "):
        target = raw[4:].strip()
        current = None if target == "/dev/null" else (
            target[2:] if target.startswith("b/") else target)
        if current is not None:
            changed.setdefault(current, [])
    elif raw.startswith("@@") and current is not None:
        try:
            plus = raw.split("+", 1)[1].split("@@", 1)[0].strip()
            start, _, count = plus.partition(",")
            start = int(start)
            count = int(count) if count else 1
        except (IndexError, ValueError):
            continue
        if count > 0:
            changed[current].append((start, start + count - 1))

# Every line of an untracked file is new.
for raw in open(untracked_path, encoding="utf-8", errors="replace"):
    path = raw.strip()
    if path:
        changed[path] = [(1, sys.maxsize)]


def ranges_for(path):
    ranges = changed.get(path)
    if ranges:
        return ranges
    # Clippy's paths are workspace-relative in practice; fall back to a suffix
    # match in case a crate reports a package-relative path.
    for known, known_ranges in changed.items():
        if path.endswith("/" + known) or known.endswith("/" + path):
            return known_ranges
    return None


hits = []
seen = set()
for raw in open(out_path, encoding="utf-8", errors="replace"):
    if '"compiler-message"' not in raw:
        continue
    try:
        message = json.loads(raw)
    except json.JSONDecodeError:
        continue
    if message.get("reason") != "compiler-message":
        continue
    body = message.get("message", {})
    if body.get("level") not in ("warning", "error"):
        continue
    code = (body.get("code") or {}).get("code") or ""
    # The crate's own lints (e.g. pedantic in `paths` and `sessions`) are
    # already enforced repo-wide by `just clippy`; this gate owns only the
    # stricter set, and --all-targets would otherwise report each diagnostic
    # once per compilation unit.
    if code not in strict:
        continue
    span = next((s for s in body.get("spans", []) if s.get("is_primary")), None)
    if span is None:
        continue
    path = span.get("file_name") or ""
    line = span.get("line_start")
    if line is None:
        continue
    ranges = ranges_for(path)
    if not ranges or not any(start <= line <= end for start, end in ranges):
        continue
    if (path, line, code) in seen:
        continue
    seen.add((path, line, code))
    hits.append((path, line, code, body.get("message")))

for path, line, code, text in hits:
    print(f"{path}:{line}: {text} [{code}]")

if hits:
    # Flush first: stdout is block-buffered under a pipe, stderr is not, so
    # without this the guidance lands above the diagnostics it refers to.
    sys.stdout.flush()
    print(
        f"\nclippy-strict: {len(hits)} diagnostic(s) on the lines your branch "
        f"changed.\nThese lints are stricter than the repo-wide set, so a "
        f"failure here is about this change: fix them, or suppress a single one\n"
        f'with #[expect(<lint>, reason = "...")]. Re-run: just clippy-strict',
        file=sys.stderr,
    )
    # Distinct from the 1 an unhandled exception here would exit with, so the
    # caller can demote hits without demoting a broken filter.
    sys.exit(hits_exit)

print("clippy-strict: clean")
PY

if [ "$hits_status" -eq "$HITS_EXIT" ] && [ -n "${CLIPPY_STRICT_REPORT_ONLY:-}" ]; then
    echo "clippy-strict: reported, not enforced here." \
        "\`just ci\` is the gate; in a revise or conflict round the directive" \
        "bounds the change, so these belong in \`notes\`." >&2
    exit 0
fi
if [ "$hits_status" -ne 0 ] && [ "$hits_status" -ne "$HITS_EXIT" ]; then
    echo "clippy-strict: the diagnostic filter failed (exit ${hits_status});" \
        "nothing was checked" >&2
    report_only_exit "$hits_status"
fi
exit "$hits_status"
