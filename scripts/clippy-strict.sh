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
# Callers: `just clippy-strict` and, through it, `just ci`. Not `just fix`: that
# is the mid-edit loop, and everything it prints is something to fix, so a hit
# printed there reads as work whatever a doc says — the round's directive bounds
# what a change may touch, and a hit outside it belongs in the round's notes.
#
# Exit codes: 0 clean, 2 hits on changed lines, anything else a failure to run
# (cargo's own status, 127 with no python3, 1 for a crash in the filter). A gate
# that exits 0 because it could not run is worse than no gate, so none of those
# is ever read as clean.
#
# BASE defaults to the merge-base with `origin/main`; only diagnostics whose
# primary span falls on a line added or changed since BASE are reported. Edits
# that are not committed yet count, as do untracked files. Any further arguments
# are passed to `cargo clippy` as the crate scope, overriding the derived one
# (the justfile pins it on macOS, where the Linux-only crates do not build).
set -euo pipefail

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

# Resolved before the cd: `$0` may be relative to where the caller stood.
here="$(cd "$(dirname "$0")" && pwd)"
cd "$(git rev-parse --show-toplevel)"

# The base ref, the changed lines and the changed crates come from the library
# the metrics grader (scripts/metrics/run.sh) shares with this gate, so the two
# agree on which lines are the branch's own. The library's comments say why
# the default base is `origin/main` and not the local `main`. lint-shell.sh
# checks the library as a script of its own, so it is not followed from here.
# shellcheck disable=SC1091
. "$here/lib/changed-lines.sh"

base="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi
base="$(changed_lines_base "$base")"

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

# Changed lines in the new revision (a -U0 diff against the working tree, so an
# uncommitted edit counts; changed-lines.sh says why) plus the untracked Rust
# files, which the diff cannot see.
merge_base="$(git merge-base "$base" HEAD)"
changed_lines_diff "$merge_base" "$diff_file"
changed_lines_untracked "$untracked_file"

if [ ! -s "$diff_file" ] && [ ! -s "$untracked_file" ]; then
    echo "clippy-strict: no Rust changes since ${base}"
    exit 0
fi

# The crates the changed files belong to, one name per line. This drives the
# scope, and it also lets the gate say what a pinned scope leaves out.
# Selecting crates is the difference between a few minutes and a cold
# workspace build; `-p` still checks every dependency of those crates, so a
# warning in a shared crate is caught. Paths outside `crates/` leave the list
# empty, which falls back to the workspace.
changed_crates=$(changed_crates "$merge_base" "$untracked_file")

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
    exit "$status"
fi

# HITS_EXIT, and only HITS_EXIT, is the filter saying it found something. Any
# other non-zero is the filter itself failing — no python3 on PATH, a crash in
# it — and is said as such rather than read as clean.
HITS_EXIT=2
hits_status=0
python3 - "$HITS_EXIT" "$out_file" "$diff_file" "$untracked_file" "$here/metrics" "${lints[@]}" <<'PY' || hits_status=$?
import json
import sys

hits_exit = int(sys.argv[1])
out_path, diff_path, untracked_path = sys.argv[2], sys.argv[3], sys.argv[4]
# The range parsing is shared with the metrics grader (changed_lines.py), so
# the two gates agree on which lines are the branch's own.
sys.path.insert(0, sys.argv[5])
import changed_lines  # noqa: E402

strict = set(sys.argv[6:])

# path -> [(start, end)] of lines added or changed in the new revision; every
# line of an untracked file is new.
changed = changed_lines.parse_ranges(diff_path, untracked_path)

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
    # The crate's own lints (e.g. pedantic in `paths` and `boxes`) are
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
    if not changed_lines.in_ranges(changed, path, line):
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

if [ "$hits_status" -ne 0 ] && [ "$hits_status" -ne "$HITS_EXIT" ]; then
    echo "clippy-strict: the diagnostic filter failed (exit ${hits_status});" \
        "nothing was checked" >&2
fi
exit "$hits_status"
