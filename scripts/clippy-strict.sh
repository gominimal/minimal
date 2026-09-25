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
# BASE defaults to the merge-base with the main branch; only diagnostics whose
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

cd "$(git rev-parse --show-toplevel)"

base="${1:-}"
if [ "$#" -gt 0 ]; then
    shift
fi
if [ -z "$base" ]; then
    base="$(git merge-base main HEAD 2>/dev/null || git merge-base origin/main HEAD)"
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

# Scope: an explicit scope wins. Otherwise lint only the crates the changed
# files belong to, which is the difference between a few minutes and a cold
# workspace build. `-p` still checks every dependency of those crates, so a
# warning in a shared crate is caught. Paths outside `crates/` leave the scope
# empty, which falls back to the workspace.
cargo_scope=("${explicit_scope[@]}")
if [ "${#cargo_scope[@]}" -eq 0 ]; then
    # One crate name per line out of `crates/<name>/...`; other paths ignored.
    crates=$( { git diff --name-only --no-ext-diff "$merge_base" -- '*.rs'
                cat "$untracked_file"; } \
        | sed -n 's|^crates/\([^/][^/]*\)/.*|\1|p' | sort -u )
    # shellcheck disable=SC2086
    for crate in $crates; do
        cargo_scope+=(-p "$crate")
    done
fi
if [ "${#cargo_scope[@]}" -eq 0 ]; then
    cargo_scope=(--workspace)
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

python3 - "$out_file" "$diff_file" "$untracked_file" "${lints[@]}" <<'PY'
import json
import sys

out_path, diff_path, untracked_path = sys.argv[1], sys.argv[2], sys.argv[3]
strict = set(sys.argv[4:])

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
    print(
        f"\nclippy-strict: {len(hits)} diagnostic(s) on changed lines "
        f"(fix these, or suppress with #[expect(..., reason = \"...\")])",
        file=sys.stderr,
    )
    sys.exit(1)

print("clippy-strict: clean")
PY
