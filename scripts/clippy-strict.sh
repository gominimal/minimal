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
# Usage: scripts/clippy-strict.sh [BASE] [CARGO_SCOPE...]
#
# BASE defaults to the merge-base with the main branch; only diagnostics whose
# primary span falls on a line added or changed since BASE are reported. Any
# further arguments are passed to `cargo clippy` as the crate scope (the
# justfile supplies its per-OS `scope`); the whole workspace is the default.
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

# macOS cannot build the Linux-only crates, so the caller passes the justfile's
# per-OS scope; default to the whole workspace.
cargo_scope=("$@")
if [ "${#cargo_scope[@]}" -eq 0 ]; then
    cargo_scope=(--workspace)
fi

lint_args=()
for lint in "${lints[@]}"; do
    lint_args+=(-W "$lint")
done

diff_file="$(mktemp)"
out_file="$(mktemp)"
trap 'rm -f "$diff_file" "$out_file"' EXIT

# Changed lines in the new revision, as "path<TAB>start<TAB>end" (1-based,
# inclusive). -U0 gives one hunk per contiguous edit; a zero-length new range is
# a pure deletion, which has no lines to report on. --no-ext-diff/--no-textconv
# keep this parseable when a developer has a diff renderer (e.g. difftastic) or
# textconv configured, which would otherwise replace the hunk headers.
git diff -U0 --no-color --no-ext-diff --no-textconv --diff-filter=d \
    "$base"...HEAD -- '*.rs' > "$diff_file"

if [ ! -s "$diff_file" ]; then
    echo "clippy-strict: no Rust changes since ${base}"
    exit 0
fi

# Clippy exits non-zero whenever it emits any diagnostic; the JSON stream is
# what we read, so its exit code is deliberately ignored.
cargo clippy "${cargo_scope[@]}" --all-targets --locked --message-format=json -- \
    "${lint_args[@]}" > "$out_file" 2>/dev/null || true

python3 - "$out_file" "$diff_file" "${lints[@]}" <<'PY'
import json
import sys

out_path, diff_path = sys.argv[1], sys.argv[2]
strict = set(sys.argv[3:])

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
