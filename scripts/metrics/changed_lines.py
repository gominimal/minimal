"""The lines a change touched, from what scripts/lib/changed-lines.sh writes.

`changed_lines_diff` writes a zero-context unified diff and
`changed_lines_untracked` the untracked Rust files; this module turns the two
into `path -> [(start, end)]` of lines added or changed in the new revision
(1-based, inclusive) and answers whether a diagnostic falls on one of them.
scripts/clippy-strict.sh and scripts/metrics/diff.py share it so the two gates
agree on which lines are the change's own. Stdlib only.
"""

from __future__ import annotations

import sys

Ranges = dict[str, list[tuple[int, int]]]


def parse_ranges(diff_path: str, untracked_path: str | None = None) -> Ranges:
    """path -> [(start, end)] of lines added or changed in the new revision."""
    changed: Ranges = {}
    current = None
    with open(diff_path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if raw.startswith("+++ "):
                target = raw[4:].strip()
                current = (
                    None
                    if target == "/dev/null"
                    else (target[2:] if target.startswith("b/") else target)
                )
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
    if untracked_path is not None:
        # Every line of an untracked file is new.
        with open(untracked_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                path = raw.strip()
                if path:
                    changed[path] = [(1, sys.maxsize)]
    return changed


def ranges_for(changed: Ranges, path: str) -> list[tuple[int, int]] | None:
    ranges = changed.get(path)
    if ranges:
        return ranges
    # Clippy's paths are workspace-relative in practice; fall back to a suffix
    # match in case a crate reports a package-relative path.
    for known, known_ranges in changed.items():
        if path.endswith("/" + known) or known.endswith("/" + path):
            return known_ranges
    return None


def in_ranges(changed: Ranges, path: str, line: int) -> bool:
    """Whether `path:line` is a line the change added or edited."""
    ranges = ranges_for(changed, path)
    return bool(ranges) and any(start <= line <= end for start, end in ranges)
