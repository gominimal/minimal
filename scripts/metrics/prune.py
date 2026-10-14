#!/usr/bin/env python3
"""Prune a snapshot history: daily for ninety days, then monthly (spec 30, QM-015).

The history is a directory of `YYYY-MM-DD-<sha7>.json` files, one per
nightly run, so the file name alone says when a snapshot was taken and
nothing has to be opened to decide its fate. A snapshot stays when it is
dated within ninety days of `today`, or when it is the earliest snapshot of
its calendar month; everything else goes. `today` defaults to the newest
snapshot's date, so the outcome depends on the history, never on the wall
clock, and the harness can replay it.

Usage: prune.py <history_dir> [--dry-run] [--today YYYY-MM-DD]

Files that do not follow the naming scheme are left alone and named on
stderr. `--dry-run` prints what would go and removes nothing. `keep` is the
decision as a pure function; the harness checks the spec's property
against it.
"""

from __future__ import annotations

import re
import sys
from datetime import date, timedelta
from pathlib import Path

KEEP_DAYS = 90
NAME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})-[0-9a-f]{7}\.json$")


def dated(name: str) -> date | None:
    """The date in a snapshot's file name, or None when the name is not one."""
    m = NAME.match(name)
    if not m:
        return None
    try:
        return date(int(m[1]), int(m[2]), int(m[3]))
    except ValueError:
        return None


def keep(names: list[str], today: date) -> set[str]:
    """The snapshots to keep: every one dated within KEEP_DAYS of `today`, and
    beyond that the earliest of each calendar month.

    Names that are not snapshots are neither kept nor removed; they are
    simply absent from the result. Two snapshots on the same day are both
    inside the window or both outside it; outside, the lexicographically
    first is the month's earliest. A snapshot dated after `today` has a
    negative age and stays.
    """
    snaps = sorted((d, n) for n in names if (d := dated(n)) is not None)
    kept = {n for d, n in snaps if today - d <= timedelta(days=KEEP_DAYS)}
    earliest: dict[tuple[int, int], str] = {}
    for d, n in snaps:  # sorted, so the first seen per month is the earliest
        earliest.setdefault((d.year, d.month), n)
    kept.update(earliest.values())
    return kept


def main(argv: list[str]) -> int:
    dry_run = False
    today: date | None = None
    positional: list[str] = []
    args = iter(argv)
    for arg in args:
        if arg == "--dry-run":
            dry_run = True
        elif arg == "--today":
            try:
                today = date.fromisoformat(next(args))
            except (StopIteration, ValueError):
                print("prune: --today takes YYYY-MM-DD", file=sys.stderr)
                return 2
        else:
            positional.append(arg)
    if len(positional) != 1:
        print("usage: prune.py <history_dir> [--dry-run] [--today YYYY-MM-DD]", file=sys.stderr)
        return 2
    history = Path(positional[0])
    if not history.is_dir():
        print(f"prune: {history} is not a directory", file=sys.stderr)
        return 1

    names = sorted(p.name for p in history.iterdir() if p.is_file())
    snaps = [n for n in names if dated(n) is not None]
    for n in names:
        if dated(n) is None:
            print(f"prune: not a snapshot name, left alone: {n}", file=sys.stderr)
    if not snaps:
        print("prune: no snapshots")
        return 0
    if today is None:
        today = max(d for n in snaps if (d := dated(n)) is not None)

    kept = keep(snaps, today)
    doomed = [n for n in snaps if n not in kept]
    verb = "would remove" if dry_run else "remove"
    for n in doomed:
        print(f"{verb} {n}")
        if not dry_run:
            (history / n).unlink()
    summary = "would remove" if dry_run else "removed"
    print(f"prune: today {today.isoformat()}, kept {len(kept)}, {summary} {len(doomed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
