#!/usr/bin/env python3
"""Snapshot schema version 1 (spec 31, QM-001).

A hand-rolled validator, stdlib only: the one dependency a JSON Schema
library would add is not worth an install step on every host that runs
`just metrics`. The shape is documented in metrics/README.md; this file is
the executable copy. `collect.py` calls `validate` before it writes, and
the harness calls it on fixtures.

Standalone: `python3 scripts/metrics/schema.py snapshot.json` exits 0 when
the document validates and 1 with one problem per line when it does not.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SCHEMA_VERSION = 1
MODES = ("full", "static", "gate", "diff", "darwin", "mutants")
RESULTS = ("pass", "warn", "fail", "not_evaluated")
GATE_KINDS = ("floor", "ceiling", "ratchet")

# Per-crate metric blocks. Each is either `null` (not measured) or a dict with
# at least these keys. Extra keys are allowed everywhere: a newer collector
# may record more than an older reader knows.
CRATE_BLOCKS: dict[str, tuple[str, ...]] = {
    "size": ("files", "code", "comments", "blanks", "test_code"),
    "clippy": ("workspace_lints", "strict", "complexity"),
    "coverage": ("lines",),
    "modules": ("acyclic", "orphans"),
    "deps": ("internal", "unused"),
    "mutants": ("tested", "caught", "missed"),
    "crap": ("functions", "over_threshold"),
    # Recorded, never gated (QM-005): one sub-block per tool, each null when
    # that tool did not run; the whole block is null when neither did.
    "experimental": ("rustqual", "anatomy"),
}


def _problems(doc: object) -> list[str]:
    out: list[str] = []

    def need(container: dict, key: str, where: str, kind: type | tuple = object) -> object:
        if key not in container:
            out.append(f"{where}: missing {key!r}")
            return None
        value = container[key]
        if value is not None and not isinstance(value, kind):
            out.append(f"{where}.{key}: expected {kind}, got {type(value).__name__}")
        return value

    if not isinstance(doc, dict):
        return ["document is not an object"]
    if doc.get("schema_version") != SCHEMA_VERSION:
        out.append(f"schema_version: expected {SCHEMA_VERSION}, got {doc.get('schema_version')!r}")
    if doc.get("kind") != "snapshot":
        out.append(f"kind: expected 'snapshot', got {doc.get('kind')!r}")

    run = need(doc, "run", "run", dict) or {}
    if run.get("mode") not in MODES:
        out.append(f"run.mode: expected one of {MODES}, got {run.get('mode')!r}")
    need(run, "host", "run", dict)
    need(run, "not_measured", "run", dict)

    git = need(doc, "git", "git", dict) or {}
    for key in ("sha", "sha7", "dirty"):
        need(git, key, "git")
    need(doc, "toolchain", "toolchain", dict)
    need(doc, "tools", "tools", dict)
    scope = need(doc, "scope", "scope", dict) or {}
    need(scope, "crates", "scope", list)
    need(scope, "excluded", "scope", dict)

    crates = need(doc, "crates", "crates", dict) or {}
    for name, crate in crates.items():
        where = f"crates.{name}"
        if not isinstance(crate, dict):
            out.append(f"{where}: not an object")
            continue
        need(crate, "layer", where, str)
        for block, keys in CRATE_BLOCKS.items():
            value = need(crate, block, where, dict)
            if isinstance(value, dict):
                for key in keys:
                    if key not in value:
                        out.append(f"{where}.{block}: missing {key!r}")

    need(doc, "workspace", "workspace", dict)
    layers = need(doc, "layers", "layers", dict) or {}
    for key in ("violations", "unexcepted", "exceptions", "unassigned"):
        need(layers, key, "layers")

    gates = need(doc, "gates", "gates", dict) or {}
    for name, gate in gates.items():
        where = f"gates.{name}"
        if not isinstance(gate, dict):
            out.append(f"{where}: not an object")
            continue
        if gate.get("kind") not in GATE_KINDS:
            out.append(f"{where}.kind: expected one of {GATE_KINDS}, got {gate.get('kind')!r}")
        if gate.get("result") not in RESULTS:
            out.append(f"{where}.result: expected one of {RESULTS}, got {gate.get('result')!r}")
        need(gate, "value", where)

    verdict = doc.get("verdict")
    if verdict not in ("pass", "warn", "fail"):
        out.append(f"verdict: expected pass|warn|fail, got {verdict!r}")
    else:
        results = [g.get("result") for g in gates.values() if isinstance(g, dict)]
        rank = {"pass": 0, "not_evaluated": 0, "warn": 1, "fail": 2}
        worst = max((rank.get(r, 0) for r in results), default=0)
        expected = ("pass", "warn", "fail")[worst]
        if verdict != expected:
            out.append(f"verdict: {verdict!r} but the worst gate says {expected!r}")
    return out


def validate(doc: object) -> list[str]:
    """Problems with `doc` as a v1 snapshot; empty when it validates."""
    return _problems(doc)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: schema.py snapshot.json", file=sys.stderr)
        return 2
    doc = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    problems = validate(doc)
    for problem in problems:
        print(problem)
    if not problems:
        print(f"{argv[0]}: valid snapshot v{SCHEMA_VERSION}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
