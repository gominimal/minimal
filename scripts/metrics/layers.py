#!/usr/bin/env python3
"""Crate-layer direction check over `cargo metadata` (spec 31, QM-007, QM-008).

Reads `metrics/layers.toml` and the workspace's `cargo metadata`, and reports
every normal dependency edge between workspace crates that the layer table
forbids. An edge named by an `[[exception]]` is reported as excepted and
counted toward the exceptions ratchet; one no exception names is unexcepted
and fails the gate. A member in no layer, or in two, is unassigned and fails
the gate too, as does a stale exception: one that names no forbidden edge.
Development and build dependencies are not edges.

Standalone: `python3 scripts/metrics/layers.py [--rules F] [--metadata F]
[--json]`. `collect.py` imports `analyse` and reads the same dict. Exit 0
clean, 2 findings, 1 for a crash or an unreadable input; stdlib only.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tomllib
from pathlib import Path

GATE_EXIT = 2


def load_rules(path: Path) -> dict:
    with path.open("rb") as fh:
        rules = tomllib.load(fh)
    if rules.get("schema") != 1:
        raise SystemExit(f"{path}: unsupported layers schema {rules.get('schema')!r}")
    return rules


def load_metadata(path: Path | None) -> dict:
    if path is not None:
        return json.loads(path.read_text(encoding="utf-8"))
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


def analyse(meta: dict, rules: dict) -> dict:
    """The layer findings for one workspace, as the snapshot's `layers` block."""
    # `--no-deps` metadata lists only the workspace, but full metadata passed
    # through `--metadata` lists every dependency too; scope to the members.
    member_ids = set(meta["workspace_members"])
    members = {p["name"]: p for p in meta["packages"] if p["id"] in member_ids}
    layer_of: dict[str, str] = {}
    doubly: set[str] = set()
    for layer, crates in rules["layers"].items():
        for crate in crates:
            if crate in layer_of:
                doubly.add(crate)
            layer_of[crate] = layer
    unassigned = sorted(
        [name for name in members if name not in layer_of] + sorted(doubly)
    )
    unknown = sorted(name for name in layer_of if name not in members)

    allowed = {layer: set(targets) for layer, targets in rules["allowed"].items()}
    exceptions = {
        (e["from"], e["to"]): e for e in rules.get("exception", [])
    }

    member_dirs = {
        str(Path(p["manifest_path"]).parent): n for n, p in members.items() if "manifest_path" in p
    }

    def internal(dep: dict) -> bool:
        """A path dependency on a workspace member, not a registry or git
        crate that shares a member's name. Metadata without `source` or
        `path` (older fixtures) falls back to the name."""
        if dep["name"] not in members or dep.get("source") is not None:
            return False
        path = dep.get("path")
        return path is None or member_dirs.get(path) == dep["name"]

    violations = []
    edges = 0
    for name in sorted(members):
        src_layer = layer_of.get(name)
        if src_layer is None:
            continue
        for dep in members[name]["dependencies"]:
            if dep.get("kind") is not None or not internal(dep):
                continue
            edges += 1
            dst_layer = layer_of.get(dep["name"])
            if dst_layer is None or dst_layer in allowed.get(src_layer, set()):
                continue
            exc = exceptions.get((name, dep["name"]))
            violations.append(
                {
                    "from": name,
                    "to": dep["name"],
                    "from_layer": src_layer,
                    "to_layer": dst_layer,
                    "excepted": exc is not None,
                    "issue": exc.get("issue") if exc else None,
                    "since": exc.get("since") if exc else None,
                }
            )
    live = {(v["from"], v["to"]) for v in violations}
    stale = sorted(f"{f} -> {t}" for (f, t) in exceptions if (f, t) not in live)
    return {
        "edges": edges,
        "violations": violations,
        "unexcepted": sum(1 for v in violations if not v["excepted"]),
        "exceptions": sum(1 for v in violations if v["excepted"]),
        "unassigned": unassigned,
        "unknown": unknown,
        "stale_exceptions": stale,
    }


def render(result: dict) -> str:
    lines = []
    for v in result["violations"]:
        tag = "excepted " if v["excepted"] else "FORBIDDEN"
        extra = f" ({v['issue']}, since {v['since']})" if v["excepted"] else ""
        lines.append(
            f"{tag} {v['from']} ({v['from_layer']}) -> {v['to']} ({v['to_layer']}){extra}"
        )
    for name in result["unassigned"]:
        lines.append(f"UNASSIGNED {name}: in no layer, or in two")
    for name in result["unknown"]:
        lines.append(f"unknown {name}: named in layers.toml, not a workspace member")
    for edge in result["stale_exceptions"]:
        lines.append(f"stale exception {edge}: no such edge; remove it")
    lines.append(
        f"layers: {result['edges']} internal edges, "
        f"{result['exceptions']} excepted, {result['unexcepted']} forbidden, "
        f"{len(result['unassigned'])} unassigned"
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", type=Path, default=Path("metrics/layers.toml"))
    parser.add_argument("--metadata", type=Path, help="cargo metadata JSON (fixture)")
    parser.add_argument("--json", action="store_true", help="print the findings as JSON")
    args = parser.parse_args(argv)

    result = analyse(load_metadata(args.metadata), load_rules(args.rules))
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else render(result))
    # A stale exception fails too: left in place, it would let a removed edge
    # come back, or outlive a layer move, without a change to the table.
    failing = (
        result["unexcepted"]
        or result["unassigned"]
        or result["unknown"]
        or result["stale_exceptions"]
    )
    return GATE_EXIT if failing else 0


if __name__ == "__main__":
    sys.exit(main())
