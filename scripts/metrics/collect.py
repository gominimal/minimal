#!/usr/bin/env python3
"""Turn raw tool output into one snapshot document (spec 31).

`run.sh` runs the tools and hands their files here; this file knows the
shape of each tool's output, attributes every finding to a crate, evaluates
the gates in metrics/thresholds.toml and writes:

  snapshot.json      the v1 snapshot (metrics/README.md; schema.py validates)
  clippy-hits.json   every strict/complexity diagnostic as (path, line, code),
                     for the diff grader to intersect with changed lines
  meta.json          wall-clock data: start time, durations, hostname

Times live in meta.json and nowhere else, so snapshot.json is byte-identical
for an identical tree, baseline and thresholds (QM-006). A collector whose
file was not given is recorded under `run.not_measured` with the reason
`run.sh` passed, and its blocks are null (QM-001).

Exit 0 when the verdict is pass or warn, 2 when it is fail, 1 for a crash or
an unreadable input. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import layers as layers_mod  # noqa: E402
import schema as schema_mod  # noqa: E402

GATE_EXIT = 2
COMPLEXITY_LINTS = (
    "clippy::cognitive_complexity",
    "clippy::too_many_lines",
    "clippy::too_many_arguments",
)
# Snapshot blocks every crate carries; null when not measured.
BLOCKS = ("size", "clippy", "coverage", "modules", "deps", "mutants", "crap", "experimental")
RANK = {"pass": 0, "not_evaluated": 0, "warn": 1, "fail": 2}


# ----------------------------------------------------------------- inputs


def read_json(path: Path | None):
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_lines(path: Path | None) -> list[str]:
    if path is None:
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def git(*args: str) -> str:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def git_info() -> dict:
    sha = git("rev-parse", "HEAD")
    ref = git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    return {"sha": sha, "sha7": sha[:7], "ref": ref, "dirty": dirty}


def members_of(meta: dict, root: Path) -> dict[str, str]:
    """crate name -> its directory relative to the repo root (e.g. crates/graph)."""
    out = {}
    for pkg in meta["packages"]:
        parent = Path(pkg["manifest_path"]).parent
        try:
            rel = parent.relative_to(root)
        except ValueError:
            # A fixture, or metadata from another checkout: keep the path from
            # the `crates` component on, which is how every tool names files.
            parts = parent.parts
            rel = Path(*parts[parts.index("crates"):]) if "crates" in parts else Path(parent.name)
        out[pkg["name"]] = rel.as_posix()
    return out


class Attributor:
    """Map a workspace-relative path to the crate whose directory contains it."""

    def __init__(self, members: dict[str, str], root: Path):
        self.root = root
        # Longest directory first so a nested crate wins over its parent.
        self.dirs = sorted(((d, n) for n, d in members.items()), key=lambda x: -len(x[0]))

    def relative(self, path: str) -> str:
        p = Path(path)
        if p.is_absolute():
            try:
                p = p.relative_to(self.root)
            except ValueError:
                # Another checkout's absolute path (llvm-cov reports them that
                # way): keep the path from the `crates` component on.
                parts = p.parts
                p = Path(*parts[parts.index("crates"):]) if "crates" in parts else p
        return p.as_posix()

    def crate(self, path: str) -> str | None:
        rel = self.relative(path)
        for directory, name in self.dirs:
            if rel == directory or rel.startswith(directory + "/"):
                return name
        return None


def is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in ("tests", "benches", "fuzz", "examples") for p in parts[:-1]) or rel.endswith(
        "build.rs"
    )


# --------------------------------------------------------------- collectors


def collect_clippy(path: Path | None, strict: list[str], attr: Attributor):
    """Per-crate lint counts, the hit list, and per-file counts for hotspots."""
    if path is None:
        return None, [], {}
    strict_set = set(strict)
    complexity_set = set(COMPLEXITY_LINTS)
    per_crate: dict[str, dict] = defaultdict(
        lambda: {
            "workspace_lints": 0,
            "strict": {lint: 0 for lint in strict},
            "complexity": {lint.split("::", 1)[1]: 0 for lint in COMPLEXITY_LINTS},
        }
    )
    per_file: dict[str, Counter] = defaultdict(Counter)
    hits = []
    seen = set()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if '"compiler-message"' not in raw:
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if msg.get("reason") != "compiler-message":
                continue
            body = msg.get("message", {})
            if body.get("level") not in ("warning", "error"):
                continue
            code = (body.get("code") or {}).get("code") or ""
            if not code:
                continue
            span = next((s for s in body.get("spans", []) if s.get("is_primary")), None)
            if span is None or span.get("line_start") is None:
                continue
            rel = attr.relative(span["file_name"])
            key = (rel, span["line_start"], code)
            if key in seen:
                continue
            seen.add(key)
            crate = attr.crate(rel) or "<workspace>"
            bucket = per_crate[crate]
            if code in strict_set:
                bucket["strict"][code] += 1
                per_file[rel]["strict"] += 1
            elif code in complexity_set:
                bucket["complexity"][code.split("::", 1)[1]] += 1
                per_file[rel]["complexity"] += 1
            else:
                bucket["workspace_lints"] += 1
            hits.append({"path": rel, "line": span["line_start"], "code": code})
    hits.sort(key=lambda h: (h["path"], h["line"], h["code"]))
    return per_crate, hits, per_file


def collect_coverage(path: Path | None, attr: Attributor):
    """Per-crate line/function/region totals and per-file uncovered lines."""
    doc = read_json(path)
    if doc is None:
        return None, None, {}
    data = doc["data"][0]
    per_crate: dict[str, dict] = defaultdict(
        lambda: {k: {"covered": 0, "total": 0} for k in ("lines", "functions", "regions")}
    )
    uncovered: dict[str, int] = {}
    for f in data.get("files", []):
        rel = attr.relative(f["filename"])
        crate = attr.crate(rel)
        if crate is None or is_test_path(rel):
            continue
        s = f["summary"]
        for k in ("lines", "functions", "regions"):
            per_crate[crate][k]["covered"] += s[k]["covered"]
            per_crate[crate][k]["total"] += s[k]["count"]
        uncovered[rel] = s["lines"]["count"] - s["lines"]["covered"]
    for crate in per_crate.values():
        for k in crate.values():
            k["pct"] = pct(k["covered"], k["total"])
    totals = data.get("totals", {})
    workspace = {
        k: {
            "covered": totals[k]["covered"],
            "total": totals[k]["count"],
            "pct": pct(totals[k]["covered"], totals[k]["count"]),
        }
        for k in ("lines", "functions", "regions")
        if k in totals
    }
    return per_crate, workspace, uncovered


def collect_size(path: Path | None, attr: Attributor):
    doc = read_json(path)
    if doc is None:
        return None
    per_crate: dict[str, dict] = defaultdict(
        lambda: {"files": 0, "code": 0, "comments": 0, "blanks": 0, "test_code": 0}
    )
    for report in doc.get("Rust", {}).get("reports", []):
        rel = attr.relative(report["name"])
        crate = attr.crate(rel)
        if crate is None:
            continue
        stats = report["stats"]
        bucket = per_crate[crate]
        bucket["files"] += 1
        bucket["code"] += stats["code"]
        bucket["comments"] += stats["comments"]
        bucket["blanks"] += stats["blanks"]
        if is_test_path(rel):
            bucket["test_code"] += stats["code"]
    return per_crate


DOT_EDGE_RE = re.compile(r'^\s*"([^"]+)"\s*->\s*"([^"]+)"\s*\[label="uses"')


def module_cycles(dot_paths: list[Path]) -> list[list[str]]:
    """Strongly connected components of size > 1 in the module `uses` graph.

    The DOT files come from `cargo modules dependencies` with functions,
    traits and types filtered out, so every node is a module and every
    `uses` edge is one module reaching into another. A crate's targets share
    the graph: a cycle through a binary-only module is still a cycle. Edges
    touching the crate root or a test module are left out (see `structural`).
    """
    def structural(node: str) -> bool:
        # The crate root re-exports its children and the children reach back
        # with `use crate::`; that pair is how a Rust crate is laid out, not a
        # cycle worth a finding. Test modules reach anywhere by design.
        if "::" not in node:
            return True
        segments = node.split("::")[1:]
        return any(
            seg == "tests" or seg.endswith("_tests") or seg in ("test_util", "test_harness")
            for seg in segments
        )

    edges: dict[str, set[str]] = defaultdict(set)
    for dot in dot_paths:
        if not dot.is_file():
            continue
        for line in dot.read_text(encoding="utf-8", errors="replace").splitlines():
            m = DOT_EDGE_RE.match(line)
            if not m or m.group(1) == m.group(2):
                continue
            if structural(m.group(1)) or structural(m.group(2)):
                continue
            edges[m.group(1)].add(m.group(2))
            edges.setdefault(m.group(2), set())
    # Tarjan, iterative: module graphs are small, recursion limits are not.
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    cycles: list[list[str]] = []
    counter = 0
    for root in sorted(edges):
        if root in index:
            continue
        work = [(root, iter(sorted(edges[root])))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for nxt in it:
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(sorted(edges[nxt]))))
                    advanced = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    top = stack.pop()
                    on_stack.discard(top)
                    component.append(top)
                    if top == node:
                        break
                if len(component) > 1:
                    cycles.append(sorted(component))
    return sorted(cycles)


def collect_modules(path: Path | None):
    """run.sh writes one JSON object per crate: {crate, targets: [{target, dot, orphans, error}]}."""
    if path is None:
        return None
    out = {}
    for line in read_lines(path):
        rec = json.loads(line)
        targets = rec.get("targets", [])
        dots = [Path(t["dot"]) for t in targets if t.get("dot")]
        orphan_sets = [set(t.get("orphans") or []) for t in targets]
        orphans = sorted(set.intersection(*orphan_sets)) if orphan_sets else []
        errors = [f"{t['target']}: {t['error']}" for t in targets if t.get("error")]
        cycles = module_cycles(dots)
        out[rec["crate"]] = {
            "acyclic": not cycles if not errors else None,
            "cycles": cycles,
            "orphans": len(orphans),
            "orphan_files": orphans,
            "error": "; ".join(errors) or None,
        }
    return out


UNUSED_RE = re.compile(r"unused (?:workspace )?dependency `([^`]+)`")


def collect_shear(path: Path | None, attr: Attributor):
    doc = read_json(path)
    if doc is None:
        return None, None
    per_crate: dict[str, list] = defaultdict(list)
    workspace_unused = []
    for finding in doc.get("findings", []):
        m = UNUSED_RE.search(finding.get("message", ""))
        if not m:
            continue
        if finding["code"] == "shear/unused_workspace_dependency":
            workspace_unused.append(m.group(1))
            continue
        if finding["code"] != "shear/unused_dependency":
            continue
        crate = attr.crate(finding["file"])
        if crate is not None:
            per_crate[crate].append(m.group(1))
    return per_crate, sorted(workspace_unused)


# ------------------------------------------------------------ experimental
# Recorded, never read by a gate (QM-005): `metric()` has no entry for these
# blocks and `evaluate_gates` reads nothing but `metric()`. Neither tool
# installed in the sandbox this was written in, so the shapes come from the
# tools' published docs (testdata/SHAPES.md) and every lookup is a `.get`.


def collect_rustqual(directory: Path | None):
    """One `<crate>.json` per crate from `rustqual <crate>/src --format json`,
    or `{"error": ...}` where run.sh recorded that the tool could not run.

    Fields per book/reference-output-formats.md at
    https://github.com/SaschaOnTour/rustqual: `summary` is documented key by
    key; `coupling.cycles` (CP-001), `coupling.sdp_violations` (CP-002),
    `dead_code` and `duplicates` are documented as arrays whose entries are
    elided, so only their lengths are read.
    """
    if directory is None:
        return None
    out = {}
    for path in sorted(directory.glob("*.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or "summary" not in doc:
            out[path.stem] = {"error": doc.get("error", "no summary in output") if isinstance(doc, dict) else "not an object"}
            continue
        summary = doc.get("summary") or {}
        coupling = doc.get("coupling") or {}
        # field per https://github.com/SaschaOnTour/rustqual/blob/main/book/coupling-quality.md
        # (the prose defines a module's instability; the JSON key is
        # unverified against a run, so a different name yields null)
        instabilities = [
            m["instability"]
            for m in coupling.get("modules") or []
            if isinstance(m, dict) and isinstance(m.get("instability"), (int, float))
        ]
        out[path.stem] = {
            "score": summary.get("quality_score"),
            "iosp_score": summary.get("iosp_score"),
            "iosp_violations": summary.get("violations"),
            "complexity_findings": summary.get("complexity_warnings"),
            "dead_code": len(doc.get("dead_code") or []),
            "duplicates": len(doc.get("duplicates") or []),
            "cycles": len(coupling.get("cycles") or []),
            "sdp_violations": len(coupling.get("sdp_violations") or []),
            "max_instability": max(instabilities) if instabilities else None,
            "dimension_scores": summary.get("dimension_scores"),
        }
    return out


def collect_anatomy(path: Path | None):
    """`cargo anatomy` over the workspace: `crates[].metrics` per
    docs/output-schema.md at https://github.com/cutsea110/cargo-anatomy
    (I = Ce / (Ce + Ca), D = |A + I - 1| / sqrt 2, H = (R + 1) / N)."""
    doc = read_json(path)
    if doc is None:
        return None
    out = {}
    for entry in doc.get("crates") or []:
        m = entry.get("metrics") or {}
        out[entry.get("crate_name")] = {
            "ca": m.get("ca"),
            "ce": m.get("ce"),
            "instability": m.get("i"),
            "abstractness": m.get("a"),
            "distance": m.get("d"),
            "cohesion": m.get("h"),
        }
    return out


def _is_number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def rustqual_totals(crates: dict) -> dict:
    """The workspace view of the per-crate rustqual blocks: the score weighted
    by lines of code (a small crate at 1.0 must not offset a large one at
    0.5), the plain mean beside it, and the finding counts summed."""
    blocks = {
        n: c["experimental"]["rustqual"]
        for n, c in crates.items()
        if c["experimental"] and c["experimental"]["rustqual"]
    }
    scored = {n: b for n, b in blocks.items() if _is_number(b.get("score"))}
    weights = {n: ((crates[n]["size"] or {}).get("code") or 0) for n in scored}
    weighted = None
    if sum(weights.values()) > 0:
        weighted = round(sum(b["score"] * weights[n] for n, b in scored.items()) / sum(weights.values()), 4)
    counts = ("iosp_violations", "complexity_findings", "dead_code", "duplicates", "cycles", "sdp_violations")
    return {
        "errors": sorted(n for n, b in blocks.items() if "error" in b),
        "score_loc_weighted": weighted,
        "score_mean": round(sum(b["score"] for b in scored.values()) / len(scored), 4) if scored else None,
        **{k: sum(b.get(k) or 0 for b in scored.values()) for k in counts},
    }


def anatomy_totals(crates: dict) -> dict:
    blocks = {
        n: c["experimental"]["anatomy"]
        for n, c in crates.items()
        if c["experimental"] and c["experimental"]["anatomy"]
    }
    distances = [b["distance"] for b in blocks.values() if _is_number(b.get("distance"))]
    # D > 0.5 is far from the main sequence; A + I < 1 puts the crate on the
    # concrete-and-stable side of it, which is the zone of pain (the other
    # side is the zone of uselessness). The simplest flag until the history
    # says where the line belongs.
    pain = sorted(
        n
        for n, b in blocks.items()
        if _is_number(b.get("distance"))
        and b["distance"] > 0.5
        and _is_number(b.get("abstractness"))
        and _is_number(b.get("instability"))
        and b["abstractness"] + b["instability"] < 1
    )
    return {
        "mean_distance": round(sum(distances) / len(distances), 4) if distances else None,
        "crates_in_zone_of_pain": pain,
    }
MUTANT_SUMMARY = {"CaughtMutant": "caught", "MissedMutant": "missed", "Timeout": "timeout", "Unviable": "unviable"}


def collect_mutants(path: Path | None, attr: Attributor):
    """Per-crate outcome counts from cargo-mutants' outcomes.json.

    One entry per scenario; the baseline is the one whose `scenario` is the
    string "Baseline", every other carries `scenario.Mutant` with the file
    the mutant lives in. The mutant is attributed by that path, falling back
    to the package cargo-mutants names. An unviable mutant never compiled,
    so it says nothing about the tests: it is counted but kept out of the
    score (metrics/README.md, "Test quality").
    """
    doc = read_json(path)
    if doc is None:
        return None
    per_crate: dict[str, Counter] = defaultdict(Counter)
    for outcome in doc.get("outcomes", []):
        scenario = outcome.get("scenario")
        if not isinstance(scenario, dict) or "Mutant" not in scenario:
            continue
        kind = MUTANT_SUMMARY.get(outcome.get("summary"))
        if kind is None:
            continue
        mutant = scenario["Mutant"]
        crate = attr.crate(mutant.get("file", "")) or mutant.get("package") or "<workspace>"
        per_crate[crate][kind] += 1
    return {name: mutants_block(counts) for name, counts in per_crate.items()}


def mutants_block(counts: Counter) -> dict:
    caught, missed, timeout = counts["caught"], counts["missed"], counts["timeout"]
    tested = caught + missed + timeout
    return {
        "tested": tested,
        "caught": caught,
        "missed": missed,
        "timeout": timeout,
        "unviable": counts["unviable"],
        # No tested mutant (every one unviable) measures nothing: null, not 0 %.
        "score_pct": pct(caught, tested) if tested else None,
    }


def collect_crap(path: Path | None, attr: Attributor, threshold: float):
    """Per-crate function counts from cargo-crap's `--format json` report.

    `entries` is one row per function with `file` (absolute), `crap` and
    `crate`. Attribution goes by path like every other collector, so a
    function lands where the coverage and clippy numbers for its file land.
    Over the threshold is strictly greater: the threshold itself is the last
    acceptable score, as cargo-crap reads it.
    """
    doc = read_json(path)
    if doc is None:
        return None
    per_crate: dict[str, dict] = defaultdict(lambda: {"functions": 0, "over_threshold": 0, "max": 0.0})
    for entry in doc.get("entries", []):
        rel = attr.relative(entry["file"])
        crate = attr.crate(rel) or entry.get("crate")
        if crate is None or is_test_path(rel):
            continue
        score = float(entry["crap"])
        bucket = per_crate[crate]
        bucket["functions"] += 1
        if score > threshold:
            bucket["over_threshold"] += 1
        bucket["max"] = max(bucket["max"], round(score, 2))
    return per_crate


def churn(window_days: int) -> Counter:
    """Commits touching each Rust file in the window, from the current history."""
    out = subprocess.run(
        ["git", "log", f"--since={window_days}.days", "--format=", "--name-only", "--", "*.rs"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return Counter(l.strip() for l in out.splitlines() if l.strip())


def hotspots(
    window_days: int,
    top: int,
    per_file_clippy: dict[str, Counter],
    uncovered: dict[str, int],
    coverage_measured: bool,
    attr: Attributor,
    root: Path,
) -> dict:
    """Rank files by churn x findings (QM-018).

    findings = complexity hits + strict hits + uncovered lines / 100. Each
    component is monotone, so a file that is worse on every axis never ranks
    below one that is better on every axis. Files outside a crate, test
    sources and files no longer in the tree are left out.

    With no findings source at all (static mode: no clippy, no coverage) the
    ranking is churn alone and says so: the hot files are still the ones a
    refactor should look at first, only unweighted.
    """
    findings_included = bool(per_file_clippy) or coverage_measured
    changes = churn(window_days)
    files = set(changes) | set(per_file_clippy) | set(uncovered)
    rows = []
    for rel in files:
        if attr.crate(rel) is None or is_test_path(rel) or not (root / rel).is_file():
            continue
        c = changes.get(rel, 0)
        complexity = per_file_clippy.get(rel, Counter()).get("complexity", 0)
        strict = per_file_clippy.get(rel, Counter()).get("strict", 0)
        unc = uncovered.get(rel, 0) if coverage_measured else None
        findings = complexity + strict + ((unc or 0) / 100.0)
        score = round(c * findings, 3) if findings_included else float(c)
        if score <= 0:
            continue
        rows.append(
            {
                "path": rel,
                "crate": attr.crate(rel),
                "churn": c,
                "complexity": complexity,
                "strict": strict,
                "uncovered_lines": unc,
                "score": score,
            }
        )
    rows.sort(key=lambda r: (-r["score"], r["path"]))
    return {
        "window_days": window_days,
        "coverage_included": coverage_measured,
        "findings_included": findings_included,
        "candidates": len(rows),
        "files": rows[:top],
    }


# ------------------------------------------------------------------- gates


def pct(covered: int, total: int) -> float:
    return round(100.0 * covered / total, 2) if total else 0.0


def metric(snapshot: dict, name: str, crate: str | None = None):
    """Resolve a gate name to a value; None when the block was not measured."""
    ws = snapshot["crates"][crate] if crate else snapshot["workspace"]
    layers = snapshot["layers"]
    table = {
        "coverage.lines_pct": lambda: (ws["coverage"] or {}).get("lines", {}).get("pct"),
        "clippy.workspace_lints": lambda: (ws["clippy"] or {}).get("workspace_lints"),
        "clippy.strict.total": lambda: (ws["clippy"] or {}).get("strict_total"),
        "clippy.complexity.total": lambda: (ws["clippy"] or {}).get("complexity_total"),
        "modules.cycles": lambda: (ws["modules"] or {}).get("cycles"),
        "modules.orphans": lambda: (ws["modules"] or {}).get("orphans"),
        "deps.unused.total": lambda: (ws["deps"] or {}).get("unused_total"),
        "size.code": lambda: (ws["size"] or {}).get("code"),
        "mutants.score_pct": lambda: (ws["mutants"] or {}).get("score_pct"),
        "crap.over_threshold": lambda: (ws["crap"] or {}).get("over_threshold"),
        "layers.unexcepted": lambda: layers["unexcepted"],
        "layers.unassigned": lambda: len(layers["unassigned"]),
        "layers.exceptions": lambda: layers["exceptions"],
    }
    if name not in table:
        raise SystemExit(f"thresholds: unknown gate {name!r}")
    try:
        return table[name]()
    except (KeyError, TypeError):
        return None


def evaluate_gates(snapshot: dict, thresholds: dict, baseline: dict | None) -> dict:
    gates = {}

    def absolute(kind: str, name: str, limit, crate=None):
        value = metric(snapshot, name, crate)
        # One metric may carry a floor and a ratchet; the kind keeps the keys apart.
        key = f"{kind}:crates.{crate}.{name}" if crate else f"{kind}:{name}"
        if value is None:
            result = "not_evaluated"
        elif kind == "floor":
            result = "pass" if value >= limit else "fail"
        else:
            result = "pass" if value <= limit else "fail"
        gates[key] = {"kind": kind, "value": value, "threshold": limit, "result": result}

    for name, limit in thresholds.get("floors", {}).items():
        absolute("floor", name, limit)
    for name, limit in thresholds.get("ceilings", {}).items():
        absolute("ceiling", name, limit)
    for crate, table in thresholds.get("crates", {}).items():
        if crate not in snapshot["crates"]:
            continue
        for name, limit in table.get("floors", {}).items():
            absolute("floor", name, limit, crate)
        for name, limit in table.get("ceilings", {}).items():
            absolute("ceiling", name, limit, crate)

    for name, spec in thresholds.get("ratchet", {}).items():
        value = metric(snapshot, name)
        base_value = metric(baseline, name) if baseline else None
        gate = {
            "kind": "ratchet",
            "value": value,
            "baseline": base_value,
            "baseline_sha7": (baseline or {}).get("git", {}).get("sha7"),
            "direction": spec["direction"],
            "tolerance": spec.get("tolerance", 0),
        }
        if value is None or base_value is None:
            gate["result"] = "not_evaluated"
        else:
            worse = value - base_value if spec["direction"] == "down" else base_value - value
            if worse <= 0:
                gate["result"] = "pass"
            elif worse <= spec.get("tolerance", 0):
                gate["result"] = "warn"
            else:
                gate["result"] = "fail"
        gates[f"ratchet:{name}"] = gate
    return gates


def verdict(gates: dict) -> str:
    worst = max((RANK[g["result"]] for g in gates.values()), default=0)
    return ("pass", "warn", "fail")[worst]


# ----------------------------------------------------------------- summary


def _fmt(value) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def summary_markdown(snapshot: dict) -> str:
    """The snapshot as a page of Markdown for a run's step summary.

    What a person opens the run for: the verdict, every gate, the workspace
    totals, the module cycles and the top hotspots. The same numbers are in
    snapshot.json; this is the glance, not the record.
    """
    ws = snapshot["workspace"]
    run = snapshot["run"]
    lines = [
        f"## Quality snapshot `{snapshot['git']['sha7']}` ({run['mode']}, {run['host']['os']}/{run['host']['arch']})",
        "",
        f"Verdict: **{snapshot['verdict']}**",
        "",
        "### Gates",
        "",
        "| Gate | Value | Baseline | Threshold | Result |",
        "|---|---|---|---|---|",
    ]
    for name, gate in sorted(snapshot["gates"].items()):
        if gate["kind"] == "ratchet":
            threshold = f"{gate['direction']}, tolerance {_fmt(gate['tolerance'])}"
            baseline = _fmt(gate.get("baseline"))
        else:
            threshold = ("≥ " if gate["kind"] == "floor" else "≤ ") + _fmt(gate["threshold"])
            baseline = "n/a"
        lines.append(f"| `{name}` | {_fmt(gate['value'])} | {baseline} | {threshold} | {gate['result']} |")

    lines += ["", "### Workspace", "", "| Metric | Value |", "|---|---|"]
    rows = []
    if ws.get("size"):
        rows.append(("Code lines", ws["size"]["code"]))
        rows.append(("Test code lines", ws["size"]["test_code"]))
    if ws.get("clippy"):
        rows.append(("Strict lint hits", ws["clippy"]["strict_total"]))
        rows.append(("Complexity lint hits", ws["clippy"]["complexity_total"]))
        rows.append(("Workspace lint hits", ws["clippy"]["workspace_lints"]))
    if ws.get("coverage"):
        rows.append(("Line coverage %", ws["coverage"].get("lines", {}).get("pct")))
        if ws["coverage"].get("test_failures"):
            rows.append(("Tests failing under coverage", ws["coverage"]["test_failures"]))
    if ws.get("modules"):
        rows.append(("Module cycles", ws["modules"]["cycles"]))
        rows.append(("Orphan modules", ws["modules"]["orphans"]))
    if ws.get("deps"):
        rows.append(("Unused dependencies", ws["deps"]["unused_total"]))
    if ws.get("mutants") and "score_pct" in ws["mutants"]:
        rows.append((f"Mutation score % ({ws['mutants'].get('scope')})", ws["mutants"]["score_pct"]))
    if ws.get("crap"):
        rows.append((f"Functions with CRAP > {_fmt(ws['crap']['threshold'])}", ws["crap"]["over_threshold"]))
    layers = snapshot["layers"]
    rows.append(("Layer edges excepted / forbidden", f"{layers['exceptions']} / {layers['unexcepted']}"))
    for label, value in rows:
        lines.append(f"| {label} | {_fmt(value)} |")

    promotable = ws.get("strict_promotable")
    if promotable:
        lines += ["", "### Promotable strict lints", ""] + [f"- `{l}`" for l in promotable]

    cycles = [
        (name, cycle)
        for name, crate in sorted(snapshot["crates"].items())
        if crate.get("modules")
        for cycle in crate["modules"].get("cycles") or []
    ]
    if cycles:
        lines += ["", "### Module cycles", ""]
        for name, cycle in cycles:
            lines.append(f"- `{name}`: " + ", ".join(f"`{m}`" for m in cycle))

    hot = snapshot.get("hotspots")
    if hot and hot.get("files"):
        lines += [
            "",
            f"### Hotspots (top {len(hot['files'])} of {hot['candidates']}, {hot['window_days']}-day window"
            + ("" if hot.get("findings_included") else "; churn only")
            + ("" if hot.get("coverage_included") else "; no coverage term")
            + ")",
            "",
            "| File | Churn | Complexity | Strict | Uncovered | Score |",
            "|---|---|---|---|---|---|",
        ]
        for f in hot["files"]:
            lines.append(
                f"| `{f['path']}` | {f['churn']} | {f['complexity']} | {f['strict']} | {_fmt(f['uncovered_lines'])} | {_fmt(f['score'])} |"
            )

    failed_tests = (ws.get("coverage") or {}).get("failed_tests") or []
    if failed_tests:
        lines += ["", "### Tests that failed under the coverage build", ""] + [f"- `{t}`" for t in failed_tests]
    if run["not_measured"]:
        lines += ["", "### Not measured", ""] + [f"- {k}: {v}" for k, v in sorted(run["not_measured"].items())]
    return "\n".join(lines) + "\n"


# -------------------------------------------------------------------- main


def parse_kv(items: list[str]) -> dict[str, str]:
    out = {}
    for item in items:
        key, _, value = item.partition("=")
        out[key] = value
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--mode", choices=schema_mod.MODES, required=True)
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--metadata", type=Path, required=True)
    ap.add_argument("--rules", type=Path, default=Path("metrics/layers.toml"))
    ap.add_argument("--thresholds", type=Path, default=Path("metrics/thresholds.toml"))
    ap.add_argument("--baseline", type=Path, help="base ref's snapshot, for the ratchets")
    ap.add_argument("--clippy", type=Path)
    ap.add_argument("--clippy-complete", action="store_true", help="clippy covered the whole workspace")
    ap.add_argument("--strict-lints", type=Path, help="one lint name per line")
    ap.add_argument("--coverage", type=Path)
    ap.add_argument("--coverage-tests", type=Path, help="JSON: tests, failures, failed[] from nextest's junit")
    ap.add_argument("--tokei", type=Path)
    ap.add_argument("--modules", type=Path)
    ap.add_argument("--shear", type=Path)
    ap.add_argument("--rustqual-dir", type=Path, help="directory of <crate>.json from rustqual --format json")
    ap.add_argument("--anatomy", type=Path, help="cargo anatomy output")
    ap.add_argument("--mutants", type=Path, help="cargo-mutants outcomes.json")
    ap.add_argument(
        "--mutants-scope",
        choices=("in-diff", "since", "shard", "workspace"),
        default="workspace",
        help="what the mutants run covered (QM-017)",
    )
    ap.add_argument("--mutants-shard", metavar="K/N", help="the shard a nightly run tested")
    ap.add_argument("--mutants-since", metavar="SHA7", help="the reference commit of a `since` run")
    ap.add_argument(
        "--mutants-budget-exhausted", action="store_true", help="the run stopped at its time budget"
    )
    ap.add_argument(
        "--mutants-untracked", type=Path, help="one untracked *.rs path per line: outside the mutation scope"
    )
    ap.add_argument("--crap", type=Path, help="cargo-crap --format json report")
    ap.add_argument("--tools", type=Path, help="JSON: tool name -> version")
    ap.add_argument("--toolchain", type=Path, help="JSON: channel, rustc, cargo")
    ap.add_argument("--scope", type=Path, help="one crate name per line that compiling collectors covered")
    ap.add_argument("--not-measured", action="append", default=[], metavar="COLLECTOR=REASON")
    ap.add_argument("--excluded", action="append", default=[], metavar="CRATE=REASON")
    ap.add_argument("--duration", action="append", default=[], metavar="STEP=SECONDS")
    ap.add_argument("--started", help="ISO-8601 start time, written to meta.json only")
    ap.add_argument("--no-hotspots", action="store_true", help="skip the git history walk")
    ap.add_argument(
        "--summary",
        action="store_true",
        help="write summary.md beside the snapshot and append it to $GITHUB_STEP_SUMMARY when set",
    )
    args = ap.parse_args(argv)

    root = args.root.resolve()
    meta = read_json(args.metadata)
    rules = layers_mod.load_rules(args.rules)
    with args.thresholds.open("rb") as fh:
        thresholds = tomllib.load(fh)
    baseline = read_json(args.baseline)
    members = members_of(meta, root)
    attr = Attributor(members, root)
    not_measured = parse_kv(args.not_measured)
    strict = read_lines(args.strict_lints)

    clippy, hits, per_file_clippy = collect_clippy(args.clippy, strict, attr)
    coverage, coverage_ws, uncovered = collect_coverage(args.coverage, attr)
    size = collect_size(args.tokei, attr)
    modules = collect_modules(args.modules)
    shear, workspace_unused = collect_shear(args.shear, attr)
    rustqual = collect_rustqual(args.rustqual_dir)
    anatomy = collect_anatomy(args.anatomy)
    mutants = collect_mutants(args.mutants, attr)
    crap_threshold = float(thresholds.get("crap", {}).get("threshold", 30))
    crap = collect_crap(args.crap, attr, crap_threshold)
    layer_result = layers_mod.analyse(meta, rules)
    layer_of = {c: l for l, cs in rules["layers"].items() for c in cs}
    scope = read_lines(args.scope) or sorted(members)

    crates = {}
    for name in sorted(members):
        crate: dict = {"layer": layer_of.get(name)}
        pkg = next(p for p in meta["packages"] if p["name"] == name)
        internal = sorted(
            d["name"] for d in pkg["dependencies"] if d["name"] in members and d.get("kind") is None
        )
        crate["size"] = size.get(name, collect_size.__defaults__ and None) if size is not None else None
        if size is not None and crate["size"] is None:
            crate["size"] = {"files": 0, "code": 0, "comments": 0, "blanks": 0, "test_code": 0}
        if clippy is not None and name in scope:
            bucket = clippy.get(name) or {
                "workspace_lints": 0,
                "strict": {lint: 0 for lint in strict},
                "complexity": {lint.split("::", 1)[1]: 0 for lint in COMPLEXITY_LINTS},
            }
            bucket = dict(bucket)
            bucket["strict_total"] = sum(bucket["strict"].values())
            bucket["complexity_total"] = sum(bucket["complexity"].values())
            crate["clippy"] = bucket
        else:
            crate["clippy"] = None
        if coverage is not None and name in scope:
            crate["coverage"] = coverage.get(name) or {
                k: {"covered": 0, "total": 0, "pct": 0.0} for k in ("lines", "functions", "regions")
            }
        else:
            crate["coverage"] = None
        crate["modules"] = modules.get(name) if modules is not None else None
        if shear is not None:
            crate["deps"] = {"internal": internal, "unused": sorted(shear.get(name, []))}
        else:
            crate["deps"] = {"internal": internal, "unused": None}
        # A crate the mutants run generated no mutants for (outside the diff,
        # or the shard) was not measured; it stays null rather than reading
        # as a perfect score.
        crate["mutants"] = mutants.get(name) if mutants is not None else None
        if crap is not None and name in scope:
            crate["crap"] = crap.get(name) or {"functions": 0, "over_threshold": 0, "max": 0.0}
        else:
            crate["crap"] = None
        # Null only when neither tool ran; a crate one tool skipped (rustqual
        # on remote-proto) keeps the other's sub-block.
        if rustqual is None and anatomy is None:
            crate["experimental"] = None
        else:
            crate["experimental"] = {
                "rustqual": rustqual.get(name) if rustqual is not None else None,
                "anatomy": anatomy.get(name) if anatomy is not None else None,
            }
        crates[name] = crate

    measured = [c for c in crates.values()]
    workspace: dict = {"crates": len(crates)}
    if size is not None:
        workspace["size"] = {
            k: sum(c["size"][k] for c in measured if c["size"]) for k in ("files", "code", "comments", "blanks", "test_code")
        }
    else:
        workspace["size"] = None
    if clippy is not None:
        strict_counts = Counter()
        complexity_counts = Counter()
        wl = 0
        for c in measured:
            if c["clippy"]:
                strict_counts.update(c["clippy"]["strict"])
                complexity_counts.update(c["clippy"]["complexity"])
                wl += c["clippy"]["workspace_lints"]
        strict_counts.update({lint: 0 for lint in strict})
        workspace["clippy"] = {
            "workspace_lints": wl,
            "strict": dict(sorted(strict_counts.items())),
            "complexity": dict(sorted(complexity_counts.items())),
            "strict_total": sum(strict_counts.values()),
            "complexity_total": sum(complexity_counts.values()),
            "scope_complete": bool(args.clippy_complete),
        }
        workspace["strict_promotable"] = (
            sorted(l for l, n in strict_counts.items() if n == 0) if args.clippy_complete else None
        )
    else:
        workspace["clippy"] = None
        workspace["strict_promotable"] = None
    workspace["coverage"] = coverage_ws
    coverage_tests = read_json(args.coverage_tests)
    if coverage_ws is not None and coverage_tests is not None:
        # Tests that failed under the instrumented build: the coverage of
        # what ran still stands, but the number is read with this beside it.
        workspace["coverage"]["tests"] = coverage_tests.get("tests")
        workspace["coverage"]["test_failures"] = coverage_tests.get("failures")
        workspace["coverage"]["failed_tests"] = coverage_tests.get("failed") or []
    if modules is not None:
        workspace["modules"] = {
            "cycles": sum(len(m.get("cycles") or []) for m in modules.values()),
            "orphans": sum(m.get("orphans") or 0 for m in modules.values()),
            "errors": sorted(k for k, m in modules.items() if m.get("error")),
        }
    else:
        workspace["modules"] = None
    if shear is not None:
        per_crate_unused = sum(len(c["deps"]["unused"]) for c in measured)
        workspace["deps"] = {
            "unused_total": per_crate_unused + len(workspace_unused),
            "unused_workspace": workspace_unused,
        }
    else:
        workspace["deps"] = None
    if rustqual is None and anatomy is None:
        workspace["experimental"] = None
    else:
        workspace["experimental"] = {
            "rustqual": rustqual_totals(crates) if rustqual is not None else None,
            "anatomy": anatomy_totals(crates) if anatomy is not None else None,
        }
    # The untracked list is recorded whenever run.sh produced one, even when
    # cargo-mutants itself did not run: a new file outside the scope is a
    # fact about the change, not about the tool (QM-017).
    untracked = read_lines(args.mutants_untracked) if args.mutants_untracked else None
    if mutants is not None:
        totals = Counter()
        for block in mutants.values():
            totals.update({k: block[k] for k in ("caught", "missed", "timeout", "unviable")})
        workspace["mutants"] = mutants_block(totals)
        workspace["mutants"]["scope"] = args.mutants_scope
        workspace["mutants"]["shard"] = args.mutants_shard
        workspace["mutants"]["since"] = args.mutants_since
        workspace["mutants"]["partial"] = bool(args.mutants_budget_exhausted)
        workspace["mutants"]["untracked_outside_scope"] = untracked or []
    elif untracked is not None:
        workspace["mutants"] = {"untracked_outside_scope": untracked}
    else:
        workspace["mutants"] = None
    if crap is not None:
        blocks = [c["crap"] for c in measured if c["crap"]]
        workspace["crap"] = {
            "functions": sum(b["functions"] for b in blocks),
            "over_threshold": sum(b["over_threshold"] for b in blocks),
            "max": max((b["max"] for b in blocks), default=0.0),
            "threshold": crap_threshold,
        }
    else:
        workspace["crap"] = None

    hotspot_cfg = thresholds.get("hotspots", {})
    if args.no_hotspots:
        hot = None
        not_measured.setdefault("hotspots", "disabled")
    else:
        hot = hotspots(
            int(hotspot_cfg.get("window_days", 90)),
            int(hotspot_cfg.get("top", 25)),
            per_file_clippy,
            uncovered,
            coverage is not None,
            attr,
            root,
        )

    tools = read_json(args.tools) or {}
    toolchain = read_json(args.toolchain) or {}
    snapshot = {
        "schema_version": schema_mod.SCHEMA_VERSION,
        "kind": "snapshot",
        "run": {
            "mode": args.mode,
            "host": {"os": platform.system().lower(), "arch": platform.machine()},
            "not_measured": dict(sorted(not_measured.items())),
        },
        "git": git_info(),
        "toolchain": toolchain,
        "tools": dict(sorted(tools.items())),
        "scope": {"crates": sorted(scope), "excluded": dict(sorted(parse_kv(args.excluded).items()))},
        "crates": crates,
        "workspace": workspace,
        "layers": layer_result,
        "hotspots": hot,
        "gates": {},
        "verdict": "pass",
    }
    snapshot["gates"] = evaluate_gates(snapshot, thresholds, baseline)
    snapshot["verdict"] = verdict(snapshot["gates"])

    problems = schema_mod.validate(snapshot)
    if problems:
        for p in problems:
            print(f"collect: schema: {p}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "snapshot.json").write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.out / "clippy-hits.json").write_text(json.dumps(hits, indent=1) + "\n", encoding="utf-8")
    durations = {k: float(v) for k, v in parse_kv(args.duration).items()}
    (args.out / "meta.json").write_text(
        json.dumps(
            {"started": args.started, "hostname": platform.node(), "durations": durations, "pid": os.getpid()},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    if args.summary:
        md = summary_markdown(snapshot)
        (args.out / "summary.md").write_text(md, encoding="utf-8")
        target = os.environ.get("GITHUB_STEP_SUMMARY")
        if target:
            try:
                with open(target, "a", encoding="utf-8") as fh:
                    fh.write(md)
            except OSError as e:
                print(f"collect: GITHUB_STEP_SUMMARY not writable ({e}); summary not appended", file=sys.stderr)

    failing = [k for k, g in snapshot["gates"].items() if g["result"] == "fail"]
    warning = [k for k, g in snapshot["gates"].items() if g["result"] == "warn"]
    print(
        f"metrics: {args.mode} snapshot {snapshot['git']['sha7']} verdict={snapshot['verdict']}"
        + (f" fail={','.join(failing)}" if failing else "")
        + (f" warn={','.join(warning)}" if warning else "")
        + (f" not_measured={','.join(sorted(not_measured))}" if not_measured else "")
    )
    return GATE_EXIT if snapshot["verdict"] == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
