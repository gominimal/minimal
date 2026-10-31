#!/usr/bin/env python3
"""Grade a head snapshot against its base ref (spec 31, QM-009 to QM-013).

`run.sh gate` and `run.sh diff` write a snapshot of the working tree with
collect.py and then hand it here. This file reads two things the change
cannot write — the thresholds at the merge-base with the base ref and the
newest snapshot on the history ref — grades the head snapshot against the
stricter of the base's thresholds and the change's own (QM-009), and writes:

  report.md     the grade a person or an agent reads; appended to
                $GITHUB_STEP_SUMMARY when that names a writable file (QM-011)
  report.json   the same content as data (QM-010)
  meta.json     wall-clock data, kept apart so report.json is byte-identical
                for an identical tree, base ref and thresholds (QM-006)

The gates are re-evaluated with collect.py's `evaluate_gates`, not a copy of
it, so a snapshot and a report never disagree on what a gate means. With no
baseline every ratchet is `not_evaluated` and the report says so.

Exit 0 when the verdict is pass or warn, 2 when it is fail, 1 for a crash or
an unreadable input. Stdlib only.
"""

from __future__ import annotations

import argparse
import copy
import datetime
import json
import os
import platform
import re
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import changed_lines  # noqa: E402
import collect  # noqa: E402
import prune  # noqa: E402

GATE_EXIT = 2
THRESHOLDS_PATH = "metrics/thresholds.toml"
HISTORY_DIR = "history"
CRATE_RE = re.compile(r"^crates/([^/]+)/")


# -------------------------------------------------------------------- git


def git(root: Path, *args: str) -> str | None:
    """stdout of a git command, or None when it fails (a missing ref, say)."""
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def resolve_base(root: Path, base_ref: str | None) -> tuple[str, str, str]:
    """(base ref, base sha, merge-base sha). Default: origin/main, then main.

    The same rule as scripts/lib/changed-lines.sh, and for the same reason: the
    remote ref cannot be behind anything the branch merged, the local one can.
    """
    candidates = [base_ref] if base_ref else ["origin/main", "main"]
    for ref in candidates:
        sha = git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
        if sha:
            merge_base = git(root, "merge-base", ref, "HEAD")
            if merge_base is None:
                raise SystemExit(f"diff: no merge-base between {ref} and HEAD")
            return ref, sha, merge_base
    raise SystemExit(f"diff: none of {candidates} names a commit; pass --base-ref")


def thresholds_at(root: Path, merge_base: str, head_path: Path) -> tuple[dict, str]:
    """The thresholds at the merge-base, else the head's copy (and which one)."""
    text = git(root, "show", f"{merge_base}:{THRESHOLDS_PATH}")
    if text is not None:
        return tomllib.loads(text), f"the stricter of `{THRESHOLDS_PATH}` at the merge-base and at head"
    # The file did not exist at the base yet (the branch introduces it), so
    # the only copy there is the change's own.
    with head_path.open("rb") as fh:
        return tomllib.load(fh), f"head's `{THRESHOLDS_PATH}` (the file is not present at the merge-base)"


def load_baseline(root: Path, history_ref: str) -> tuple[dict | None, str | None, str]:
    """The newest snapshot on the history ref: (document, file name, note)."""
    listing = git(root, "ls-tree", "--name-only", f"{history_ref}:{HISTORY_DIR}")
    if listing is None:
        return None, None, f"`{history_ref}` has no `{HISTORY_DIR}/` directory or does not exist"
    names = sorted(n for n in listing.splitlines() if n.endswith(".json"))
    if not names:
        return None, None, f"`{history_ref}:{HISTORY_DIR}/` holds no snapshot"
    # Two snapshots of one day (a dispatch and the nightly) are ordered by
    # their commits, not by the sha7 in the name.
    name = prune.newest(names, lambda sha: prune.commit_time(sha, root))
    text = git(root, "show", f"{history_ref}:{HISTORY_DIR}/{name}")
    if text is None:
        return None, name, f"`{history_ref}:{HISTORY_DIR}/{name}` could not be read"
    try:
        return json.loads(text), name, ""
    except json.JSONDecodeError as e:
        return None, name, f"`{name}` is not JSON: {e}"


def age_commits(root: Path, sha: str | None) -> int | None:
    """Commits on HEAD since the baseline's commit; None when it is unknown here."""
    if not sha:
        return None
    count = git(root, "rev-list", "--count", f"{sha}..HEAD")
    return int(count) if count is not None and count.isdigit() else None


def repo_slug(root: Path) -> str | None:
    """owner/name out of the origin URL, whatever its scheme."""
    url = git(root, "remote", "get-url", "origin")
    if not url:
        return None
    path = url.rstrip("/").removesuffix(".git").replace(":", "/")
    parts = [p for p in path.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else None


# ------------------------------------------------------------- thresholds


def _stricter_table(base: dict, head: dict, pick) -> tuple[dict, dict[str, str]]:
    """Union of two gate tables, each entry the stricter value and its source."""
    out, source = {}, {}
    for name in sorted(set(base) | set(head)):
        if name in base and name in head:
            value = pick(base[name], head[name])
            source[name] = "both" if base[name] == head[name] else ("base" if value == base[name] else "head")
        elif name in base:
            value, source[name] = base[name], "base"
        else:
            value, source[name] = head[name], "head"
        out[name] = value
    return out, source


def _stricter_ratchet(base: dict, head: dict):
    # Direction is a property of the metric, not a bar; the base's reading
    # wins when they disagree, because the base is what review approved.
    return {
        "direction": base.get("direction", head.get("direction")),
        "tolerance": min(base.get("tolerance", 0), head.get("tolerance", 0)),
    }


def stricter(base: dict, head: dict) -> tuple[dict, dict[str, str]]:
    """The effective thresholds: per gate, the stricter of base and head (QM-009).

    Floors take the max, ceilings and ratchet tolerances the min; a gate only
    one side declares is kept. So a change can tighten the bar it is graded by
    and never loosen it. Returns the thresholds and `gate key -> source`
    ("base", "head" or "both").
    """
    out = dict(head)
    sources: dict[str, str] = {}
    out["floors"], src = _stricter_table(base.get("floors", {}), head.get("floors", {}), max)
    sources.update({f"floor:{k}": v for k, v in src.items()})
    out["ceilings"], src = _stricter_table(base.get("ceilings", {}), head.get("ceilings", {}), min)
    sources.update({f"ceiling:{k}": v for k, v in src.items()})
    out["ratchet"], src = _stricter_table(
        base.get("ratchet", {}), head.get("ratchet", {}), _stricter_ratchet
    )
    sources.update({f"ratchet:{k}": v for k, v in src.items()})
    crates = {}
    for crate in sorted(set(base.get("crates", {})) | set(head.get("crates", {}))):
        b, h = base.get("crates", {}).get(crate, {}), head.get("crates", {}).get(crate, {})
        table = {}
        table["floors"], src = _stricter_table(b.get("floors", {}), h.get("floors", {}), max)
        sources.update({f"floor:crates.{crate}.{k}": v for k, v in src.items()})
        table["ceilings"], src = _stricter_table(b.get("ceilings", {}), h.get("ceilings", {}), min)
        sources.update({f"ceiling:crates.{crate}.{k}": v for k, v in src.items()})
        crates[crate] = table
    out["crates"] = crates
    return out, sources


def scoped_baseline(baseline: dict | None, snapshot: dict) -> tuple[dict | None, bool]:
    """Compare like with like when head's compiling collectors covered a subset.

    In diff mode clippy (and coverage) run over the changed crates only, so
    the head's workspace totals are sums over that scope. Against the
    baseline's whole-workspace totals every ratchet would read as an
    improvement. The baseline's totals are therefore re-summed over the same
    crates before the ratchets see them.
    """
    clippy = snapshot["workspace"].get("clippy")
    if baseline is None or clippy is None or clippy.get("scope_complete", True):
        return baseline, False
    scope = set(snapshot["scope"]["crates"])
    projected = copy.deepcopy(baseline)
    crates = [c for name, c in projected.get("crates", {}).items() if name in scope]
    if projected["workspace"].get("clippy") is not None:
        blocks = [c["clippy"] for c in crates if c.get("clippy")]
        for key in ("strict_total", "complexity_total", "workspace_lints"):
            projected["workspace"]["clippy"][key] = sum(b.get(key, 0) for b in blocks)
    if projected["workspace"].get("coverage") is not None and snapshot["workspace"].get("coverage"):
        lines = [c["coverage"]["lines"] for c in crates if c.get("coverage")]
        covered = sum(l["covered"] for l in lines)
        total = sum(l["total"] for l in lines)
        projected["workspace"]["coverage"]["lines"] = {
            "covered": covered,
            "total": total,
            "pct": collect.pct(covered, total),
        }
    return projected, True


# ----------------------------------------------------------------- report


def crate_of(path: str) -> str | None:
    m = CRATE_RE.match(path)
    return m.group(1) if m else None


def fmt(value) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:g}"
    return str(value)


def delta(value, base) -> str:
    if value is None or base is None:
        return fmt(value)
    d = value - base
    if d == 0:
        return fmt(value)
    return f"{fmt(value)} ({'+' if d > 0 else ''}{fmt(round(d, 2))})"


def threshold_text(gate: dict) -> str:
    kind = gate["kind"]
    if kind == "floor":
        text = f">= {fmt(gate['threshold'])}"
    elif kind == "ceiling":
        text = f"<= {fmt(gate['threshold'])}"
    else:
        text = f"{gate['direction']}, tolerance {fmt(gate['tolerance'])}"
    if gate.get("threshold_from") == "base":
        text += " (base)"
    return text


def render(report: dict, baseline_note: str, scoped: bool, thresholds_source: str, history_ref: str) -> str:
    head7, base7, mb7 = report["head_sha"][:7], report["base_sha"][:7], report["merge_base"][:7]
    lines = [f"# Quality report: `{head7}` against `{base7}`", ""]
    lines.append(
        f"Head `{head7}` graded against base `{report['base_ref']}` (`{base7}`, merge-base `{mb7}`)"
        + (f" in `{report['repo']}`." if report["repo"] else ".")
    )
    lines.append(f"Thresholds: {thresholds_source}.")
    b = report["baseline"]
    if b:
        age = f"{b['age_commits']} commit(s) behind head" if b["age_commits"] is not None else "age unknown here"
        lines.append(f"Baseline: `{b['name']}` (`{b['sha7']}`, {age}) from `{history_ref}`.")
        if scoped:
            lines.append(
                "Ratchets over the compiling collectors compare the crates in this run's scope only."
            )
    else:
        lines.append(f"Baseline: none ({baseline_note}). Every ratchet gate is not evaluated.")
    lines += ["", f"Verdict: **{report['verdict']}**", ""]

    lines += ["### Gates", "", "| Gate | Value | Baseline | Threshold | Result |", "|---|---|---|---|---|"]
    for key, gate in sorted(report["gates"].items()):
        lines.append(
            f"| `{key}` | {fmt(gate['value'])} | {fmt(gate.get('baseline'))} | "
            f"{threshold_text(gate)} | {gate['result']} |"
        )

    lines += ["", "### Changed crates", ""]
    if report["changed_crates"]:
        lines += [
            "| Crate | New strict hits | Strict total | Complexity total | Unused deps | Layer |",
            "|---|---|---|---|---|---|",
        ]
        for row in report["changed_crates"]:
            lines.append(
                f"| `{row['crate']}` | {fmt(row['new_strict_hits'])} | "
                f"{delta(row['strict_total'], row['strict_total_base'])} | "
                f"{delta(row['complexity_total'], row['complexity_total_base'])} | "
                f"{fmt(row['unused_deps'])} | {fmt(row['layer'])} |"
            )
    else:
        lines.append("No crate under `crates/` has changed Rust lines.")

    lines += ["", "### New strict hits on changed lines", ""]
    if report["new_strict_hits"]:
        lines += [f"- `{h['path']}:{h['line']}` [{h['code']}]" for h in report["new_strict_hits"]]
    elif report["not_measured"].get("clippy"):
        lines.append(f"Not measured: clippy did not run ({report['not_measured']['clippy']}).")
    else:
        lines.append("None.")

    lines += ["", "### Promotable strict lints", ""]
    if report["promotable"] is None:
        lines.append("Not computed: clippy did not cover the whole workspace in this mode.")
    elif report["promotable"]:
        lines += [f"- `{lint}`" for lint in report["promotable"]]
    else:
        lines.append("None at zero across the workspace.")

    lines += ["", "### Not measured in this mode", ""]
    if report["not_measured"]:
        lines += ["| Collector | Reason |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in sorted(report["not_measured"].items())]
    else:
        lines.append("Every collector ran.")

    lines += ["", "### Scope", ""]
    if report["scope_complete"]:
        lines.append(f"Snapshot mode `{report['mode']}`; the scope is the whole workspace.")
    else:
        lines.append(
            f"Snapshot mode `{report['mode']}`; the compiling collectors were scoped to "
            + ", ".join(f"`{c}`" for c in report["scope"])
            + "."
        )
    if report["scope_uncovered"]:
        lines.append("Changed crates the scope left out (graded elsewhere, never here):")
        lines += [f"- `{c}`" for c in report["scope_uncovered"]]
    else:
        lines.append("Changed crates outside the scope: none.")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--head", type=Path, required=True, help="dir with snapshot.json and clippy-hits.json")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--base-ref", help="ref to grade against (default: origin/main, then main)")
    ap.add_argument("--history-ref", default="origin/metrics-data", help="ref holding history/*.json")
    ap.add_argument("--thresholds", type=Path, default=Path(THRESHOLDS_PATH), help="the head's copy")
    ap.add_argument("--thresholds-base", type=Path, help="override the copy read from the merge-base")
    ap.add_argument("--changed", type=Path, help="-U0 diff from scripts/lib/changed-lines.sh")
    ap.add_argument("--untracked", type=Path, help="untracked Rust files, one per line")
    ap.add_argument("--repo", help="owner/name (default: from the origin remote)")
    args = ap.parse_args(argv)

    root = args.root.resolve()
    snapshot = json.loads((args.head / "snapshot.json").read_text(encoding="utf-8"))
    hits_path = args.head / "clippy-hits.json"
    hits = json.loads(hits_path.read_text(encoding="utf-8")) if hits_path.is_file() else []

    base_ref, base_sha, merge_base = resolve_base(root, args.base_ref)
    if args.thresholds_base:
        with args.thresholds_base.open("rb") as fh:
            base_th = tomllib.load(fh)
        th_source = f"the stricter of `{args.thresholds_base}` and `{args.thresholds}`"
    else:
        base_th, th_source = thresholds_at(root, merge_base, args.thresholds)
    with args.thresholds.open("rb") as fh:
        head_th = tomllib.load(fh)
    effective, sources = stricter(base_th, head_th)

    baseline, baseline_name, baseline_note = load_baseline(root, args.history_ref)
    baseline_for_gates, scoped = scoped_baseline(baseline, snapshot)
    gates = collect.evaluate_gates(snapshot, effective, baseline_for_gates)
    for key, gate in gates.items():
        gate["threshold_from"] = sources.get(key)
        if gate["kind"] == "ratchet":
            gate["threshold"] = gate["tolerance"]
            gate["scoped"] = scoped
    verdict = collect.verdict(gates)

    changed = {}
    if args.changed or args.untracked:
        changed = changed_lines.parse_ranges(args.changed or os.devnull, args.untracked)
    changed_names = sorted({c for c in (crate_of(p) for p in changed) if c})
    clippy_ws = snapshot["workspace"].get("clippy") or {}
    strict_codes = set(clippy_ws.get("strict", {}))
    new_hits = sorted(
        (h for h in hits if h["code"] in strict_codes and changed_lines.in_ranges(changed, h["path"], h["line"])),
        key=lambda h: (h["path"], h["line"], h["code"]),
    )

    base_crates = (baseline or {}).get("crates", {})
    rows = []
    for name in changed_names:
        crate = snapshot["crates"].get(name)
        if crate is None:
            # Changed under crates/ but not a workspace member: a crate the
            # branch removed, or a directory that is not a package.
            continue
        bc = base_crates.get(name, {})
        rows.append(
            {
                "crate": name,
                "layer": crate.get("layer"),
                "in_scope": name in snapshot["scope"]["crates"],
                "new_strict_hits": sum(1 for h in new_hits if crate_of(h["path"]) == name)
                if crate.get("clippy") is not None
                else None,
                "strict_total": (crate.get("clippy") or {}).get("strict_total"),
                "strict_total_base": (bc.get("clippy") or {}).get("strict_total"),
                "complexity_total": (crate.get("clippy") or {}).get("complexity_total"),
                "complexity_total_base": (bc.get("clippy") or {}).get("complexity_total"),
                "unused_deps": len(crate["deps"]["unused"]) if (crate.get("deps") or {}).get("unused") is not None else None,
            }
        )
    scope_uncovered = [r["crate"] for r in rows if not r["in_scope"]]

    report = {
        "schema_version": 1,
        "kind": "report",
        "repo": args.repo or repo_slug(root),
        "head_sha": snapshot["git"]["sha"],
        "base_ref": base_ref,
        "base_sha": base_sha,
        "merge_base": merge_base,
        "baseline": {
            "name": baseline_name,
            "sha7": baseline.get("git", {}).get("sha7"),
            "age_commits": age_commits(root, baseline.get("git", {}).get("sha")),
        }
        if baseline
        else None,
        "pr": None,
        "mode": snapshot["run"]["mode"],
        "scope": snapshot["scope"]["crates"],
        "scope_complete": set(snapshot["scope"]["crates"]) >= set(snapshot["crates"]),
        "verdict": verdict,
        "gates": gates,
        "changed_crates": rows,
        "new_strict_hits": new_hits,
        "promotable": snapshot["workspace"].get("strict_promotable"),
        "not_measured": snapshot["run"].get("not_measured", {}),
        "scope_uncovered": scope_uncovered,
    }
    markdown = render(report, baseline_note, scoped, th_source, args.history_ref)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.out / "report.md").write_text(markdown, encoding="utf-8")
    (args.out / "meta.json").write_text(
        json.dumps(
            {
                "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "hostname": platform.node(),
                "pid": os.getpid(),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        try:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(markdown)
        except OSError as e:
            print(f"diff: GITHUB_STEP_SUMMARY not writable ({e}); report not appended", file=sys.stderr)

    failing = sorted(k for k, g in gates.items() if g["result"] == "fail")
    print(
        f"metrics: report {report['head_sha'][:7]} vs {base_ref} verdict={verdict}"
        + (f" fail={','.join(failing)}" if failing else "")
        + (f" new_strict_hits={len(new_hits)}" if new_hits else "")
        + ("" if baseline else " baseline=none")
    )
    return GATE_EXIT if verdict == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
