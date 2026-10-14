#!/usr/bin/env bash
#
# metrics_test.sh — harness for scripts/metrics/ (spec 30).
#
# Every case runs over fixtures under scripts/metrics/testdata; no tool is
# invoked, no crate is compiled, no network. Cases are named after the
# requirement they check (the spec's `verify:` lines name them). Run them all
# with `bash scripts/metrics_test.sh`, one with `bash scripts/metrics_test.sh
# <case>`, or the lot through `just test-shell` and the workspace suite
# (crates/common/tests/shell_harnesses.rs).

# `<check> && ok ... || bad ...` is the harness idiom: ok/bad never fail, so
# the else-branch warning (SC2015) and the `$?` style note (SC2181) do not apply.
# shellcheck disable=SC2015,SC2181
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
data="$here/metrics/testdata"
collect="$here/metrics/collect.py"
layers="$here/metrics/layers.py"
schema="$here/metrics/schema.py"
prune="$here/metrics/prune.py"
dashboard="$here/metrics/dashboard.py"
command -v python3 >/dev/null 2>&1 || { echo "python3 required" >&2; exit 1; }

tmp="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-metrics)"
trap 'rm -rf "$tmp"' EXIT

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# jq-less field access: py <file> <python expression over `s`>
py() { python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' "$1" "$2"; }

# The collector over the standard fixture set, with the given extra flags.
# Runs from the repo root (collect.py reads git for the sha); hotspots are off
# unless a case turns them on, so no case walks the real history.
run_collect() {
    local out="$1"; shift
    (cd "$root" && python3 "$collect" --out "$out" --mode full --root "$root" \
        --metadata "$data/small-metadata.json" --rules "$data/small-layers.toml" \
        --thresholds "$data/thresholds-basic.toml" --strict-lints "$data/strict-lints.txt" \
        --no-hotspots "$@")
}
standard=(--clippy "$data/clippy.json" --clippy-complete --coverage "$data/llvm-cov.json"
          --tokei "$data/tokei.json" --modules "$data/modules.jsonl" --shear "$data/shear.json")

# ------------------------------------------------------------------- cases

snapshot_validates() {   # QM-001
    local out="$tmp/validates"
    run_collect "$out" "${standard[@]}" >/dev/null 2>&1 || true
    if [ -f "$out/snapshot.json" ] && python3 "$schema" "$out/snapshot.json" >/dev/null; then
        ok "snapshot validates against schema v1"
    else
        bad "snapshot missing or invalid"; return
    fi
    [ -f "$out/meta.json" ] && ok "meta.json written beside the snapshot" || bad "no meta.json"
    [ -f "$out/clippy-hits.json" ] && ok "clippy-hits.json written" || bad "no clippy-hits.json"
    # A document with a wrong verdict is rejected.
    python3 - "$out/snapshot.json" "$tmp/broken.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); s["verdict"] = "pass"; s["gates"]["ceiling:layers.unexcepted"]["result"] = "fail"
json.dump(s, open(sys.argv[2], "w"))
PY
    if python3 "$schema" "$tmp/broken.json" >/dev/null 2>&1; then
        bad "schema accepted a verdict that disagrees with its gates"
    else
        ok "schema rejects a verdict that disagrees with its gates"
    fi
}

missing_tool_is_not_measured() {   # QM-001 failure clause
    local out="$tmp/missing"
    run_collect "$out" --tokei "$data/tokei.json" --not-measured "coverage=cargo-llvm-cov not installed" \
        --not-measured "clippy=static mode" >/dev/null 2>&1 || true
    [ "$(py "$out/snapshot.json" "s['run']['not_measured']['coverage']")" = "cargo-llvm-cov not installed" ] \
        && ok "the reason is recorded under run.not_measured" || bad "reason not recorded"
    [ "$(py "$out/snapshot.json" "s['crates']['graph']['coverage']")" = "None" ] \
        && ok "an unmeasured block is null, not zero" || bad "unmeasured block not null"
    [ "$(py "$out/snapshot.json" "s['gates']['floor:coverage.lines_pct']['result']")" = "not_evaluated" ] \
        && ok "a gate over an unmeasured block is not_evaluated" || bad "gate over unmeasured block evaluated"
    # run.sh exits 3 when a collector that should have run could not; the
    # snapshot is still written. Exercised with a fake cargo on PATH.
    local fake="$tmp/fakebin"; mkdir -p "$fake"
    printf '#!/bin/sh\necho "no cargo here" >&2\nexit 7\n' > "$fake/cargo"; chmod +x "$fake/cargo"
    local status=0
    (cd "$root" && PATH="$fake:$PATH" bash "$here/metrics/run.sh" static --out "$tmp/run-missing" >/dev/null 2>&1) || status=$?
    [ "$status" -eq 1 ] && ok "run.sh exits non-zero, never clean, when cargo metadata cannot run" \
        || bad "run.sh exit $status with a broken cargo"
}

verdict_is_worst_gate() {   # QM-002, property over every gate combination
    python3 - "$collect" <<'PY'
import importlib.util, itertools, sys
spec = importlib.util.spec_from_file_location("collect", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
results = ("pass", "warn", "fail", "not_evaluated")
rank = {"pass": 0, "not_evaluated": 0, "warn": 1, "fail": 2}
assert m.verdict({}) == "pass"
for n in (1, 2, 3):
    for combo in itertools.product(results, repeat=n):
        gates = {f"g{i}": {"result": r} for i, r in enumerate(combo)}
        want = ("pass", "warn", "fail")[max(rank[r] for r in combo)]
        assert m.verdict(gates) == want, (combo, m.verdict(gates))
print("ok")
PY
    [ $? -eq 0 ] && ok "verdict is the worst gate over every combination of up to three gates" || bad "verdict property"
}

strict_counts_and_promotable() {   # QM-003
    local out="$tmp/strict"
    run_collect "$out" "${standard[@]}" >/dev/null 2>&1 || true
    local snap="$out/snapshot.json"
    [ "$(py "$snap" "s['crates']['graph']['clippy']['strict']['clippy::unwrap_used']")" = "2" ] \
        && ok "duplicate diagnostics (one per compilation unit) count once" || bad "dedup"
    [ "$(py "$snap" "s['workspace']['clippy']['strict_total']")" = "4" ] \
        && ok "workspace strict total sums the crates" || bad "strict total"
    [ "$(py "$snap" "s['workspace']['clippy']['complexity']")" = "{'cognitive_complexity': 1, 'too_many_arguments': 0, 'too_many_lines': 1}" ] \
        && ok "complexity lints are counted apart from the strict set" || bad "complexity counts"
    [ "$(py "$snap" "s['workspace']['clippy']['workspace_lints']")" = "1" ] \
        && ok "a non-strict diagnostic counts under workspace_lints" || bad "workspace_lints"
    [ "$(py "$snap" "s['workspace']['strict_promotable']")" = "['clippy::mem_forget']" ] \
        && ok "a strict lint at zero is listed as promotable" || bad "promotable"
    # A pinned scope: run.sh then omits --clippy-complete.
    printf 'graph\n' > "$tmp/scope-graph.txt"
    run_collect "$tmp/partial" --clippy "$data/clippy.json" --coverage "$data/llvm-cov.json" --tokei "$data/tokei.json" \
        --modules "$data/modules.jsonl" --shear "$data/shear.json" --scope "$tmp/scope-graph.txt" >/dev/null 2>&1 || true
    [ "$(py "$tmp/partial/snapshot.json" "s['workspace']['strict_promotable']")" = "None" ] \
        && ok "no promotable list when clippy did not cover the whole workspace" || bad "partial promotable"
    [ "$(py "$tmp/partial/snapshot.json" "s['crates']['decode']['clippy']")" = "None" ] \
        && ok "a crate outside the scope carries no clippy block" || bad "out-of-scope clippy block"
}

coverage_excludes_tests_and_generated() {   # QM-004
    local out="$tmp/cov"
    run_collect "$out" "${standard[@]}" >/dev/null 2>&1 || true
    local snap="$out/snapshot.json"
    # graph: lib.rs 80/100 + plan.rs 10/50; tests/it.rs excluded.
    [ "$(py "$snap" "s['crates']['graph']['coverage']['lines']")" = "{'covered': 90, 'pct': 60.0, 'total': 150}" ] \
        && ok "test sources stay out of a crate's denominator" || bad "graph coverage $(py "$snap" "s['crates']['graph']['coverage']['lines']")"
    [ "$(py "$snap" "s['crates']['decode']['coverage']['lines']['total']")" = "200" ] \
        && ok "build.rs stays out of the denominator" || bad "decode coverage"
    [ "$(py "$snap" "s['gates']['floor:coverage.lines_pct']['result']")" = "pass" ] \
        && ok "the workspace floor reads the llvm-cov totals" || bad "coverage gate"
}

experimental_never_changes_verdict() {   # QM-005
    local out="$tmp/exp"
    run_collect "$out" "${standard[@]}" >/dev/null 2>&1 || true
    python3 - "$out/snapshot.json" "$collect" "$data/thresholds-basic.toml" <<'PY'
import json, random, sys, tomllib, importlib.util
spec = importlib.util.spec_from_file_location("collect", sys.argv[2]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
s = json.load(open(sys.argv[1])); th = tomllib.load(open(sys.argv[3], "rb"))
base = m.verdict(m.evaluate_gates(s, th, None))
random.seed(30)
for _ in range(50):
    for c in s["crates"].values():
        c["experimental"] = {"rustqual": {"score": random.random() * 100, "cycles": random.randint(0, 9)},
                             "anatomy": {"instability": random.random(), "distance": random.random()}}
    assert m.verdict(m.evaluate_gates(s, th, None)) == base
# The gate code never names the block: the property holds by construction,
# not by the luck of the fixture.
import inspect
assert "experimental" not in inspect.getsource(m.metric) + inspect.getsource(m.evaluate_gates)
print("ok")
PY
    [ $? -eq 0 ] && ok "fifty random experimental sections leave the verdict unchanged; metric() never reads the block" || bad "experimental changed the verdict"
    # The real shape: fixtures standing in for `rustqual <crate>/src --format
    # json` (graph and decode only, as remote-proto would be left out in the
    # tree) and `cargo anatomy` (every crate).
    local real="$tmp/exp-real/snapshot.json" plain="$out/snapshot.json"
    run_collect "$tmp/exp-real" "${standard[@]}" --rustqual-dir "$data/rustqual" --anatomy "$data/anatomy.json" >/dev/null 2>&1 || true
    [ -f "$real" ] || { bad "no snapshot with the experimental fixtures"; return; }
    python3 "$schema" "$real" >/dev/null && ok "a snapshot with experimental blocks validates" || bad "experimental snapshot invalid"
    [ "$(py "$real" "s['verdict']")" = "$(py "$plain" "s['verdict']")" ] \
        && ok "the verdict is the same with and without the experimental collectors" || bad "verdict differs with experimental collectors"
    [ "$(py "$real" "json.dumps(s['gates'], sort_keys=True)")" = "$(py "$plain" "json.dumps(s['gates'], sort_keys=True)")" ] \
        && ok "every gate result is the same with and without them" || bad "gates differ with experimental collectors"
    [ "$(py "$real" "s['crates']['graph']['experimental']['rustqual']['score']")" = "0.823" ] \
        && ok "crates.graph.experimental.rustqual.score is populated" || bad "rustqual score: $(py "$real" "s['crates']['graph']['experimental']['rustqual']")"
    [ "$(py "$real" "(s['crates']['graph']['experimental']['rustqual']['cycles'], s['crates']['decode']['experimental']['rustqual']['sdp_violations'], s['crates']['graph']['experimental']['rustqual']['max_instability'])")" = "(1, 1, 1.0)" ] \
        && ok "CP-001 cycles, CP-002 violations and the module instability maximum are counted" || bad "rustqual coupling counts"
    [ "$(py "$real" "(s['crates']['common']['experimental']['rustqual'], s['crates']['common']['experimental']['anatomy']['instability'])")" = "(None, 0.0)" ] \
        && ok "a crate one tool skipped keeps the other tool's sub-block" || bad "mixed sub-blocks: $(py "$real" "s['crates']['common']['experimental']")"
    [ "$(py "$real" "s['workspace']['experimental']['anatomy']['crates_in_zone_of_pain']")" = "['mip']" ] \
        && ok "the zone-of-pain flag names the concrete, stable, distant crate" || bad "zone of pain: $(py "$real" "s['workspace']['experimental']['anatomy']")"
    [ "$(py "$real" "s['workspace']['experimental']['rustqual']['score_loc_weighted'] is not None")" = "True" ] \
        && ok "the workspace score is weighted by lines of code" || bad "no weighted score"
    [ "$(py "$plain" "s['crates']['graph']['experimental']")" = "None" ] \
        && ok "with neither tool the block is null" || bad "block not null without the tools"
}

experimental_missing_tool_is_not_measured() {   # QM-005 with QM-001's failure clause: absent tools are recorded, never faked
    if ! (cd "$root" && cargo metadata --format-version 1 --no-deps --offline >/dev/null 2>&1); then
        echo "skip - cargo metadata --offline does not run here, and run.sh needs it"
        return
    fi
    # A PATH with every directory that holds either tool taken out.
    local clean_path
    clean_path="$(python3 -c 'import os; print(":".join(d for d in os.environ["PATH"].split(":") if not any(os.path.exists(os.path.join(d, t)) for t in ("rustqual", "cargo-anatomy"))))')"
    local status=0 snap="$tmp/run-exp/snapshot.json"
    (cd "$root" && PATH="$clean_path" bash "$here/metrics/run.sh" full --out "$tmp/run-exp" \
        --no-coverage --no-modules --no-clippy --no-hotspots >/dev/null 2>&1) || status=$?
    [ -f "$snap" ] || { bad "run.sh full wrote no snapshot (exit $status)"; return; }
    [ "$(py "$snap" "s['run']['not_measured'].get('experimental.rustqual', '').startswith('rustqual not installed')")" = "True" ] \
        && ok "experimental.rustqual is under run.not_measured with its reason" || bad "rustqual reason: $(py "$snap" "s['run']['not_measured']")"
    [ "$(py "$snap" "s['run']['not_measured'].get('experimental.anatomy', '').startswith('cargo-anatomy not installed')")" = "True" ] \
        && ok "experimental.anatomy is under run.not_measured with its reason" || bad "anatomy reason: $(py "$snap" "s['run']['not_measured']")"
    [ "$(py "$snap" "s['crates']['common']['experimental']")" = "None" ] \
        && ok "the experimental block is null, not zero" || bad "experimental block not null"
    [ "$(py "$snap" "s['tools']['rustqual']")" = "" ] \
        && ok "no version is recorded for an absent tool" || bad "a version for an absent tool"
    [ "$status" -ne 3 ] && ok "a missing experimental tool does not mark the snapshot incomplete" || bad "exit 3 for a missing experimental tool"
}

report_is_byte_stable() {   # QM-006
    run_collect "$tmp/stable1" "${standard[@]}" >/dev/null 2>&1 || true
    sleep 1
    run_collect "$tmp/stable2" "${standard[@]}" >/dev/null 2>&1 || true
    if cmp -s "$tmp/stable1/snapshot.json" "$tmp/stable2/snapshot.json"; then
        ok "two runs over the same inputs give byte-identical snapshots"
    else
        bad "snapshots differ between runs"
    fi
    grep -q '"started"' "$tmp/stable1/meta.json" && ok "the start time lives in meta.json" || bad "no start time in meta"
    grep -q '"started"' "$tmp/stable1/snapshot.json" && bad "a timestamp leaked into the snapshot" || ok "no timestamp in the snapshot"
}

forbidden_edge_is_reported() {   # QM-007
    # The fixture tree is clean; seed a session->build style edge: common (leaf) -> graph.
    python3 - "$data/small-metadata.json" "$tmp/bad-meta.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
next(p for p in m["packages"] if p["name"] == "common")["dependencies"].append({"name": "graph", "kind": None})
next(p for p in m["packages"] if p["name"] == "decode")["dependencies"].append({"name": "mip", "kind": "dev"})
json.dump(m, open(sys.argv[2], "w"))
PY
    local status=0 out
    out="$(python3 "$layers" --rules "$data/small-layers.toml" --metadata "$tmp/bad-meta.json" --json)" || status=$?
    [ "$status" -eq 2 ] && ok "a forbidden edge exits 2" || bad "exit $status for a forbidden edge"
    echo "$out" | grep -q '"from": "common"' && ok "the edge is named with its crates" || bad "edge not reported"
    echo "$out" | grep -q '"to": "mip"' && bad "a dev-dependency counted as an edge" || ok "dev-dependencies are not edges"
    status=0
    python3 "$layers" --rules "$data/small-layers.toml" --metadata "$data/small-metadata.json" >/dev/null || status=$?
    [ "$status" -eq 0 ] && ok "the clean fixture exits 0" || bad "clean fixture exit $status"
    # The real tree and the real table: every carried edge is excepted.
    status=0
    (cd "$root" && python3 "$layers" --metadata "$data/cargo-metadata.json" >/dev/null) || status=$?
    [ "$status" -eq 0 ] && ok "the repo's own layers.toml holds against the committed metadata fixture" || bad "repo layers exit $status"
}

excepted_edge_is_counted_not_failed() {   # QM-007 exception clause
    cat > "$tmp/exc-layers.toml" <<'EOF'
schema = 1
[layers]
leaf = ["common"]
build = ["decode", "graph"]
product = ["mip"]
[allowed]
leaf = []
build = ["leaf", "build"]
product = ["leaf", "build"]
[[exception]]
from = "common"
to = "graph"
reason = "fixture"
since = "2026-10-14"
issue = "fixture#1"
EOF
    local status=0 out
    out="$(python3 "$layers" --rules "$tmp/exc-layers.toml" --metadata "$tmp/bad-meta.json" --json)" || status=$?
    [ "$status" -eq 0 ] && ok "an excepted edge does not fail the gate" || bad "excepted edge exit $status"
    [ "$(echo "$out" | python3 -c 'import json,sys; s=json.load(sys.stdin); print(s["exceptions"], s["unexcepted"])')" = "1 0" ] \
        && ok "it counts toward exceptions, not unexcepted" || bad "exception counts"
    echo "$out" | grep -q '"issue": "fixture#1"' && ok "the exception's issue is carried" || bad "issue not carried"
    out="$(python3 "$layers" --rules "$tmp/exc-layers.toml" --metadata "$data/small-metadata.json" --json)" || true
    echo "$out" | grep -q '"common -> graph"' && ok "a stale exception is reported" || bad "stale exception not reported"
}

unassigned_crate_fails() {   # QM-008
    cat > "$tmp/un-layers.toml" <<'EOF'
schema = 1
[layers]
leaf = ["common"]
build = ["decode", "graph"]
[allowed]
leaf = []
build = ["leaf", "build"]
EOF
    local status=0 out
    out="$(python3 "$layers" --rules "$tmp/un-layers.toml" --metadata "$data/small-metadata.json" --json)" || status=$?
    [ "$status" -eq 2 ] && ok "a member in no layer exits 2" || bad "unassigned exit $status"
    echo "$out" | grep -q '"mip"' && ok "the unassigned crate is named" || bad "unassigned not named"
    run_collect "$tmp/un" "${standard[@]}" --rules "$tmp/un-layers.toml" >/dev/null 2>&1 || status=$?
    [ "$(py "$tmp/un/snapshot.json" "s['gates']['ceiling:layers.unassigned']['result']")" = "fail" ] \
        && ok "the layers.unassigned gate fails in the snapshot" || bad "unassigned gate"
}

hotspots_rank_churn_times_findings() {   # QM-018
    # A throwaway repo whose history gives a.rs 3 commits and b.rs 1; clippy
    # findings favour b.rs. churn x findings must still rank a.rs first when
    # a.rs has findings, and a file with no findings scores 0.
    local repo="$tmp/hot"; mkdir -p "$repo/crates/graph/src"
    git -c init.templateDir= init -q "$repo" 2>/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x
    for i in 1 2 3; do echo "fn a$i(){}" >> "$repo/crates/graph/src/a.rs"; git -C "$repo" add -A; git -C "$repo" commit -q -m "a$i"; done
    echo "fn b(){}" > "$repo/crates/graph/src/b.rs"; echo "fn c(){}" > "$repo/crates/graph/src/c.rs"
    git -C "$repo" add -A; git -C "$repo" commit -q -m "b c"
    python3 - "$tmp/hot-meta.json" "$repo" <<'PY'
import json, sys
json.dump({"packages": [{"name": "graph", "id": "g", "manifest_path": sys.argv[2] + "/crates/graph/Cargo.toml",
           "description": "g", "dependencies": [], "targets": [{"kind": ["lib"], "name": "graph"}]}], "workspace_members": []}, open(sys.argv[1], "w"))
PY
    python3 - "$tmp/hot-clippy.json" <<'PY'
import json, sys
def msg(code, path, line):
    return {"reason": "compiler-message", "message": {"level": "warning", "code": {"code": code}, "message": "m",
            "spans": [{"file_name": path, "line_start": line, "is_primary": True}]}}
rows = [msg("clippy::unwrap_used", "crates/graph/src/a.rs", 1), msg("clippy::unwrap_used", "crates/graph/src/b.rs", 1),
        msg("clippy::cognitive_complexity", "crates/graph/src/b.rs", 1), msg("clippy::unwrap_used", "crates/graph/src/b.rs", 2)]
open(sys.argv[1], "w").write("\n".join(json.dumps(r) for r in rows) + "\n")
PY
    (cd "$repo" && python3 "$collect" --out "$tmp/hot-out" --mode full --root "$repo" --metadata "$tmp/hot-meta.json" \
        --rules "$tmp/hot-layers.toml" --thresholds "$data/thresholds-basic.toml" --strict-lints "$data/strict-lints.txt" \
        --clippy "$tmp/hot-clippy.json" --clippy-complete --not-measured "coverage=fixture" >/dev/null 2>&1) || true
    local snap="$tmp/hot-out/snapshot.json"
    [ -f "$snap" ] || { bad "hotspot snapshot not written"; return; }
    # a.rs: 3 commits x 1 finding = 3; b.rs: 1 commit x 3 findings = 3; c.rs: no findings.
    [ "$(py "$snap" "[(f['path'], f['churn'], f['score']) for f in s['hotspots']['files']]")" = "[('crates/graph/src/a.rs', 3, 3.0), ('crates/graph/src/b.rs', 1, 3.0)]" ] \
        && ok "score is churn times findings; ties break on path; a file with no findings is absent" \
        || bad "ranking: $(py "$snap" "[(f['path'], f['churn'], f['score']) for f in s['hotspots']['files']]")"
    [ "$(py "$snap" "s['hotspots']['coverage_included']")" = "False" ] && ok "coverage_included is false without coverage" || bad "coverage flag"
    [ "$(py "$snap" "s['hotspots']['findings_included']")" = "True" ] && ok "findings_included is true with clippy" || bad "findings flag"
}

hotspots_without_coverage() {   # QM-018 fallback clause: no findings source at all ranks on churn
    local repo="$tmp/hot"
    [ -d "$repo" ] || hotspots_rank_churn_times_findings >/dev/null
    (cd "$repo" && python3 "$collect" --out "$tmp/hot-static" --mode static --root "$repo" --metadata "$tmp/hot-meta.json" \
        --rules "$tmp/hot-layers.toml" --thresholds "$data/thresholds-basic.toml" --strict-lints "$data/strict-lints.txt" \
        --not-measured "coverage=static mode" --not-measured "clippy=static mode" >/dev/null 2>&1) || true
    local snap="$tmp/hot-static/snapshot.json"
    [ "$(py "$snap" "s['hotspots']['findings_included']")" = "False" ] && ok "findings_included is false in static mode" || bad "findings flag"
    [ "$(py "$snap" "[(f['path'], f['score']) for f in s['hotspots']['files']]")" = "[('crates/graph/src/a.rs', 3.0), ('crates/graph/src/b.rs', 1.0), ('crates/graph/src/c.rs', 1.0)]" ] \
        && ok "without findings the ranking is churn alone" || bad "churn-only ranking: $(py "$snap" "[(f['path'], f['score']) for f in s['hotspots']['files']]")"
}

module_cycles_from_dot() {   # cargo-modules' --acyclic is unusable (type<->method edges); SCCs come from the DOT
    local out="$tmp/modules"
    run_collect "$out" "${standard[@]}" >/dev/null 2>&1 || true
    local snap="$out/snapshot.json"
    [ "$(py "$snap" "s['crates']['graph']['modules']['cycles']")" = "[['graph::builds', 'graph::plan']]" ] \
        && ok "a two-module uses cycle is found from the DOT graph" || bad "graph cycles: $(py "$snap" "s['crates']['graph']['modules']")"
    [ "$(py "$snap" "s['crates']['graph']['modules']['acyclic']")" = "False" ] && ok "acyclic is false for that crate" || bad "acyclic flag"
    [ "$(py "$snap" "s['crates']['decode']['modules']['cycles']")" = "[]" ] && ok "owns edges and acyclic uses edges make no cycle" || bad "decode cycles"
    [ "$(py "$snap" "s['crates']['decode']['modules']['orphan_files']")" = "['crates/decode/src/old.rs']" ] \
        && ok "an orphan is a file every target of the crate orphans" || bad "orphan intersection: $(py "$snap" "s['crates']['decode']['modules']['orphan_files']")"
    [ "$(py "$snap" "s['workspace']['modules']")" = "{'cycles': 1, 'errors': [], 'orphans': 1}" ] \
        && ok "workspace modules block sums cycles and orphans" || bad "workspace modules: $(py "$snap" "s['workspace']['modules']")"
    [ "$(py "$snap" "s['gates']['ceiling:modules.cycles']['result']")" = "fail" ] && ok "the cycles ceiling fails on the seeded cycle" || bad "cycles gate"
    # Root <-> child and anything through a test module is structure, not a finding.
    local cycles
    cycles="$(python3 -c '
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("collect", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.module_cycles([Path(sys.argv[2])]))' "$collect" "$data/structural.dot")"
    [ "$cycles" = "[]" ] && ok "root and test-module edges are structural, not cycles" || bad "structural filter: $cycles"
}

darwin_scope_lists_uncovered_crates() {   # QM-013: the snapshot side; the report side lands with the diff grader
    local out="$tmp/darwin"
    printf 'graph\n' > "$tmp/scope-graph.txt"
    run_collect "$out" "${standard[@]}" --mode darwin --scope "$tmp/scope-graph.txt" >/dev/null 2>&1 || true
    [ "$(py "$out/snapshot.json" "s['run']['mode']")" = "darwin" ] && ok "mode is recorded as darwin" || bad "mode"
    [ "$(py "$out/snapshot.json" "s['scope']['crates']")" = "['graph']" ] && ok "the pinned scope is recorded" || bad "scope"
    [ "$(py "$out/snapshot.json" "s['crates']['decode']['coverage']")" = "None" ] \
        && ok "a crate outside the scope has no coverage block" || bad "out-of-scope coverage"
    [ "$(py "$out/snapshot.json" "s['crates']['decode']['size'] is not None")" = "True" ] \
        && ok "static collectors still cover every crate" || bad "size missing outside scope"
}

prune_keeps_daily_then_monthly() {   # QM-015, property over generated histories
    # keep(f) iff age(f, today) <= 90 days or f is the earliest snapshot of its
    # month: checked against generated names over about 400 days, with gaps,
    # doubled days and several reference dates.
    python3 - "$prune" <<'PY'
import importlib.util, random, sys
from datetime import date, timedelta
spec = importlib.util.spec_from_file_location("prune", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
random.seed(15)
start = date(2025, 9, 1)
for trial in range(20):
    names = []
    for day in range(400):
        if random.random() < 0.8:
            d = start + timedelta(days=day)
            for k in range(2 if random.random() < 0.1 else 1):
                names.append(f"{d.isoformat()}-{random.randrange(16**7):07x}")
    names = [n + ".json" for n in dict.fromkeys(names)]
    today = start + timedelta(days=random.choice((100, 250, 399, 450)))
    kept = m.keep(names, today)
    by_month = {}
    for n in names:
        by_month.setdefault(n[:7], []).append(n)
    for n in names:
        age = (today - date.fromisoformat(n[:10])).days
        earliest = n == min(by_month[n[:7]])
        assert (n in kept) == (age <= 90 or earliest), (trial, n, today, age, earliest, n in kept)
    for month, ns in by_month.items():
        old = [n for n in ns if (today - date.fromisoformat(n[:10])).days > 90]
        if len(old) == len(ns):
            assert len(kept & set(ns)) == 1, (trial, month, kept & set(ns))
    assert kept <= set(names)
    assert m.keep(names + ["README.md", "2025-13-40-abcdefg.json"], today) == kept
print("ok")
PY
    [ $? -eq 0 ] && ok "keep(f) iff age <= 90 days or earliest of its month, over twenty generated histories" || bad "prune property"
    # On a copy of the fixtures plus a second June file: --dry-run removes
    # nothing; the real run removes only the later June snapshot.
    local hist="$tmp/prune-hist"; rm -rf "$hist"; mkdir -p "$hist"
    cp "$data/history/"*.json "$hist/"
    cp "$data/history/2026-06-05-1a2b3c4.json" "$hist/2026-06-20-fffffff.json"
    echo "not a snapshot" > "$hist/notes.txt"
    local before after
    before="$(find "$hist" -mindepth 1 -printf '%f\n' | sort)"
    python3 "$prune" "$hist" --dry-run >"$tmp/prune-dry.out" 2>/dev/null
    after="$(find "$hist" -mindepth 1 -printf '%f\n' | sort)"
    [ "$before" = "$after" ] && ok "--dry-run removes nothing" || bad "--dry-run changed the directory"
    grep -q '^would remove 2026-06-20-fffffff.json$' "$tmp/prune-dry.out" && ok "--dry-run names what it would remove" || bad "dry-run output: $(cat "$tmp/prune-dry.out")"
    python3 "$prune" "$hist" >"$tmp/prune.out" 2>/dev/null
    [ ! -f "$hist/2026-06-20-fffffff.json" ] && [ -f "$hist/2026-06-05-1a2b3c4.json" ] && [ -f "$hist/notes.txt" ] \
        && ok "the later June snapshot goes; the earliest, the recent ones and a non-snapshot stay" || bad "prune removed the wrong files: $(ls "$hist")"
    grep -q '^remove 2026-06-20-fffffff.json$' "$tmp/prune.out" && ok "the removal is printed" || bad "prune output: $(cat "$tmp/prune.out")"
}

dashboard_renders_offline_with_tables() {   # QM-016
    local out="$tmp/dash"
    python3 "$dashboard" "$data/history" "$out" >/dev/null 2>&1 || { bad "dashboard.py failed over the fixtures"; return; }
    [ -f "$out/index.html" ] && ok "index.html written" || { bad "no index.html"; return; }
    # Structure: a table after every svg, headings, no script, no URL in any
    # src or href. Checked with html.parser, no third-party package.
    python3 - "$out/index.html" <<'PY'
import sys
from html.parser import HTMLParser
class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.seq = []; self.scripts = 0; self.urls = []; self.headings = []; self.titles = 0
        self.in_h = None; self.links = 0
    def handle_starttag(self, tag, attrs):
        if tag in ("svg", "table"): self.seq.append(tag)
        if tag == "script": self.scripts += 1
        if tag == "title": self.titles += 1
        if tag in ("link", "img", "iframe", "object", "embed"): self.links += 1
        if tag in ("h1", "h2"): self.in_h = tag
        for k, v in attrs:
            if k in ("src", "href", "xlink:href", "data") and v and ("http://" in v or "https://" in v or v.startswith("//")):
                self.urls.append(v)
    def handle_endtag(self, tag):
        if tag in ("h1", "h2"): self.in_h = None
    def handle_data(self, data):
        if self.in_h and data.strip(): self.headings.append(data.strip())
p = P(); p.feed(open(sys.argv[1], encoding="utf-8").read())
svgs = [i for i, t in enumerate(p.seq) if t == "svg"]
assert svgs, "no svg"
for i in svgs:
    assert i + 1 < len(p.seq) and p.seq[i + 1] == "table", ("svg without a table after it", i, p.seq)
assert p.scripts == 0, "script tag"
assert p.links == 0, "external resource tag"
assert not p.urls, p.urls
assert p.titles == len(svgs) + 1, (p.titles, len(svgs))  # the page title plus one per chart
for h in ("Quality metrics", "Coverage, lines covered", "Strict lint hits", "Complexity lint hits",
          "Unused dependencies", "Code size, lines of code", "Layer edges", "Latest gates", "Top hotspots",
          "Promotable strict lints"):
    assert h in p.headings, (h, p.headings)
html = open(sys.argv[1], encoding="utf-8").read()
assert "not measured" in html, "the null coverage snapshot is not shown as a gap"
assert "clippy::mem_forget" in html, "promotable lint missing"
assert "crates/mip/src/main.rs" in html, "hotspot path missing"
print("ok")
PY
    [ $? -eq 0 ] && ok "every svg is followed by a table; headings present; no script, no URL" || bad "dashboard structure"
    # Gap, not zero: the August snapshot has coverage null, so the coverage
    # line is two segments (four points) and no point sits on the axis.
    python3 - "$out/index.html" <<'PY'
import re, sys
html = open(sys.argv[1], encoding="utf-8").read()
cov = re.search(r'<section id="coverage">(.*?)</section>', html, re.S).group(1)
assert len(re.findall(r'<path class="line"', cov)) == 2, "coverage line is not broken at the gap"
assert len(re.findall(r'<circle', cov)) == 4, "a null coverage drew a marker"
print("ok")
PY
    [ $? -eq 0 ] && ok "a null metric is a gap in the line, not a zero" || bad "gap rendering"
    # Deterministic: a second run over the same history is byte-identical.
    sleep 1
    python3 "$dashboard" "$data/history" "$tmp/dash2" >/dev/null 2>&1
    cmp -s "$out/index.html" "$tmp/dash2/index.html" && ok "two runs give byte-identical pages" || bad "pages differ between runs"
    # One snapshot: points and tables, no lines, still every table.
    local one="$tmp/one-hist"; mkdir -p "$one"
    cp "$data/history/2026-10-01-5e6f7a8.json" "$one/"
    python3 "$dashboard" "$one" "$tmp/dash-one" >/dev/null 2>&1 \
        && grep -q '<circle' "$tmp/dash-one/index.html" && ! grep -q '<path class="line"' "$tmp/dash-one/index.html" \
        && [ "$(grep -o '<svg' "$tmp/dash-one/index.html" | wc -l)" -eq "$(grep -o '<svg' "$out/index.html" | wc -l)" ] \
        && ok "a single snapshot renders points and tables, no lines" || bad "single-snapshot render"
    # A file that fails the schema is skipped and listed on the page.
    cp "$data/history/"*.json "$one/"
    echo '{"kind": "nope"}' > "$one/2026-10-02-bad0bad.json"
    python3 "$dashboard" "$one" "$tmp/dash-skip" >/dev/null 2>&1
    grep -q '2026-10-02-bad0bad.json' "$tmp/dash-skip/index.html" && ok "an invalid snapshot is skipped and listed" || bad "invalid snapshot not listed"
}

clippy_thresholds_agree() {   # thresholds.toml [clippy] mirrors clippy.toml
    python3 - "$root" <<'PY'
import sys, tomllib
root = sys.argv[1]
th = tomllib.load(open(f"{root}/metrics/thresholds.toml", "rb"))["clippy"]
cl = tomllib.load(open(f"{root}/clippy.toml", "rb"))
for k, v in th.items():
    assert cl.get(k) == v, (k, cl.get(k), v)
PY
    [ $? -eq 0 ] && ok "clippy.toml and metrics/thresholds.toml agree on the complexity thresholds" || bad "complexity thresholds disagree"
}

# -------------------------------------------------------------------- run

# The hotspot cases share a tiny layers file.
cat > "$tmp/hot-layers.toml" <<'EOF'
schema = 1
[layers]
build = ["graph"]
[allowed]
build = ["build"]
EOF

all_cases=(
    snapshot_validates
    missing_tool_is_not_measured
    verdict_is_worst_gate
    strict_counts_and_promotable
    coverage_excludes_tests_and_generated
    experimental_never_changes_verdict
    experimental_missing_tool_is_not_measured
    report_is_byte_stable
    forbidden_edge_is_reported
    excepted_edge_is_counted_not_failed
    unassigned_crate_fails
    hotspots_rank_churn_times_findings
    hotspots_without_coverage
    module_cycles_from_dot
    darwin_scope_lists_uncovered_crates
    prune_keeps_daily_then_monthly
    dashboard_renders_offline_with_tables
    clippy_thresholds_agree
)
cases=("${all_cases[@]}")
[ "$#" -gt 0 ] && cases=("$@")

for case in "${cases[@]}"; do
    if ! declare -F "$case" >/dev/null; then
        bad "no such case: $case"
        continue
    fi
    echo "== $case =="
    "$case"
done

echo
echo "metrics_test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
