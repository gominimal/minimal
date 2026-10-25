#!/usr/bin/env bash
#
# metrics_test.sh — harness for scripts/metrics/ (spec 31).
#
# Every case runs over fixtures under scripts/metrics/testdata; no tool is
# invoked, no crate is compiled, no network. Cases are named after the
# requirement they check (the spec's `verify:` lines name them). Run them all
# with `bash scripts/metrics_test.sh`, one with `bash scripts/metrics_test.sh
# <case>`, or the lot through `just test-shell` and the workspace suite
# (crates/common/tests/shell_harnesses.rs).

# `<check> && ok ... || bad ...` is the harness idiom: ok/bad never fail, so
# the else-branch warning (SC2015) and the `$?` style note (SC2181) do not apply.
# The grading cases grep report.md for Markdown, whose backticks are literal
# text inside single quotes on purpose (SC2016).
# shellcheck disable=SC2015,SC2016,SC2181
set -euo pipefail

# Cases that run the real scripts inherit this environment, and in Actions
# that includes GITHUB_STEP_SUMMARY: run inside the nightly's coverage pass,
# the gate cases wrote their grading report onto the metrics job's own
# summary page. The cases that check the append set the variable themselves.
unset GITHUB_STEP_SUMMARY

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
data="$here/metrics/testdata"
collect="$here/metrics/collect.py"
diff="$here/metrics/diff.py"
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
        --no-coverage --no-modules --no-clippy --no-hotspots --no-mutants >/dev/null 2>"$tmp/run-exp.err") || status=$?
    [ -f "$snap" ] || { bad "run.sh full wrote no snapshot (exit $status)"; return; }
    [ "$(py "$snap" "s['run']['not_measured'].get('experimental.rustqual', '').startswith('rustqual not installed')")" = "True" ] \
        && ok "experimental.rustqual is under run.not_measured with its reason" || bad "rustqual reason: $(py "$snap" "s['run']['not_measured']")"
    [ "$(py "$snap" "s['run']['not_measured'].get('experimental.anatomy', '').startswith('cargo-anatomy not installed')")" = "True" ] \
        && ok "experimental.anatomy is under run.not_measured with its reason" || bad "anatomy reason: $(py "$snap" "s['run']['not_measured']")"
    [ "$(py "$snap" "s['crates']['common']['experimental']")" = "None" ] \
        && ok "the experimental block is null, not zero" || bad "experimental block not null"
    [ "$(py "$snap" "s['tools']['rustqual']")" = "" ] \
        && ok "no version is recorded for an absent tool" || bad "a version for an absent tool"
    [ "$status" -ne 3 ] && ok "a missing experimental tool does not mark the snapshot incomplete" \
        || bad "exit 3 for a missing experimental tool: $(grep FAILED "$tmp/run-exp.err" | head -n1)"
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
    # The report too: two gradings of the same head give the same bytes.
    grade "$tmp/report-stable1" >/dev/null 2>&1 || true
    sleep 1
    grade "$tmp/report-stable2" >/dev/null 2>&1 || true
    if cmp -s "$tmp/report-stable1/report.json" "$tmp/report-stable2/report.json" && cmp -s "$tmp/report-stable1/report.md" "$tmp/report-stable2/report.md"; then
        ok "two gradings of the same head give byte-identical report.json and report.md"
    else
        bad "reports differ between runs"
    fi
    grep -q '"generated"' "$tmp/report-stable1/meta.json" && ok "the report's time lives in its meta.json" || bad "no time in report meta"
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
    status=0
    out="$(python3 "$layers" --rules "$tmp/exc-layers.toml" --metadata "$data/small-metadata.json" --json)" || status=$?
    echo "$out" | grep -q '"common -> graph"' && ok "a stale exception is reported" || bad "stale exception not reported"
    [ "$status" -eq 2 ] && ok "a stale exception exits 2" || bad "stale exception exit $status"
}

edges_match_by_package_not_name() {   # a registry crate named like a member is not an edge
    # common (leaf) -> graph is forbidden; each variant names `graph` as a
    # dependency of common, and only the path dependency on the member is it.
    local variant status out
    for variant in registry outside member; do
        python3 - "$data/small-metadata.json" "$tmp/edge-$variant.json" "$variant" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
dep = {"name": "graph", "kind": None,
       "registry": {"source": "registry+https://github.com/rust-lang/crates.io-index"},
       "outside": {"source": None, "path": "/elsewhere/graph"},
       "member": {"source": None, "path": "/x/crates/graph"}}[sys.argv[3]]
dep = {"name": "graph", "kind": None, **dep}
next(p for p in m["packages"] if p["name"] == "common")["dependencies"].append(dep)
json.dump(m, open(sys.argv[2], "w"))
PY
        status=0
        out="$(python3 "$layers" --rules "$data/small-layers.toml" --metadata "$tmp/edge-$variant.json" --json)" || status=$?
        case "$variant" in
            member) [ "$status" -eq 2 ] && ok "a path dependency on the member is the forbidden edge" || bad "member edge exit $status" ;;
            *) [ "$status" -eq 0 ] && ok "a same-named crate ($variant) is not an internal edge" || bad "$variant dep exit $status: $out" ;;
        esac
    done
}

non_member_packages_are_not_crates() {   # full metadata through --metadata
    # Without --no-deps, `packages` carries every dependency; only the
    # workspace members are crates to place in a layer.
    python3 - "$data/small-metadata.json" "$tmp/full-meta.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["packages"].append({"name": "serde", "id": "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
                      "manifest_path": "/r/serde/Cargo.toml", "description": "serde", "dependencies": [], "targets": []})
json.dump(m, open(sys.argv[2], "w"))
PY
    local status=0 out
    out="$(python3 "$layers" --rules "$data/small-layers.toml" --metadata "$tmp/full-meta.json" --json)" || status=$?
    [ "$status" -eq 0 ] && ok "a non-member package is not a crate to place" || bad "non-member exit $status: $out"
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

newest_snapshot_orders_a_day_by_commit() {   # the baseline and the mutants `auto` reference
    # Two commits an hour apart whose sha7s sort the other way round, and a
    # snapshot of each under the same date: a name sort picks the older one.
    local repo="$tmp/newest" n=0 early late
    rm -rf "$repo"; git -c init.templateDir= init -q -b main "$repo" 2>/dev/null
    gc() { GIT_COMMITTER_DATE="$1" GIT_AUTHOR_DATE="$1" git -C "$repo" -c user.name=t -c user.email=t@x commit -q --allow-empty -m "$2"; }
    gc 2026-10-01T01:00:00Z early; early="$(git -C "$repo" rev-parse --short=7 HEAD)"
    while :; do
        n=$((n + 1)); gc 2026-10-01T02:00:00Z "late $n"; late="$(git -C "$repo" rev-parse --short=7 HEAD)"
        [[ "$late" < "$early" ]] && break
        git -C "$repo" reset -q --hard HEAD~1
    done
    mkdir -p "$repo/hist"
    echo '{}' > "$repo/hist/2026-10-01-$early.json"; echo '{}' > "$repo/hist/2026-10-01-$late.json"
    echo '{}' > "$repo/hist/2026-09-30-fffffff.json"
    [ "$(cd "$repo" && python3 "$prune" --newest hist)" = "2026-10-01-$late.json" ] \
        && ok "prune.py --newest takes the later commit of the day, not the larger sha7" \
        || bad "newest: $(cd "$repo" && python3 "$prune" --newest hist)"
    # diff.py's baseline over a history ref holding both.
    git -C "$repo" checkout -q --orphan metrics-data
    git -C "$repo" rm -rqf --cached . 2>/dev/null || true
    mkdir -p "$repo/history"; cp "$repo/hist/"*.json "$repo/history/"
    git -C "$repo" add history; gc 2026-10-02T00:00:00Z data
    git -C "$repo" checkout -q main
    if python3 - "$here/metrics" "$repo" "2026-10-01-$late.json" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import diff
_, name, note = diff.load_baseline(Path(sys.argv[2]), "metrics-data")
assert name == sys.argv[3], (name, note)
PY
    then ok "diff.py grades against the later commit of the day"
    else bad "diff.py baseline picked the older snapshot"
    fi
    unset -f gc
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

# The mutants cases share one throwaway repo: a main branch, a feature commit
# that edits a Rust file, an untracked new Rust file, and a fake cargo whose
# `mutants` subcommand logs its argv and copies the fixture outcomes.json
# where a real run would write it. Nothing compiles. run.sh resolves its
# helpers from the repo root, so scripts/ and metrics/ are copied in.
mutants_repo() {
    local repo="$tmp/mut"
    [ -d "$repo" ] && return
    mkdir -p "$repo/crates/graph/src" "$repo/metrics" "$repo/fakebin"
    cp -R "$root/scripts" "$repo/scripts"
    cp "$root/rust-toolchain.toml" "$repo/rust-toolchain.toml"
    cp "$data/small-layers.toml" "$repo/metrics/layers.toml"
    cp "$data/thresholds-basic.toml" "$repo/metrics/thresholds.toml"
    git -c init.templateDir= init -q -b main "$repo" 2>/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x
    printf 'pub fn a() -> u8 { 1 }\n' > "$repo/crates/graph/src/lib.rs"
    git -C "$repo" add -A; git -C "$repo" commit -q -m base
    git -C "$repo" checkout -q -b feat
    printf 'pub fn a() -> u8 { 2 }\n' > "$repo/crates/graph/src/lib.rs"
    git -C "$repo" commit -q -am change
    printf 'pub fn b() {}\n' > "$repo/crates/graph/src/new.rs"
    cat > "$repo/fakebin/cargo" <<EOF
#!/bin/sh
case "\$1" in
    metadata) cat "$data/small-metadata.json" ;;
    mutants)
        [ "\$2" = "--version" ] && { echo "cargo-mutants 27.1.0"; exit 0; }
        printf '%s\n' "\$@" > "$tmp/mut-argv"
        while [ "\$#" -gt 0 ]; do [ "\$1" = "--output" ] && out="\$2"; shift; done
        mkdir -p "\$out/mutants.out" && cp "$data/outcomes.json" "\$out/mutants.out/outcomes.json" ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$repo/fakebin/cargo"
    for stub in cargo-mutants cargo-nextest; do
        printf '#!/bin/sh\nexit 0\n' > "$repo/fakebin/$stub"; chmod +x "$repo/fakebin/$stub"
    done
}

# run_mutants_mode: run.sh in mutants mode over the throwaway repo, once.
run_mutants_mode() {
    mutants_repo
    local repo="$tmp/mut"
    [ -f "$repo/.scratch/mut/snapshot.json" ] && return
    (cd "$repo" && PATH="$repo/fakebin:$PATH" bash scripts/metrics/run.sh mutants main --out "$repo/.scratch/mut" >/dev/null 2>&1) || true
}

mutants_scope_follows_mode() {   # QM-017
    # collect.py: per-crate counts and the score over the fixture, scope as given.
    run_collect "$tmp/mut-diff" --mutants "$data/outcomes.json" --mutants-scope in-diff >/dev/null 2>&1 || true
    local snap="$tmp/mut-diff/snapshot.json"
    [ -f "$snap" ] || { bad "no snapshot with --mutants"; return; }
    [ "$(py "$snap" "s['crates']['graph']['mutants']")" = "{'caught': 3, 'missed': 2, 'score_pct': 50.0, 'tested': 6, 'timeout': 1, 'unviable': 0}" ] \
        && ok "graph: caught, missed and timeout make up tested; score is caught over tested" \
        || bad "graph mutants: $(py "$snap" "s['crates']['graph']['mutants']")"
    [ "$(py "$snap" "(s['crates']['decode']['mutants']['unviable'], s['crates']['decode']['mutants']['score_pct'])")" = "(1, 66.67)" ] \
        && ok "decode: an unviable mutant is counted but stays out of the score" || bad "decode mutants"
    [ "$(py "$snap" "s['crates']['common']['mutants']")" = "None" ] \
        && ok "a crate the run generated no mutants for is null, not a perfect score" || bad "common mutants not null"
    [ "$(py "$snap" "(s['workspace']['mutants']['scope'], s['workspace']['mutants']['tested'], s['workspace']['mutants']['score_pct'])")" = "('in-diff', 9, 55.56)" ] \
        && ok "the workspace sums the crates and records the in-diff scope" || bad "workspace mutants"
    [ "$(py "$snap" "s['gates']['floor:mutants.score_pct']['value']")" = "55.56" ] \
        && ok "the mutants.score_pct floor reads the workspace score" || bad "mutants floor"
    # Every mutant unviable: nothing was tested, so the score is null, not 0 %.
    python3 - "$data/outcomes.json" "$tmp/unviable-outcomes.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["outcomes"] = [o for o in d["outcomes"] if not isinstance(o["scenario"], dict) or o["summary"] == "Unviable"]
json.dump(d, open(sys.argv[2], "w"))
PY
    run_collect "$tmp/mut-unviable" --mutants "$tmp/unviable-outcomes.json" --mutants-scope in-diff >/dev/null 2>&1 || true
    [ "$(py "$tmp/mut-unviable/snapshot.json" "(s['workspace']['mutants']['tested'], s['workspace']['mutants']['score_pct'], s['gates']['floor:mutants.score_pct']['result'])")" = "(0, None, 'not_evaluated')" ] \
        && ok "no tested mutant leaves the score null and the floor not evaluated" \
        || bad "all-unviable mutants: $(py "$tmp/mut-unviable/snapshot.json" "(s['workspace']['mutants'], s['gates']['floor:mutants.score_pct'])")"
    run_collect "$tmp/mut-shard" --mutants "$data/outcomes.json" --mutants-scope shard --mutants-shard 2/7 >/dev/null 2>&1 || true
    [ "$(py "$tmp/mut-shard/snapshot.json" "(s['workspace']['mutants']['scope'], s['workspace']['mutants']['shard'])")" = "('shard', '2/7')" ] \
        && ok "a nightly run records its shard" || bad "shard not recorded"
    # run.sh: the mode decides what cargo-mutants is told to test.
    run_mutants_mode
    local repo="$tmp/mut"
    snap="$repo/.scratch/mut/snapshot.json"
    [ -f "$snap" ] || { bad "mutants mode wrote no snapshot"; return; }
    grep -qx -- '--in-diff' "$tmp/mut-argv" && ok "mutants mode passes --in-diff" || bad "no --in-diff in argv: $(tr '\n' ' ' < "$tmp/mut-argv")"
    grep -qx -- '--shard' "$tmp/mut-argv" && bad "mutants mode passed --shard" || ok "mutants mode passes no shard"
    grep -q '^+pub fn a() -> u8 { 2 }$' "$repo/.scratch/mut/raw/mutants.diff" \
        && ok "the diff carries the changed line from the merge-base" || bad "changed line not in the diff"
    [ "$(py "$snap" "(s['run']['mode'], s['workspace']['mutants']['scope'])")" = "('mutants', 'in-diff')" ] \
        && ok "the snapshot says mutants mode, in-diff scope" || bad "mode/scope: $(py "$snap" "(s['run']['mode'], s['workspace']['mutants']['scope'])")"
    rm -f "$tmp/mut-argv"
    (cd "$repo" && PATH="$repo/fakebin:$PATH" bash scripts/metrics/run.sh full --no-coverage --no-modules --no-clippy --out "$repo/.scratch/full" >/dev/null 2>&1) || true
    snap="$repo/.scratch/full/snapshot.json"
    [ -f "$snap" ] || { bad "full mode wrote no snapshot"; return; }
    # No history dir in the fixture, so `auto` falls back to the merge-base with main.
    grep -qx -- '--in-diff' "$tmp/mut-argv" && ok "full mode passes --in-diff for the lines since the reference" || bad "no --in-diff in argv: $(tr '\n' ' ' < "$tmp/mut-argv")"
    grep -qx -- '--shard' "$tmp/mut-argv" && bad "full mode passed --shard" || ok "full mode passes no shard"
    [ "$(py "$snap" "(s['workspace']['mutants']['scope'], s['workspace']['mutants']['since'] == __import__('subprocess').run(['git','-C','$repo','rev-parse','--short=7','main'],capture_output=True,text=True).stdout.strip(), s['workspace']['mutants']['partial'])")" = "('since', True, False)" ] \
        && ok "the nightly snapshot records the since scope, the reference and no partial flag" || bad "full scope: $(py "$snap" "s['workspace']['mutants']")"
    rm -f "$tmp/mut-argv"
    # The newest history snapshot names the reference when it is a commit.
    mkdir -p "$repo/.scratch/metrics/history"
    echo '{}' > "$repo/.scratch/metrics/history/2026-10-01-$(git -C "$repo" rev-parse --short=7 main).json"
    (cd "$repo" && PATH="$repo/fakebin:$PATH" bash scripts/metrics/run.sh full --no-coverage --no-modules --no-clippy --out "$repo/.scratch/full2" >/dev/null 2>&1) || true
    grep -qx -- '--in-diff' "$tmp/mut-argv" && ok "a history snapshot's sha7 is the reference" || bad "history reference not used"
    (cd "$repo" && PATH="$repo/fakebin:$PATH" bash scripts/metrics/run.sh full --no-coverage --no-modules --no-clippy --since HEAD --out "$repo/.scratch/full3" >/dev/null 2>&1) || true
    [ "$(py "$repo/.scratch/full3/snapshot.json" "s['run']['not_measured'].get('mutants','').startswith('no Rust changes since')")" = "True" ] \
        && ok "--since HEAD finds nothing to test and says so" || bad "since HEAD: $(py "$repo/.scratch/full3/snapshot.json" "s['run']['not_measured']")"
    rm -f "$tmp/mut-argv"
    (cd "$repo" && PATH="$repo/fakebin:$PATH" bash scripts/metrics/run.sh full --no-coverage --no-modules --no-clippy --no-mutants --out "$repo/.scratch/nomut" >/dev/null 2>&1) || true
    [ ! -f "$tmp/mut-argv" ] && [ "$(py "$repo/.scratch/nomut/snapshot.json" "s['workspace']['mutants']")" = "None" ] \
        && ok "--no-mutants runs nothing and leaves the block null" || bad "--no-mutants"
}

untracked_file_is_listed() {   # QM-017 untracked clause
    run_mutants_mode
    local repo="$tmp/mut" snap="$tmp/mut/.scratch/mut/snapshot.json"
    [ -f "$snap" ] || { bad "mutants mode wrote no snapshot"; return; }
    [ "$(py "$snap" "s['workspace']['mutants']['untracked_outside_scope']")" = "['crates/graph/src/new.rs']" ] \
        && ok "the untracked file is listed as outside the mutation scope" || bad "untracked list: $(py "$snap" "s['workspace']['mutants']['untracked_outside_scope']")"
    grep -q 'new.rs' "$repo/.scratch/mut/raw/mutants.diff" && bad "the untracked file leaked into the diff" || ok "the diff never names it, so cargo-mutants never saw it"
    # collect.py alone: the list is a fact about the change, so it is written
    # even when cargo-mutants did not run.
    printf 'crates/graph/src/new.rs\n' > "$tmp/untracked.txt"
    run_collect "$tmp/mut-untracked" --mutants-untracked "$tmp/untracked.txt" --not-measured "mutants=no Rust changes since main" >/dev/null 2>&1 || true
    [ "$(py "$tmp/mut-untracked/snapshot.json" "s['workspace']['mutants']")" = "{'untracked_outside_scope': ['crates/graph/src/new.rs']}" ] \
        && ok "with no run the block carries the list alone" || bad "list without a run"
    [ "$(py "$tmp/mut-untracked/snapshot.json" "s['gates']['floor:mutants.score_pct']['result']")" = "not_evaluated" ] \
        && ok "no score, so the floor is not evaluated" || bad "floor evaluated without a score"
}

truncated_junit_keeps_the_snapshot() {   # QM-001: a bad test report is not a lost snapshot
    mutants_repo
    local repo="$tmp/mut" fake="$tmp/junit-fakebin"
    if ! ls "$(rustc --print target-libdir 2>/dev/null)"/libprofiler_builtins-*.rlib >/dev/null 2>&1; then
        echo "skip - this toolchain has no profiler runtime, so run.sh skips coverage before the junit step"
        return
    fi
    mkdir -p "$fake"
    # cargo llvm-cov succeeds and leaves a junit cut off mid-element, as a
    # killed nextest does.
    cat > "$fake/cargo" <<EOF
#!/bin/sh
case "\$1 \$2" in
    "metadata "*) cat "$data/small-metadata.json" ;;
    "llvm-cov nextest")
        while [ "\$#" -gt 0 ]; do [ "\$1" = "--output-path" ] && out="\$2"; shift; done
        mkdir -p target/llvm-cov-target/nextest/coverage
        printf '<testsuites tests="3" failures="0"><testsuite name="graph"' > target/llvm-cov-target/nextest/coverage/junit.xml
        cp "$data/llvm-cov.json" "\$out" ;;
    "llvm-cov report") : ;;
    "llvm-cov show-env") : ;;
    *" --version") echo "\$1 1.0.0" ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$fake/cargo"
    for stub in cargo-llvm-cov cargo-nextest; do
        printf '#!/bin/sh\nexit 0\n' > "$fake/$stub"; chmod +x "$fake/$stub"
    done
    local status=0 snap="$repo/.scratch/junit/snapshot.json"
    (cd "$repo" && PATH="$fake:$PATH" bash scripts/metrics/run.sh full --no-modules --no-clippy --no-mutants --no-hotspots \
        --out "$repo/.scratch/junit" >/dev/null 2>"$tmp/junit.err") || status=$?
    [ -f "$snap" ] && ok "a truncated junit still leaves a snapshot" \
        || { bad "no snapshot with a truncated junit (exit $status): $(tail -n3 "$tmp/junit.err")"; return; }
    [ "$(py "$snap" "(s['workspace']['coverage'] is not None, 'tests' in s['workspace']['coverage'])")" = "(True, False)" ] \
        && ok "coverage is kept and the unreadable test counts are left out" \
        || bad "coverage with a truncated junit: $(py "$snap" "s['workspace']['coverage']")"
}

missing_nextest_fails_mutants_mode() {   # the mutants task never passes empty
    mutants_repo
    local repo="$tmp/mut" fake="$tmp/nonextest-bin" clean_path status=0 snap="$tmp/mut/.scratch/nonextest/snapshot.json"
    mkdir -p "$fake"; cp "$repo/fakebin/cargo" "$repo/fakebin/cargo-mutants" "$fake/"
    # A PATH with every directory that holds cargo-nextest taken out.
    clean_path="$(python3 -c 'import os; print(":".join(d for d in os.environ["PATH"].split(":") if not os.path.exists(os.path.join(d, "cargo-nextest"))))')"
    (cd "$repo" && PATH="$fake:$clean_path" bash scripts/metrics/run.sh mutants main --out "$repo/.scratch/nonextest" >/dev/null 2>"$tmp/nonextest.err") || status=$?
    [ "$status" -eq 3 ] && ok "mutants mode without cargo-nextest exits 3, not 0" || bad "mutants mode without nextest exit $status"
    [ "$(py "$snap" "s['run']['not_measured'].get('mutants', '').startswith('cargo-nextest not installed')")" = "True" ] \
        && ok "the snapshot names the missing tool" || bad "not_measured: $(py "$snap" "s['run']['not_measured']")"
}

failed_gate_outranks_incomplete_in_grading() {   # exit 2 wins over 3 in gate/diff
    # A copy of the throwaway repo whose metadata carries a forbidden edge
    # (common -> graph fails ceiling:layers.unexcepted) and whose tokei
    # falls over (size FAILED, so the snapshot is incomplete).
    mutants_repo
    local repo="$tmp/mut-exit" fake="$tmp/exit-fakebin"
    rm -rf "$repo"; cp -r "$tmp/mut" "$repo"; mkdir -p "$fake"
    cp "$data/small-layers.toml" "$repo/metrics/layers.toml"
    python3 - "$data/small-metadata.json" "$tmp/exit-meta.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
next(p for p in m["packages"] if p["name"] == "common")["dependencies"].append({"name": "graph", "kind": None})
json.dump(m, open(sys.argv[2], "w"))
PY
    printf '#!/bin/sh\ncase "$1" in metadata) cat "%s" ;; *) exit 1 ;; esac\n' "$tmp/exit-meta.json" > "$fake/cargo"
    printf '#!/bin/sh\n[ "$1" = "--version" ] && { echo "tokei 15.0.0"; exit 0; }\necho broken >&2; exit 1\n' > "$fake/tokei"
    chmod +x "$fake/cargo" "$fake/tokei"
    local status=0 out
    out="$(cd "$repo" && PATH="$fake:$PATH" bash scripts/metrics/run.sh gate main --out "$repo/.scratch/exit" 2>"$tmp/exit.err")" || status=$?
    grep -q 'size FAILED' "$tmp/exit.err" && ok "the fixture loses a collector" || { bad "tokei did not fail: $(tail -n3 "$tmp/exit.err")"; return; }
    printf '%s\n' "$out" | tail -n1 | grep -q '^quality-gate: fail ' && ok "the fixture fails a gate" || { bad "verdict: $(printf '%s\n' "$out" | tail -n1)"; return; }
    [ "$status" -eq 2 ] && ok "a failed gate exits 2 even when the snapshot is incomplete" || bad "exit $status with a failed gate and a lost collector"
}

crap_counts_over_threshold() {   # CRAP per crate against [crap] threshold
    local out="$tmp/crap"
    run_collect "$out" "${standard[@]}" --crap "$data/crap.json" >/dev/null 2>&1 || true
    local snap="$out/snapshot.json"
    [ -f "$snap" ] || { bad "no snapshot with --crap"; return; }
    # graph: 48.2 and 31.5 are over; 30.0 is the threshold itself; tests/it.rs is excluded.
    [ "$(py "$snap" "s['crates']['graph']['crap']")" = "{'functions': 4, 'max': 48.2, 'over_threshold': 2}" ] \
        && ok "graph: strictly over the threshold counts; the threshold itself and test sources do not" \
        || bad "graph crap: $(py "$snap" "s['crates']['graph']['crap']")"
    [ "$(py "$snap" "s['crates']['decode']['crap']")" = "{'functions': 2, 'max': 12.0, 'over_threshold': 0}" ] \
        && ok "decode: functions counted, none over" || bad "decode crap"
    [ "$(py "$snap" "s['crates']['common']['crap']")" = "{'functions': 0, 'max': 0.0, 'over_threshold': 0}" ] \
        && ok "a crate in scope with no functions reported is zeros, not null" || bad "common crap"
    [ "$(py "$snap" "s['workspace']['crap']")" = "{'functions': 6, 'max': 48.2, 'over_threshold': 2, 'threshold': 30.0}" ] \
        && ok "the workspace sums the crates and records the threshold" || bad "workspace crap: $(py "$snap" "s['workspace']['crap']")"
    [ "$(py "$snap" "(s['gates']['ratchet:crap.over_threshold']['value'], s['gates']['ratchet:crap.over_threshold']['result'])")" = "(2, 'not_evaluated')" ] \
        && ok "the ratchet reads the count and waits for a baseline" || bad "crap ratchet"
    python3 - "$snap" "$tmp/crap-base.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); s["workspace"]["crap"]["over_threshold"] = 1
json.dump(s, open(sys.argv[2], "w"))
PY
    run_collect "$tmp/crap2" "${standard[@]}" --crap "$data/crap.json" --baseline "$tmp/crap-base.json" >/dev/null 2>&1 || true
    [ "$(py "$tmp/crap2/snapshot.json" "s['gates']['ratchet:crap.over_threshold']['result']")" = "fail" ] \
        && ok "one more function over the threshold than the baseline fails the ratchet" || bad "crap ratchet against baseline"
}

publish_targets_history_ref_only() {   # QM-014: the publish script pushes to the history branch and never to main
    local remote="$tmp/pub-remote" repo="$tmp/pub-repo"
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x
    git -c init.templateDir= init -q --bare "$remote" 2>/dev/null
    git -c init.templateDir= init -q "$repo" 2>/dev/null
    mkdir -p "$repo/scripts/metrics"
    cp "$here/metrics/publish-snapshot.sh" "$here/metrics/prune.py" "$repo/scripts/metrics/"
    echo "main" > "$repo/README.md"
    git -C "$repo" add -A && git -C "$repo" commit -q -m "main" && git -C "$repo" branch -M main
    git -C "$repo" remote add origin "$remote" && git -C "$repo" push -q origin main
    local main_before; main_before="$(git -C "$remote" rev-parse main)"
    # A full, clean snapshot out of the fixture set, of the checkout's own
    # commit, date fixed.
    local head7; head7="$(git -C "$repo" rev-parse HEAD | cut -c1-7)"
    python3 - "$data/history" "$tmp/pub-snap.json" "$head7" <<'PY'
import json, sys, glob
s = json.load(open(sorted(glob.glob(sys.argv[1] + "/*.json"))[-1]))
s["run"]["mode"] = "full"; s["git"]["dirty"] = False; s["git"]["sha7"] = sys.argv[3]
json.dump(s, open(sys.argv[2], "w"))
PY
    local status=0
    (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-snap.json" --date 2026-10-14 >"$tmp/pub.out" 2>&1) || status=$?
    [ "$status" -eq 0 ] && ok "first publish creates the orphan branch and pushes" || bad "publish exit $status: $(cat "$tmp/pub.out")"
    git -C "$remote" rev-parse --verify -q refs/heads/metrics-data >/dev/null && ok "metrics-data exists on the remote" || bad "no metrics-data on the remote"
    [ "$(git -C "$remote" rev-parse main)" = "$main_before" ] && ok "main on the remote is untouched" || bad "main moved"
    [ "$(git -C "$remote" rev-list --count metrics-data)" = "1" ] && ok "the data branch is an orphan with one commit" || bad "data branch history: $(git -C "$remote" rev-list --count metrics-data)"
    git -C "$remote" ls-tree --name-only -r metrics-data | grep -qx "history/2026-10-14-$head7.json" && ok "the snapshot is named by date and sha7 under history/" || bad "tree: $(git -C "$remote" ls-tree --name-only -r metrics-data)"
    [ "$(git -C "$repo" rev-parse --abbrev-ref HEAD)" = "main" ] && [ -z "$(git -C "$repo" status --porcelain)" ] && ok "the working checkout is left on its branch, clean" || bad "working checkout disturbed"
    # Second publish appends; same snapshot twice is a no-op.
    status=0
    (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-snap.json" --date 2026-10-15 >/dev/null 2>&1) || status=$?
    [ "$(git -C "$remote" rev-list --count metrics-data)" = "2" ] && ok "a second publish appends one commit" || bad "second publish"
    (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-snap.json" --date 2026-10-15 >"$tmp/pub2.out" 2>&1) || status=$?
    grep -q "nothing to publish" "$tmp/pub2.out" && ok "the same snapshot again is a no-op" || bad "repeat publish: $(cat "$tmp/pub2.out")"
    # Refusals: a darwin run and a dirty tree are not history.
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["run"]["mode"]="darwin"; json.dump(s,open(sys.argv[2],"w"))' "$tmp/pub-snap.json" "$tmp/pub-darwin.json"
    status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-darwin.json" >/dev/null 2>&1) || status=$?
    [ "$status" -eq 2 ] && ok "a darwin snapshot is refused" || bad "darwin snapshot exit $status"
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["git"]["dirty"]=True; json.dump(s,open(sys.argv[2],"w"))' "$tmp/pub-snap.json" "$tmp/pub-dirty.json"
    status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-dirty.json" >/dev/null 2>&1) || status=$?
    [ "$status" -eq 2 ] && ok "a dirty-tree snapshot is refused" || bad "dirty snapshot exit $status"
    # The artifact is untrusted: a field that would leave history/ is refused
    # before anything is written, and so is a dirty flag that is not a boolean.
    local bad_sha before_tree
    before_tree="$(git -C "$remote" rev-parse metrics-data)"
    for bad_sha in '../../x' 'ABC1234' 'abc123' 'abc1234/../../x' 'abc1234
'; do
        python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["git"]["sha7"]=sys.argv[3]; json.dump(s,open(sys.argv[2],"w"))' "$tmp/pub-snap.json" "$tmp/pub-badsha.json" "$bad_sha"
        status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-badsha.json" --date 2026-10-16 >"$tmp/pub-badsha.out" 2>&1) || status=$?
        [ "$status" -eq 2 ] && grep -q 'refusing git.sha7' "$tmp/pub-badsha.out" \
            && ok "a sha7 of $(printf '%q' "$bad_sha") is refused" || bad "sha7 $(printf '%q' "$bad_sha") exit $status: $(cat "$tmp/pub-badsha.out")"
    done
    # A well-formed sha7 of a commit this checkout is not on was not made by
    # this run's collector.
    local other7; other7="$([ "${head7:0:1}" = 0 ] && echo 1 || echo 0)${head7:1}"
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["git"]["sha7"]=sys.argv[3]; json.dump(s,open(sys.argv[2],"w"))' "$tmp/pub-snap.json" "$tmp/pub-othersha.json" "$other7"
    status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-othersha.json" --date 2026-10-16 >"$tmp/pub-othersha.out" 2>&1) || status=$?
    [ "$status" -eq 2 ] && grep -q 'this checkout is at' "$tmp/pub-othersha.out" \
        && ok "a snapshot of another commit is refused" || bad "other-commit sha7 exit $status: $(cat "$tmp/pub-othersha.out")"
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); s["git"]["dirty"]="false"; json.dump(s,open(sys.argv[2],"w"))' "$tmp/pub-snap.json" "$tmp/pub-strdirty.json"
    status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-strdirty.json" --date 2026-10-16 >/dev/null 2>&1) || status=$?
    [ "$status" -eq 2 ] && ok "a dirty flag that is not the boolean false is refused" || bad "string dirty exit $status"
    local bad_date
    for bad_date in '../2026-10-16' '2026-10-16/x' '2026-10-16
x' '2026-02-30' '2026-13-01'; do
        status=0; (cd "$repo" && bash scripts/metrics/publish-snapshot.sh "$tmp/pub-snap.json" --date "$bad_date" >/dev/null 2>&1) || status=$?
        [ "$status" -eq 2 ] && ok "a date of $(printf '%q' "$bad_date") is refused" || bad "date $(printf '%q' "$bad_date") exit $status"
    done
    [ "$(git -C "$remote" rev-parse metrics-data)" = "$before_tree" ] && ok "no refused snapshot reached metrics-data" || bad "a refused snapshot was pushed"
    [ ! -e "$tmp/x" ] && [ ! -e "$repo/x" ] && ok "nothing was written outside history/" || bad "a file escaped history/"
    [ "$(git -C "$remote" rev-parse main)" = "$main_before" ] && ok "main is still untouched after every publish" || bad "main moved later"
}

nightly_budget_is_declared() {   # QM-N02: the nightly job's wall clock is the spec's bound
    local wf="$root/.github/workflows/metrics.yml" nightly="$root/.github/workflows/nightly-tests.yml"
    [ -f "$wf" ] || { echo "skip - no metrics workflow in this tree"; return; }
    local budget
    budget="$(awk '/^  metrics:$/{p=1} p && /timeout-minutes:/{print $2; exit}' "$wf")"
    [ "$budget" = "120" ] && ok "the metrics job declares timeout-minutes 120" || bad "metrics job timeout: '$budget'"
    local collector publisher
    collector="$(awk '/^  metrics:$/{p=1} /^  publish:$/{p=0} p' "$wf")"
    publisher="$(awk '/^  publish:$/{p=1} p' "$wf")"
    printf '%s\n' "$collector" | grep -q 'continue-on-error: true' && ok "the job is non-blocking" || bad "metrics job blocks"
    awk '/^  metrics:$/{p=1} p' "$wf" | grep -q 'publish-snapshot.sh' && ok "the job publishes through the script" || bad "no publish step"
    # The collector runs untrusted code, so the write token lives only in
    # `publish`, which runs on main alone.
    ! printf '%s\n' "$collector" | grep -q 'contents: write' && ! printf '%s\n' "$collector" | grep -q 'persist-credentials: true' \
        && ok "the collector job holds no write token and persists none" || bad "the collector job can write"
    printf '%s\n' "$publisher" | grep -q 'contents: write' && printf '%s\n' "$publisher" | grep -q "github.ref == 'refs/heads/main'" \
        && printf '%s\n' "$publisher" | grep -q 'publish-snapshot.sh' \
        && ok "publish alone holds the write token, on main only" || bad "publish job shape"
    # The tools build from crates.io sources, and only main writes the
    # cache of them that every run restores.
    ! printf '%s\n' "$collector" | grep -q 'cargo-binstall@' \
        && ok "the collector installs its tools from source" || bad "the collector installs cargo-binstall"
    # Every save step, not just one: the line before each `uses:` is its `if:`.
    local saves guarded
    saves="$(printf '%s\n' "$collector" | grep -c 'actions/cache/save@')"
    guarded="$(printf '%s\n' "$collector" | awk '/actions\/cache\/save@/{print prev} {prev=$0}' | grep -c "github.ref == 'refs/heads/main'")"
    [ "$saves" -gt 0 ] && [ "$guarded" -eq "$saves" ] \
        && ok "every cache save in the collector runs on main only" || bad "cache saves: $saves, guarded to main: $guarded"
    grep -q '^  workflow_dispatch:' "$wf" && grep -q '^  workflow_call:' "$wf" && ok "the workflow runs alone and when called" || bad "metrics.yml lacks workflow_dispatch or workflow_call"
    [ -f "$nightly" ] || { echo "skip - no nightly workflow in this tree"; return; }
    awk '/^  metrics:$/{p=1} /^  notify:$/{p=0} p' "$nightly" | grep -q 'uses: ./.github/workflows/metrics.yml' && ok "the nightly calls metrics.yml" || bad "nightly-tests does not call metrics.yml"
    awk '/^  notify:$/{p=1} p' "$nightly" | grep -q 'needs:.*metrics' && bad "notify depends on metrics (it must not while non-blocking)" || ok "notify does not depend on metrics"
}

summary_is_appended_for_a_snapshot() {   # the nightly's glance: summary.md beside the snapshot, appended to the step summary
    local out="$tmp/summary" step="$tmp/step-summary.md"
    : > "$step"
    GITHUB_STEP_SUMMARY="$step" run_collect "$out" "${standard[@]}" --summary >/dev/null 2>&1 || true
    [ -f "$out/summary.md" ] && ok "summary.md is written beside the snapshot" || { bad "no summary.md"; return; }
    cmp -s "$out/summary.md" "$step" && ok "the same text is appended to GITHUB_STEP_SUMMARY" || bad "step summary differs from summary.md"
    grep -q '^Verdict: \*\*' "$out/summary.md" && ok "it carries the verdict" || bad "no verdict line"
    grep -q '`ceiling:modules.cycles`' "$out/summary.md" && ok "it carries every gate" || bad "gates table incomplete"
    grep -q '^| Strict lint hits | 4 |' "$out/summary.md" && ok "it carries the workspace totals" || bad "workspace totals missing"
    grep -q 'graph::builds' "$out/summary.md" && ok "it lists the module cycles" || bad "module cycles missing"
    grep -q '^- `clippy::mem_forget`' "$out/summary.md" && ok "it lists the promotable lints" || bad "promotable lints missing"
    run_collect "$tmp/summary2" "${standard[@]}" --summary >/dev/null 2>&1 || true
    cmp -s "$out/summary.md" "$tmp/summary2/summary.md" && ok "summary.md is byte-stable" || bad "summary.md differs between runs"
    run_collect "$tmp/nosummary" "${standard[@]}" >/dev/null 2>&1 || true
    [ ! -f "$tmp/nosummary/summary.md" ] && ok "without --summary nothing is written" || bad "summary.md written without the flag"
}

clippy_thresholds_agree() {   # thresholds.toml [clippy] mirrors every clippy.toml
    # Clippy reads only the nearest clippy.toml above a crate's manifest, so a
    # per-crate file must restate the thresholds or that crate falls back to
    # clippy's defaults.
    python3 - "$root" <<'PY'
import glob, sys, tomllib
root = sys.argv[1]
th = tomllib.load(open(f"{root}/metrics/thresholds.toml", "rb"))["clippy"]
for path in [f"{root}/clippy.toml", *sorted(glob.glob(f"{root}/crates/*/clippy.toml"))]:
    cl = tomllib.load(open(path, "rb"))
    for k, v in th.items():
        assert cl.get(k) == v, (path, k, cl.get(k), v)
PY
    [ $? -eq 0 ] && ok "every clippy.toml and metrics/thresholds.toml agree on the complexity thresholds" || bad "complexity thresholds disagree"
}

# ------------------------------------------------------- grading fixtures

# A throwaway repo for the grading cases. `main` holds the base thresholds;
# the checked-out `feature` branch loosens one gate, tightens another, edits
# two crates and leaves one file untracked; `metrics-data` carries one baseline
# snapshot, built with plumbing so the working tree is never touched. The head
# snapshot comes from collect.py over the standard fixtures, run inside the
# repo so its git block is the fixture's.
#
# Against the fixtures' numbers (coverage 54.29 %, strict total 4, graph
# coverage 60 %), the base's floor of 60 fails where the head's 50 would pass,
# and the head's tolerance of 0 fails the strict ratchet where the base's 1
# would warn: each side is stricter somewhere, so the report proves both
# directions of QM-009.
grade_repo="$tmp/grade"
grade_head="$tmp/grade-head"
make_grade_repo() {
    local repo="$grade_repo"
    mkdir -p "$repo/crates/graph/src" "$repo/crates/decode/src" "$repo/metrics"
    git -c init.templateDir= init -q -b main "$repo" 2>/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x
    seq 1 30 | sed 's/^/fn graph_/; s/$/() {}/' > "$repo/crates/graph/src/lib.rs"
    seq 1 80 | sed 's/^/fn decode_/; s/$/() {}/' > "$repo/crates/decode/src/lib.rs"
    cat > "$repo/metrics/thresholds.toml" <<'EOF'
schema = 1
[floors]
"coverage.lines_pct" = 60.0
[ceilings]
"clippy.workspace_lints" = 5
"layers.unexcepted" = 0
[ratchet]
"clippy.strict.total" = { direction = "down", tolerance = 1 }
[crates.graph.floors]
"coverage.lines_pct" = 70.0
EOF
    git -C "$repo" add -A && git -C "$repo" commit -q -m base
    git -C "$repo" checkout -q -b feature
    cat > "$repo/metrics/thresholds.toml" <<'EOF'
schema = 1
[floors]
"coverage.lines_pct" = 50.0
[ceilings]
"clippy.workspace_lints" = 0
"layers.unexcepted" = 0
[ratchet]
"clippy.strict.total" = { direction = "down", tolerance = 0 }
"coverage.lines_pct" = { direction = "up", tolerance = 0.25 }
EOF
    # graph line 10 carries a fixture unwrap_used hit; decode's hit is on line
    # 70, which stays untouched, so only graph gains a hit on a changed line.
    sed -i.bak '10s/.*/fn graph_10_edited() {}/' "$repo/crates/graph/src/lib.rs"
    sed -i.bak '1s/.*/fn decode_1_edited() {}/' "$repo/crates/decode/src/lib.rs"
    rm -f "$repo"/crates/*/src/*.bak
    git -C "$repo" add -A && git -C "$repo" commit -q -m feature
    echo "fn brand_new() {}" > "$repo/crates/decode/src/new.rs"

    (cd "$repo" && python3 "$collect" --out "$grade_head" --mode full --root "$repo" \
        --metadata "$data/small-metadata.json" --rules "$data/small-layers.toml" \
        --thresholds "$repo/metrics/thresholds.toml" --strict-lints "$data/strict-lints.txt" \
        --no-hotspots "${standard[@]}" >/dev/null 2>&1) || true

    # The baseline: the head snapshot as the base commit saw it, one strict
    # hit fewer in graph.
    local base_sha; base_sha="$(git -C "$repo" rev-parse main)"
    python3 - "$grade_head/snapshot.json" "$tmp/baseline.json" "$base_sha" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
s["git"] = {"sha": sys.argv[3], "sha7": sys.argv[3][:7], "ref": "main", "dirty": False}
s["workspace"]["clippy"]["strict_total"] = 3
s["crates"]["graph"]["clippy"]["strict_total"] = 2
json.dump(s, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
    local blob sub top commit
    blob="$(git -C "$repo" hash-object -w "$tmp/baseline.json")"
    sub="$(printf '100644 blob %s\t2026-10-01-%s.json\n' "$blob" "${base_sha:0:7}" | git -C "$repo" mktree)"
    top="$(printf '040000 tree %s\thistory\n' "$sub" | git -C "$repo" mktree)"
    commit="$(git -C "$repo" commit-tree "$top" -m baseline)"
    git -C "$repo" update-ref refs/heads/metrics-data "$commit"

    # What run.sh hands diff.py: the changed ranges from the shared library,
    # resolved the way clippy-strict.sh resolves them (no origin here, so the
    # local main is the fallback).
    # shellcheck disable=SC1091
    (cd "$repo" && . "$root/scripts/lib/changed-lines.sh" \
        && mb="$(changed_lines_base)" && changed_lines_diff "$mb" "$tmp/grade-changed.diff" \
        && changed_lines_untracked "$tmp/grade-untracked.txt")
}

# grade <out> [diff.py args...]: diff.py over the grading fixture.
grade() {
    local out="$1"; shift
    [ -d "$grade_repo" ] || make_grade_repo
    (cd "$grade_repo" && python3 "$diff" --head "$grade_head" --out "$out" --history-ref metrics-data \
        --changed "$tmp/grade-changed.diff" --untracked "$tmp/grade-untracked.txt" --repo fixture/repo "$@")
}

# ---------------------------------------------------------- grading cases

base_thresholds_win_when_stricter() {   # QM-009
    local out="$tmp/stricter" status=0
    grade "$out" >/dev/null 2>&1 || status=$?
    [ "$status" -eq 2 ] && ok "a change graded by the base's stricter floor exits 2" || bad "exit $status"
    local rep="$out/report.json"
    [ -f "$rep" ] || { bad "no report.json"; return; }
    [ "$(py "$rep" "s['gates']['floor:coverage.lines_pct']['threshold'], s['gates']['floor:coverage.lines_pct']['threshold_from']")" = "(60.0, 'base')" ] \
        && ok "the base's stricter floor is the effective threshold" || bad "floor: $(py "$rep" "s['gates']['floor:coverage.lines_pct']")"
    [ "$(py "$rep" "s['gates']['floor:coverage.lines_pct']['result']")" = "fail" ] \
        && ok "the head cannot loosen the floor it is graded by" || bad "loosened floor passed"
    [ "$(py "$rep" "s['gates']['ceiling:clippy.workspace_lints']['threshold'], s['gates']['ceiling:clippy.workspace_lints']['threshold_from']")" = "(0, 'head')" ] \
        && ok "the head's stricter ceiling wins the other way" || bad "ceiling: $(py "$rep" "s['gates']['ceiling:clippy.workspace_lints']")"
    [ "$(py "$rep" "s['gates']['ratchet:clippy.strict.total']['tolerance'], s['gates']['ratchet:clippy.strict.total']['result']")" = "(0, 'fail')" ] \
        && ok "the head's tighter ratchet tolerance wins and fails on one new hit" || bad "ratchet: $(py "$rep" "s['gates']['ratchet:clippy.strict.total']")"
    [ "$(py "$rep" "s['gates']['floor:crates.graph.coverage.lines_pct']['threshold_from'], s['gates']['floor:crates.graph.coverage.lines_pct']['result']")" = "('base', 'fail')" ] \
        && ok "a per-crate floor only the base declares is still graded" || bad "base-only crate floor"
    [ "$(py "$rep" "'ratchet:coverage.lines_pct' in s['gates']")" = "True" ] \
        && ok "a ratchet only the head declares is graded too" || bad "head-only ratchet missing"
    grep -q "(base)" "$out/report.md" && ok "the report marks a threshold the base set" || bad "no (base) marker in report.md"
    # The property: for all B, H, effective(B, H) is at least as strict as each and symmetric in its values.
    python3 - "$diff" <<'PY'
import importlib.util, random, sys
spec = importlib.util.spec_from_file_location("diff", sys.argv[1]); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
random.seed(9)
names = ["a", "b", "c", "d"]
def table():
    return {
        "floors": {n: random.choice([0.0, 25.0, 50.0, 75.0]) for n in random.sample(names, random.randint(0, 4))},
        "ceilings": {n: random.randint(0, 5) for n in random.sample(names, random.randint(0, 4))},
        "ratchet": {n: {"direction": "down", "tolerance": random.choice([0, 0.25, 1, 2])} for n in random.sample(names, random.randint(0, 4))},
        "crates": {c: {"floors": {n: random.choice([0.0, 40.0, 80.0]) for n in random.sample(names, random.randint(0, 2))}} for c in random.sample(["x", "y"], random.randint(0, 2))},
    }
for _ in range(200):
    b, h = table(), table()
    e, _src = m.stricter(b, h)
    e2, _ = m.stricter(h, b)
    assert e["floors"] == e2["floors"] and e["ceilings"] == e2["ceilings"]
    assert {k: v["tolerance"] for k, v in e["ratchet"].items()} == {k: v["tolerance"] for k, v in e2["ratchet"].items()}
    for side in (b, h):
        for n, v in side["floors"].items():
            assert e["floors"][n] >= v
        for n, v in side["ceilings"].items():
            assert e["ceilings"][n] <= v
        for n, v in side["ratchet"].items():
            assert e["ratchet"][n]["tolerance"] <= v["tolerance"]
        for c, t in side["crates"].items():
            for n, v in t["floors"].items():
                assert e["crates"][c]["floors"][n] >= v
print("ok")
PY
    [ $? -eq 0 ] && ok "effective(B, H) is at least as strict as B and as H over two hundred random pairs" || bad "stricter property"
}

no_baseline_means_not_evaluated() {   # QM-009 failure clause
    local out="$tmp/nobase" status=0
    grade "$out" --history-ref no-such-ref >/dev/null 2>&1 || status=$?
    local rep="$out/report.json"
    [ -f "$rep" ] || { bad "no report.json without a baseline (exit $status)"; return; }
    [ "$(py "$rep" "s['baseline']")" = "None" ] && ok "baseline is null" || bad "baseline not null"
    [ "$(py "$rep" "sorted(set(g['result'] for g in s['gates'].values() if g['kind'] == 'ratchet'))")" = "['not_evaluated']" ] \
        && ok "every ratchet is not_evaluated" || bad "a ratchet was evaluated without a baseline"
    grep -q "Every ratchet gate is not evaluated" "$out/report.md" && ok "the report says so" || bad "report.md silent about the missing baseline"
    grep -q "no-such-ref" "$out/report.md" && ok "the report names the history ref it looked at" || bad "history ref not named"
}

report_carries_every_section() {   # QM-010
    local out="$tmp/sections"
    grade "$out" >/dev/null 2>&1 || true
    local md="$out/report.md" rep="$out/report.json"
    [ -f "$md" ] && [ -f "$rep" ] || { bad "report files missing"; return; }
    local heading missing=""
    for heading in "### Gates" "### Changed crates" "### New strict hits on changed lines" "### Promotable strict lints" "### Not measured in this mode" "### Scope"; do
        grep -qF "$heading" "$md" || missing="$missing '$heading'"
    done
    [ -z "$missing" ] && ok "every section heading is present" || bad "missing headings:$missing"
    grep -q '^Verdict: \*\*fail\*\*$' "$md" && ok "the verdict line is bold and matches the gates" || bad "verdict line"
    local head7 base7
    head7="$(git -C "$grade_repo" rev-parse --short=7 HEAD)"; base7="$(git -C "$grade_repo" rev-parse --short=7 main)"
    grep -q "Head \`$head7\` graded against base \`main\` (\`$base7\`" "$md" && ok "head and base commits are named" || bad "head/base commits"
    grep -q "Baseline: \`2026-10-01-$base7.json\` (\`$base7\`, 1 commit(s) behind head)" "$md" \
        && ok "the baseline's name and age are named" || bad "baseline name/age: $(grep Baseline "$md")"
    python3 - "$rep" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
need = ["schema_version", "kind", "repo", "head_sha", "base_sha", "merge_base", "baseline", "pr", "verdict", "gates",
        "changed_crates", "new_strict_hits", "promotable", "not_measured", "scope_uncovered"]
missing = [k for k in need if k not in s]
assert not missing, missing
assert s["schema_version"] == 1 and s["kind"] == "report" and s["pr"] is None and s["repo"] == "fixture/repo"
assert s["baseline"]["age_commits"] == 1 and s["baseline"]["name"].endswith(".json")
for g in s["gates"].values():
    assert "value" in g and "result" in g and "threshold" in g
    if g["kind"] == "ratchet":
        assert "baseline" in g
print("ok")
PY
    [ $? -eq 0 ] && ok "report.json carries every key and every gate row has value, baseline, threshold and result" || bad "report.json keys"
    [ "$(py "$rep" "[(r['crate'], r['new_strict_hits'], r['strict_total'], r['strict_total_base']) for r in s['changed_crates']]")" = "[('decode', 0, 1, 1), ('graph', 1, 3, 2)]" ] \
        && ok "changed crates carry new hits and deltas against the baseline" || bad "changed crates: $(py "$rep" "s['changed_crates']")"
    [ "$(py "$rep" "[(h['path'], h['line'], h['code']) for h in s['new_strict_hits']]")" = "[('crates/graph/src/lib.rs', 10, 'clippy::unwrap_used')]" ] \
        && ok "only the strict hit on a changed line is new; the untouched one on line 22 is not" || bad "new hits: $(py "$rep" "s['new_strict_hits']")"
    grep -q '^- `crates/graph/src/lib.rs:10` \[clippy::unwrap_used\]$' "$md" && ok "the hit is listed as path:line [code]" || bad "hit list format"
    [ "$(py "$rep" "s['promotable']")" = "['clippy::mem_forget']" ] && ok "promotable lints are carried" || bad "promotable"
    [ "$(py "$rep" "s['not_measured']")" = "{'hotspots': 'disabled'}" ] && ok "collectors that did not run are listed" || bad "not_measured: $(py "$rep" "s['not_measured']")"
}

step_summary_is_appended() {   # QM-011
    local summary="$tmp/step-summary.md"
    printf 'prior content\n' > "$summary"
    (cd "$grade_repo" && GITHUB_STEP_SUMMARY="$summary" python3 "$diff" --head "$grade_head" --out "$tmp/summary-out" \
        --history-ref metrics-data --changed "$tmp/grade-changed.diff" --untracked "$tmp/grade-untracked.txt" >/dev/null 2>&1) || true
    [ "$(head -n1 "$summary")" = "prior content" ] && ok "existing content is kept" || bad "summary overwritten"
    grep -q '^# Quality report' "$summary" && ok "the Markdown report is appended" || bad "report not appended"
    cmp -s <(tail -n +2 "$summary") "$tmp/summary-out/report.md" && ok "appended bytes are report.md" || bad "appended content differs from report.md"
    local status=0
    (cd "$grade_repo" && GITHUB_STEP_SUMMARY="$tmp/no-such-dir/summary.md" python3 "$diff" --head "$grade_head" --out "$tmp/summary-out2" \
        --history-ref metrics-data --changed "$tmp/grade-changed.diff" --untracked "$tmp/grade-untracked.txt" >/dev/null 2>&1) || status=$?
    [ "$status" -eq 2 ] && [ -f "$tmp/summary-out2/report.md" ] && ok "an unwritable summary path does not stop the report" || bad "unwritable summary: exit $status"
    (cd "$grade_repo" && env -u GITHUB_STEP_SUMMARY python3 "$diff" --head "$grade_head" --out "$tmp/summary-out3" \
        --history-ref metrics-data --changed "$tmp/grade-changed.diff" --untracked "$tmp/grade-untracked.txt" >/dev/null 2>&1) || true
    cmp -s "$tmp/summary-out/report.md" "$tmp/summary-out3/report.md" && ok "the summary variable does not change the report" || bad "report differs with the variable set"
}

# The real tree, not a fixture: `run.sh gate` needs `cargo metadata` over a
# workspace. A checkout without origin/main or main (a shallow CI clone) gets
# HEAD as the base, so the case still proves what it is about.
gate_base_arg() {
    if git -C "$root" rev-parse -q --verify origin/main >/dev/null 2>&1 || git -C "$root" rev-parse -q --verify main >/dev/null 2>&1; then
        printf ''
    else
        printf 'HEAD'
    fi
}

gate_runs_without_rustc() {   # QM-012
    command -v cargo >/dev/null 2>&1 || { echo "skip - cargo not on PATH; the gate needs cargo metadata"; return; }
    # rustc and cargo-clippy exit 99 and log every call; cargo itself is real,
    # so `cargo metadata --no-deps` still reads the manifests.
    local fake="$tmp/norustc"; mkdir -p "$fake"
    printf '#!/bin/sh\necho "$0 $*" >> "%s/invoked.log"\nexit 99\n' "$fake" > "$fake/rustc"
    cp "$fake/rustc" "$fake/cargo-clippy"; chmod +x "$fake/rustc" "$fake/cargo-clippy"
    local status=0 out
    out="$(cd "$root" && PATH="$fake:$PATH" bash "$here/metrics/run.sh" gate "$(gate_base_arg)" --out "$tmp/gate-norustc" 2>"$tmp/gate-norustc.err")" || status=$?
    [ "$status" -eq 0 ] && ok "the gate exits 0 with rustc and cargo-clippy unusable" || bad "gate exit $status: $(tail -n3 "$tmp/gate-norustc.err")"
    [ ! -s "$fake/invoked.log" ] && ok "neither rustc nor cargo-clippy was invoked" || bad "compiler invoked: $(cat "$fake/invoked.log")"
    local last; last="$(printf '%s\n' "$out" | tail -n1)"
    if printf '%s' "$last" | grep -qE '^quality-gate: (pass|warn|fail) report=.+ sha256=[0-9a-f]{64}$'; then
        ok "stdout ends with the verdict, the report path and its sha256"
    else
        bad "last line: $last"; return
    fi
    local path digest
    path="$(printf '%s' "$last" | sed 's/.* report=\(.*\) sha256=.*/\1/')"
    digest="$(printf '%s' "$last" | sed 's/.* sha256=//')"
    case "$path" in /*) ;; *) path="$root/$path" ;; esac
    [ "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$path")" = "$digest" ] \
        && ok "the sha256 is report.json's" || bad "sha256 mismatch"
    [ "$(py "$tmp/gate-norustc/snapshot.json" "s['run']['mode']")" = "gate" ] && ok "the snapshot records gate mode" || bad "mode"
    [ "$(py "$tmp/gate-norustc/snapshot.json" "sorted(k for k in s['run']['not_measured'] if k in ('clippy','coverage','deps','modules'))")" = "['clippy', 'coverage', 'deps', 'modules']" ] \
        && ok "the compiling collectors and cargo-shear are recorded as not measured" || bad "not_measured: $(py "$tmp/gate-norustc/snapshot.json" "s['run']['not_measured']")"
}

darwin_scope_lists_uncovered_crates_in_report() {   # QM-013: the report side
    [ -d "$grade_repo" ] || make_grade_repo
    printf 'graph\n' > "$tmp/scope-graph-only.txt"
    local head="$tmp/darwin-head"
    (cd "$grade_repo" && python3 "$collect" --out "$head" --mode darwin --root "$grade_repo" \
        --metadata "$data/small-metadata.json" --rules "$data/small-layers.toml" \
        --thresholds "$grade_repo/metrics/thresholds.toml" --strict-lints "$data/strict-lints.txt" \
        --no-hotspots --scope "$tmp/scope-graph-only.txt" --clippy "$data/clippy.json" --coverage "$data/llvm-cov.json" \
        --tokei "$data/tokei.json" --modules "$data/modules.jsonl" --shear "$data/shear.json" >/dev/null 2>&1) || true
    local out="$tmp/darwin-report"
    (cd "$grade_repo" && python3 "$diff" --head "$head" --out "$out" --history-ref metrics-data \
        --changed "$tmp/grade-changed.diff" --untracked "$tmp/grade-untracked.txt" >/dev/null 2>&1) || true
    [ -f "$out/report.json" ] || { bad "no darwin report"; return; }
    [ "$(py "$out/report.json" "s['scope_uncovered']")" = "['decode']" ] \
        && ok "the changed crate the pinned scope left out is listed" || bad "scope_uncovered: $(py "$out/report.json" "s['scope_uncovered']")"
    grep -A3 '^### Scope' "$out/report.md" | grep -q 'scoped to `graph`' && ok "the report names the pinned scope" || bad "scope not named"
    grep -q '^- `decode`$' "$out/report.md" && ok "the report lists decode under Scope" || bad "decode not listed"
    [ "$(py "$out/report.json" "[r['new_strict_hits'] for r in s['changed_crates'] if r['crate']=='decode']")" = "[None]" ] \
        && ok "an uncovered crate's strict hits read as not measured, not zero" || bad "uncovered crate hits"
    [ "$(py "$out/report.json" "s['promotable']")" = "None" ] && ok "no promotable list from a partial scope" || bad "promotable from partial scope"
    # The ratchets compare the scope's crates on both sides rather than the
    # scope's sum against the whole baseline.
    [ "$(py "$out/report.json" "s['gates']['ratchet:clippy.strict.total']['scoped'], s['gates']['ratchet:clippy.strict.total']['baseline']")" = "(True, 2)" ] \
        && ok "a scoped ratchet re-sums the baseline over the same crates" || bad "scoped ratchet: $(py "$out/report.json" "s['gates']['ratchet:clippy.strict.total']")"
}

gate_fits_probe_budget() {   # QM-N01
    command -v cargo >/dev/null 2>&1 || { echo "skip - cargo not on PATH; the gate needs cargo metadata"; return; }
    local status=0 start elapsed
    start="$(date +%s)"
    (cd "$root" && bash "$here/metrics/run.sh" gate "$(gate_base_arg)" --out "$tmp/gate-budget" > "$tmp/gate-budget.out" 2>&1) || status=$?
    elapsed=$(( $(date +%s) - start ))
    [ "$elapsed" -lt 300 ] && ok "the gate over the real tree took ${elapsed}s, inside the 300 s probe budget" || bad "gate took ${elapsed}s"
    [ "$status" -ne 1 ] && ok "the gate wrote its report (exit $status)" || bad "gate crashed: $(tail -n3 "$tmp/gate-budget.out")"
    tail -n1 "$tmp/gate-budget.out" | grep -q '^quality-gate: ' && ok "the evidence line is last on stdout" || bad "no evidence line"
}

clippy_strict_unchanged() {   # the refactor onto changed-lines.sh keeps the gate's contract
    local repo="$tmp/strict"; mkdir -p "$repo/crates/graph/src"
    git -c init.templateDir= init -q -b main "$repo" 2>/dev/null
    export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@x GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@x
    seq 1 30 | sed 's/^/fn graph_/; s/$/() {}/' > "$repo/crates/graph/src/lib.rs"
    git -C "$repo" add -A && git -C "$repo" commit -q -m base
    git -C "$repo" checkout -q -b feature
    sed -i.bak '10s/.*/fn graph_10_edited() {}/' "$repo/crates/graph/src/lib.rs"; rm -f "$repo/crates/graph/src/lib.rs.bak"
    git -C "$repo" add -A && git -C "$repo" commit -q -m feature
    # A cargo that answers `cargo clippy` with a canned diagnostic stream.
    local fake="$tmp/strict-bin"; mkdir -p "$fake"
    cat > "$fake/cargo" <<'EOF'
#!/bin/sh
case "$1" in clippy) cat "$CANNED"; exit 0 ;; esac
echo "fake cargo: unexpected $*" >&2; exit 9
EOF
    chmod +x "$fake/cargo"
    canned() {   # canned <file> <line>
        python3 - "$1" "$2" <<'PY'
import json, sys
msg = {"reason": "compiler-message", "message": {"level": "warning", "code": {"code": "clippy::unwrap_used"}, "message": "used `unwrap()` on a `Result`",
       "spans": [{"file_name": "crates/graph/src/lib.rs", "line_start": int(sys.argv[2]), "is_primary": True}]}}
open(sys.argv[1], "w").write(json.dumps(msg) + "\n" + json.dumps({"reason": "build-finished", "success": True}) + "\n")
PY
    }
    local status=0 out
    canned "$tmp/canned-hit.json" 10
    out="$(cd "$repo" && CANNED="$tmp/canned-hit.json" PATH="$fake:$PATH" bash "$root/scripts/clippy-strict.sh" 2>"$tmp/strict-hit.err")" || status=$?
    [ "$status" -eq 2 ] && ok "a strict hit on a changed line exits 2" || bad "hit exit $status: $(cat "$tmp/strict-hit.err")"
    printf '%s\n' "$out" | grep -q '^crates/graph/src/lib.rs:10: used `unwrap()` on a `Result` \[clippy::unwrap_used\]$' \
        && ok "the hit is printed as path:line: message [code]" || bad "hit output: $out"
    grep -q 'diagnostic(s) on the lines your branch changed' "$tmp/strict-hit.err" && ok "the guidance follows on stderr" || bad "no guidance"
    grep -q '^clippy-strict: scope -p graph$' "$tmp/strict-hit.err" && ok "the scope is derived from the changed crate" || bad "scope: $(grep scope "$tmp/strict-hit.err")"
    status=0
    canned "$tmp/canned-clean.json" 22
    out="$(cd "$repo" && CANNED="$tmp/canned-clean.json" PATH="$fake:$PATH" bash "$root/scripts/clippy-strict.sh" 2>/dev/null)" || status=$?
    [ "$status" -eq 0 ] && [ "$out" = "clippy-strict: clean" ] && ok "a hit on an unchanged line is clean, exit 0" || bad "clean: exit $status, '$out'"
    status=0
    out="$(cd "$repo" && CANNED="$tmp/canned-hit.json" PATH="$fake:$PATH" bash "$root/scripts/clippy-strict.sh" HEAD 2>/dev/null)" || status=$?
    [ "$status" -eq 0 ] && printf '%s' "$out" | grep -q '^clippy-strict: no Rust changes since ' && ok "no changes since BASE exits 0 before cargo runs" || bad "no-change: exit $status, '$out'"
    # The pinned-scope message names what the scope leaves out, as before.
    status=0
    (cd "$repo" && CANNED="$tmp/canned-clean.json" PATH="$fake:$PATH" bash "$root/scripts/clippy-strict.sh" "" -p other >/dev/null 2>"$tmp/strict-pinned.err") || status=$?
    grep -q 'changed crates not covered here: graph' "$tmp/strict-pinned.err" && ok "a pinned scope says which changed crate it leaves out" || bad "pinned: $(cat "$tmp/strict-pinned.err")"
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
    non_member_packages_are_not_crates
    edges_match_by_package_not_name
    unassigned_crate_fails
    hotspots_rank_churn_times_findings
    hotspots_without_coverage
    module_cycles_from_dot
    darwin_scope_lists_uncovered_crates
    prune_keeps_daily_then_monthly
    newest_snapshot_orders_a_day_by_commit
    dashboard_renders_offline_with_tables
    mutants_scope_follows_mode
    untracked_file_is_listed
    truncated_junit_keeps_the_snapshot
    failed_gate_outranks_incomplete_in_grading
    missing_nextest_fails_mutants_mode
    crap_counts_over_threshold
    publish_targets_history_ref_only
    nightly_budget_is_declared
    clippy_thresholds_agree
    base_thresholds_win_when_stricter
    no_baseline_means_not_evaluated
    report_carries_every_section
    step_summary_is_appended
    gate_runs_without_rustc
    darwin_scope_lists_uncovered_crates_in_report
    gate_fits_probe_budget
    clippy_strict_unchanged
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
