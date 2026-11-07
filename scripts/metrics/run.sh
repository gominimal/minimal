#!/usr/bin/env bash
# Architectural-health snapshot: run the collectors, hand their output to
# collect.py, and in the grading modes grade the result with diff.py (spec 31).
#
# Usage: scripts/metrics/run.sh MODE [BASE] [OPTIONS] [-p CRATE ...]
#
#   MODE      full    every collector; the nightly run and `just metrics`
#             static  no compiler: layers, size, unused deps, hotspots from
#                     history. What a cold sandbox can afford.
#             gate    grade the change without a compiler: layers, size and
#                     hotspots, then the report against the base ref. The
#                     review runtime's probe and the tail of `agent-verify`
#                     (.minimal/minimal.toml); QM-012.
#             diff    gate plus clippy over the crates the change touched;
#                     `just metrics-diff`. --coverage adds llvm-cov over the
#                     same crates.
#             mutants [BASE]
#                     the static collectors plus cargo-mutants over the lines
#                     changed since the merge-base with BASE (default
#                     origin/main). Linux only (QM-017).
#   BASE              gate, diff and mutants: the ref to grade against. Empty
#                     or absent means the merge-base with origin/main (then
#                     main), the rule scripts/clippy-strict.sh follows.
#   --out DIR         where snapshot.json, clippy-hits.json, meta.json and (in
#                     the grading modes) report.md, report.json land
#                     (default .scratch/metrics/<mode>)
#   --history-ref REF gate and diff: the ref holding history/*.json baselines
#                     (default origin/metrics-data)
#   --coverage        diff: run llvm-cov over the scope too
#   --since REF       full: mutation-test the lines changed since REF (default
#                     `auto`: the newest snapshot in --history, else the
#                     merge-base with origin/main); MINIMAL_METRICS_MUTANTS_BUDGET_SECS
#                     caps the run (default 2700)
#   --history DIR     full: where the history snapshots are (default
#                     .scratch/metrics/history, what the nightly fetches)
#   --no-coverage, --no-modules, --no-clippy, --no-hotspots, --no-experimental, --no-mutants
#                     skip one collector; it is recorded as not measured
#   -p CRATE          pin the compiling collectors to these crates (the
#                     justfile does this on macOS); repeatable
#
# The experimental step (full mode only) runs rustqual per crate and
# cargo-anatomy once when they are on PATH. What they measure is recorded and
# read by no gate (QM-005), so neither can fail the run; a missing tool is a
# skip, a tool that falls over on one crate leaves an error in that crate's
# block.
#
# Every collector that cannot run is recorded in the snapshot as not measured
# with its reason, and the run still writes the snapshot (QM-001). Exit codes:
#   0  snapshot written, verdict pass or warn
#   2  snapshot written, verdict fail (in the grading modes: the report's)
#   3  snapshot written, but a collector could not run (read it as incomplete)
#   1  nothing written: a crash, or no python3
# When both 2 and 3 apply, the grading modes exit 2 (the change failed on
# what was measured) and the other modes exit 3 (the nightly publishes only
# a complete snapshot, and keys that on 3).
# None of the non-zero ones is ever read as clean.
#
# The grading modes end stdout with one line the review runtime records as
# evidence, whatever the exit code:
#   quality-gate: <verdict> report=<path to report.json> sha256=<hex>
# report.json carries no times, so the hash identifies what was measured.
#
# Gate mode runs nothing that reaches rustc: `cargo metadata --no-deps` reads
# the manifests alone, but cargo-shear resolves the whole dependency graph,
# and that probes `rustc -vV` and may need the registry, so the gate records
# unused deps as not measured and leaves them to diff and full.
#
# Tool versions are read from the binaries and recorded, so the snapshot says
# what measured it; install-tools.sh holds the pins. Only the tools a mode runs
# are probed: asking clippy for its version already runs rustc.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
here="scripts/metrics"
mode="${1:-}"
case "$mode" in
    full|static|gate|diff|mutants) shift ;;
    "") echo "usage: $0 full|static|gate|diff|mutants [BASE] [--out DIR] [--history-ref REF] [--coverage] [--no-coverage] [--no-modules] [--no-clippy] [--no-hotspots] [--no-experimental] [--no-mutants] [--since REF] [--history DIR] [-p CRATE]..." >&2; exit 1 ;;
    *) echo "metrics: unknown mode '$mode'" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "metrics: python3 is required" >&2; exit 127; }

grading=0
case "$mode" in gate|diff) grading=1 ;; esac
if [ "$mode" = "mutants" ] && [ "$(uname -s)" = "Darwin" ]; then
    # cargo-mutants runs the baseline suite before any mutant and stops when
    # it fails; the suite is green only on Linux (.minimal/minimal.toml).
    echo "metrics: mutants mode needs Linux: cargo-mutants wants the baseline suite green, and it is green only there" >&2
    exit 1
fi

# The grading modes and mutants take an optional positional BASE first. The
# justfile passes it quoted, so it may be the empty string; an option is never
# a base.
base=""
if { [ "$grading" -eq 1 ] || [ "$mode" = "mutants" ]; } && [ "$#" -gt 0 ]; then
    case "$1" in
        -*) ;;
        *) base="$1"; shift ;;
    esac
fi

out=".scratch/metrics/$mode"
history_ref="origin/metrics-data"
# full mode's mutants: the reference commit (`auto`: newest history snapshot,
# then the merge-base with origin/main) and the wall-clock budget.
mutants_since="auto"
history_dir=".scratch/metrics/history"
mutants_budget="${MINIMAL_METRICS_MUTANTS_BUDGET_SECS:-2700}"
want_coverage=1 want_modules=1 want_clippy=1 want_hotspots=1 want_deps=1 want_experimental=1 want_mutants=1
opt_coverage=0
scope=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --history-ref) history_ref="$2"; shift 2 ;;
        --coverage) opt_coverage=1; shift ;;
        --no-coverage) want_coverage=0; shift ;;
        --no-modules) want_modules=0; shift ;;
        --no-clippy) want_clippy=0; shift ;;
        --no-hotspots) want_hotspots=0; shift ;;
        --no-experimental) want_experimental=0; shift ;;
        --no-mutants) want_mutants=0; shift ;;
        --since) mutants_since="$2"; shift 2 ;;
        --history) history_dir="$2"; shift 2 ;;
        -p) scope+=("$2"); shift 2 ;;
        -p*) scope+=("${1#-p}"); shift ;;
        *) echo "metrics: unknown argument '$1'" >&2; exit 1 ;;
    esac
done
case "$mode" in
    static) want_coverage=0 want_modules=0 want_clippy=0 want_experimental=0 want_mutants=0 ;;
    gate)   want_coverage=0 want_modules=0 want_clippy=0 want_deps=0 want_experimental=0 want_mutants=0 ;;
    diff)   want_modules=0 want_experimental=0 want_mutants=0; [ "$opt_coverage" -eq 1 ] || want_coverage=0 ;;
    mutants) want_coverage=0 want_modules=0 want_clippy=0 want_experimental=0 ;;
esac

work="$out/raw"
mkdir -p "$work"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
export CARGO_TERM_COLOR=never

collect_args=()
not_measured=()   # collector=reason
failed=0          # a collector that should have run could not
durations=()

# since <epoch-seconds>: seconds elapsed, one decimal.
since() { python3 -c 'import sys,time; print(round(time.time()-float(sys.argv[1]),1))' "$1"; }
now()   { python3 -c 'import time; print(time.time())'; }

skip() { not_measured+=("$1=$2"); echo "metrics: $1 not measured: $2" >&2; }
fail_collector() { not_measured+=("$1=$2"); failed=1; echo "metrics: $1 FAILED: $2" >&2; }

tool_version() {   # tool_version <name> <command...>: first dotted number of the first line, or empty
    command -v "$1" >/dev/null 2>&1 || return 0
    shift
    "$@" 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true
}

# ------------------------------------------------------------ changed lines
# What the change touched, from the library clippy-strict.sh shares, so the
# two gates agree on which lines are the branch's own. Resolved before the
# collectors because diff mode scopes clippy to the changed crates.
if [ "$grading" -eq 1 ]; then
    # lint-shell.sh checks the library as a script of its own.
    # shellcheck disable=SC1091
    . "scripts/lib/changed-lines.sh"
    base_ref="$base"
    base="$(changed_lines_base "$base")"
    merge_base="$(git merge-base "$base" HEAD)"
    changed_lines_diff "$merge_base" "$work/changed.diff"
    changed_lines_untracked "$work/untracked.txt"
    changed_crates "$merge_base" "$work/untracked.txt" > "$work/changed-crates.txt"
    no_rust_changes=0
    if [ ! -s "$work/changed.diff" ] && [ ! -s "$work/untracked.txt" ]; then
        no_rust_changes=1
    fi
    # An explicit scope wins (macOS pins one); otherwise the changed crates,
    # or the workspace when Rust outside crates/ changed. Without Rust changes
    # there is nothing to lint, and `cargo clippy --workspace` would spend the
    # budget proving it.
    if [ "$mode" = diff ] && [ "${#scope[@]}" -eq 0 ]; then
        if [ "$no_rust_changes" -eq 1 ]; then
            want_clippy=0 want_coverage=0
        elif [ -s "$work/changed-crates.txt" ]; then
            # A read loop, not mapfile: macOS's stock bash is 3.2.
            while IFS= read -r c; do [ -n "$c" ] && scope+=("$c"); done < "$work/changed-crates.txt"
        fi
    fi
fi

# ---------------------------------------------------------------- toolchain
compiles=0
if [ "$want_clippy" -eq 1 ] || [ "$want_coverage" -eq 1 ] || [ "$want_modules" -eq 1 ]; then compiles=1; fi
rustc_v=""
[ "$compiles" -eq 1 ] && rustc_v="$(tool_version rustc rustc --version)"
cargo_v="$(tool_version cargo cargo --version)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null | head -n1)"
printf '{"channel": "%s", "rustc": "%s", "cargo": "%s"}\n' "$channel" "$rustc_v" "$cargo_v" > "$work/toolchain.json"

tools_json="{"
add_tool() { tools_json="$tools_json\"$1\": \"$2\", "; }
add_tool tokei "$(tool_version tokei tokei --version)"
shear_v=""; cov_v=""; modules_v=""; nextest_v=""; clippy_v=""; mutants_v=""; crap_v=""; rustqual_v=""; anatomy_v=""
[ "$want_deps" -eq 1 ] && shear_v="$(tool_version cargo-shear cargo shear --version)"
if [ "$want_coverage" -eq 1 ]; then
    cov_v="$(tool_version cargo-llvm-cov cargo llvm-cov --version)"
    nextest_v="$(tool_version cargo-nextest cargo nextest --version)"
    crap_v="$(tool_version cargo-crap cargo crap --version)"
fi
[ "$want_modules" -eq 1 ] && modules_v="$(tool_version cargo-modules cargo modules --version)"
[ "$want_clippy" -eq 1 ] && clippy_v="$(tool_version cargo-clippy cargo clippy --version)"
if [ "$want_mutants" -eq 1 ]; then
    mutants_v="$(tool_version cargo-mutants cargo mutants --version)"
    [ -n "$nextest_v" ] || nextest_v="$(tool_version cargo-nextest cargo nextest --version)"
fi
if [ "$want_experimental" -eq 1 ]; then
    rustqual_v="$(tool_version rustqual rustqual --version)"
    anatomy_v="$(tool_version cargo-anatomy cargo anatomy -V)"
fi
add_tool cargo-shear "$shear_v"
add_tool cargo-llvm-cov "$cov_v"
add_tool cargo-modules "$modules_v"
add_tool cargo-nextest "$nextest_v"
add_tool clippy "$clippy_v"
add_tool rustqual "$rustqual_v"
add_tool cargo-anatomy "$anatomy_v"
add_tool cargo-mutants "$mutants_v"
add_tool cargo-crap "$crap_v"
printf '%s}\n' "${tools_json%, }" > "$work/tools.json"

# ----------------------------------------------------------------- metadata
t0="$(now)"
if ! cargo metadata --format-version 1 --no-deps --offline > "$work/metadata.json" 2> "$work/metadata.err"; then
    echo "metrics: cargo metadata failed; nothing can be attributed to a crate" >&2
    cat "$work/metadata.err" >&2
    exit 1
fi
durations+=("metadata=$(since "$t0")")
all_crates="$(python3 -c 'import json,sys; print("\n".join(sorted(p["name"] for p in json.load(open(sys.argv[1]))["packages"])))' "$work/metadata.json")"

# The scope the compiling collectors cover: the pinned crates, else every
# member. collect.py nulls the compile-based blocks of crates outside it.
if [ "${#scope[@]}" -gt 0 ]; then
    printf '%s\n' ${scope[@]+"${scope[@]}"} > "$work/scope.txt"
    cargo_scope=()
    for c in ${scope[@]+"${scope[@]}"}; do cargo_scope+=(-p "$c"); done
    clippy_complete=()
else
    printf '%s\n' "$all_crates" > "$work/scope.txt"
    cargo_scope=(--workspace)
    clippy_complete=(--clippy-complete)
fi
collect_args+=(--scope "$work/scope.txt")

# The strict lint list is owned by clippy-strict.sh; read it from there so the
# two cannot drift.
grep -oE 'clippy::[a-z_]+' scripts/clippy-strict.sh | sort -u > "$work/strict-lints.txt"
collect_args+=(--strict-lints "$work/strict-lints.txt")

# --------------------------------------------------------------------- size
if command -v tokei >/dev/null 2>&1; then
    t0="$(now)"
    if tokei crates --output json --files --exclude '**/fuzz/**' > "$work/tokei.json" 2> "$work/tokei.err"; then
        collect_args+=(--tokei "$work/tokei.json")
    else
        fail_collector size "tokei exited $? ($(head -c 200 "$work/tokei.err"))"
    fi
    durations+=("size=$(since "$t0")")
else
    skip size "tokei not installed (scripts/metrics/install-tools.sh)"
fi

# -------------------------------------------------------------- unused deps
if [ "$want_deps" -eq 0 ]; then
    skip deps "$mode mode: cargo shear resolves the dependency graph, which probes rustc"
elif command -v cargo-shear >/dev/null 2>&1; then
    t0="$(now)"
    status=0
    # cargo-shear resolves the full dependency graph, so every git dependency
    # has to be in the cargo home first; on a fresh runner nothing has
    # fetched yet. The fetch is what the compiling collectors need anyway.
    cargo fetch --locked > "$work/fetch.out" 2> "$work/fetch.err" || true
    cargo shear --format json --offline > "$work/shear.json" 2> "$work/shear.err" || status=$?
    # 0 clean, 1 findings; anything else did not run.
    if [ "$status" -le 1 ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$work/shear.json" 2>/dev/null; then
        collect_args+=(--shear "$work/shear.json")
    else
        fail_collector deps "cargo shear exited $status ($(head -c 200 "$work/shear.err"))"
    fi
    durations+=("deps=$(since "$t0")")
else
    skip deps "cargo-shear not installed (scripts/metrics/install-tools.sh)"
fi

# ------------------------------------------------------------------- clippy
if [ "$want_clippy" -eq 0 ]; then
    if [ "$mode" = diff ] && [ "${no_rust_changes:-0}" -eq 1 ]; then
        skip clippy "no Rust changes since $base"
    else
        skip clippy "$mode mode"
    fi
else
    lint_args=()
    while read -r lint; do lint_args+=(-W "$lint"); done < "$work/strict-lints.txt"
    for lint in clippy::cognitive_complexity clippy::too_many_lines clippy::too_many_arguments; do
        lint_args+=(-W "$lint")
    done
    t0="$(now)"
    status=0
    cargo clippy ${cargo_scope[@]+"${cargo_scope[@]}"} --all-targets --locked --message-format=json -- ${lint_args[@]+"${lint_args[@]}"} \
        > "$work/clippy.json" 2> "$work/clippy.err" || status=$?
    if [ "$status" -eq 0 ]; then
        collect_args+=(--clippy "$work/clippy.json" ${clippy_complete[@]+"${clippy_complete[@]}"})
    else
        fail_collector clippy "cargo clippy exited $status (see $work/clippy.err)"
    fi
    durations+=("clippy=$(since "$t0")")
fi

# ----------------------------------------------------------------- coverage
# run_crap <lcov> <out>: CRAP per function, from the sources and the lcov
# file coverage wrote. A hook after coverage rather than a collector of its
# own, so whichever mode produces an lcov.info gets it.
run_crap() {
    local lcov="$1" out="$2" t0 status=0
    if ! command -v cargo-crap >/dev/null 2>&1; then
        skip crap "cargo-crap not installed (scripts/metrics/install-tools.sh)"
    elif [ ! -s "$lcov" ]; then
        skip crap "coverage wrote no lcov.info"
    else
        t0="$(now)"
        cargo crap ${cargo_scope[@]+"${cargo_scope[@]}"} --lcov "$lcov" --format json > "$out/raw/crap.json" 2> "$out/raw/crap.err" || status=$?
        if [ "$status" -eq 0 ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$out/raw/crap.json" 2>/dev/null; then
            collect_args+=(--crap "$out/raw/crap.json")
        else
            fail_collector crap "cargo crap exited $status ($(head -c 200 "$out/raw/crap.err"))"
        fi
        durations+=("crap=$(since "$t0")")
    fi
}

rm -f "$out/lcov.info"
if [ "$want_coverage" -eq 0 ]; then
    if [ "$mode" = diff ] && [ "${no_rust_changes:-0}" -eq 1 ]; then
        skip coverage "no Rust changes since $base"
    else
        skip coverage "$mode mode"
    fi
    skip crap "coverage not measured"
elif ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    skip coverage "cargo-llvm-cov not installed (scripts/metrics/install-tools.sh)"
    skip crap "coverage not measured"
elif ! command -v cargo-nextest >/dev/null 2>&1; then
    skip coverage "cargo-nextest not installed"
    skip crap "coverage not measured"
elif ! ls "$(rustc --print target-libdir 2>/dev/null)"/libprofiler_builtins-*.rlib >/dev/null 2>&1; then
    # A toolchain built without the profiler runtime cannot compile with
    # -C instrument-coverage (rustc E0463 on every build script). rustup's
    # toolchains ship it; some distribution builds do not. Say so up front
    # rather than after a cold instrumented build fails.
    skip coverage "toolchain has no profiler runtime (libprofiler_builtins); use a rustup toolchain"
    skip crap "coverage not measured"
else
    # Without rustup's llvm-tools-preview, a matching system LLVM works when
    # named through the environment cargo-llvm-cov reads.
    if [ -z "${LLVM_COV:-}" ] && ! cargo llvm-cov show-env >/dev/null 2>&1; then
        if command -v llvm-cov >/dev/null 2>&1 && command -v llvm-profdata >/dev/null 2>&1; then
            export LLVM_COV LLVM_PROFDATA
            LLVM_COV="$(command -v llvm-cov)"; LLVM_PROFDATA="$(command -v llvm-profdata)"
        fi
    fi
    t0="$(now)"
    status=0
    # Test sources, fuzz targets, build scripts and generated code are kept
    # out of the denominator (QM-004). The lcov file is for the tools that
    # read coverage per function (cargo-crap) and for a person's viewer.
    # --ignore-run-fail: a test that fails under the instrumented build (a
    # hard-coded target/debug path, a host-dependent probe) must not take
    # the coverage of everything that ran with it. The failures are counted
    # from nextest's junit and recorded in the snapshot instead.
    cargo llvm-cov nextest ${cargo_scope[@]+"${cargo_scope[@]}"} --locked --profile coverage --no-tests=fail \
        --ignore-run-fail \
        --ignore-filename-regex '(^|/)(tests|benches|fuzz|examples)/|build\.rs$|/target/' \
        --json --summary-only --output-path "$work/llvm-cov.json" \
        > "$work/coverage.out" 2> "$work/coverage.err" || status=$?
    junit="$(find target/llvm-cov-target -path '*nextest/coverage/junit.xml' 2>/dev/null | head -n1 || true)"
    if [ -n "$junit" ]; then
        # A truncated or malformed junit leaves the file empty; it is then not
        # passed on, so collect.py still writes the snapshot (QM-001).
        python3 - "$junit" <<'PY' > "$work/coverage-tests.json" 2> "$work/coverage-tests.err" || : > "$work/coverage-tests.json"
import json, sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
tests = int(root.get("tests") or 0); failures = int(root.get("failures") or 0); errors = int(root.get("errors") or 0)
failed = sorted(f"{c.get('classname')}::{c.get('name')}" for c in root.iter("testcase") if c.find("failure") is not None or c.find("error") is not None)
print(json.dumps({"tests": tests, "failures": failures + errors, "failed": failed}))
PY
        if [ -s "$work/coverage-tests.json" ]; then
            collect_args+=(--coverage-tests "$work/coverage-tests.json")
        fi
    fi
    if [ "$status" -eq 0 ]; then
        collect_args+=(--coverage "$work/llvm-cov.json")
        cargo llvm-cov report --lcov --output-path "$out/lcov.info" >/dev/null 2>&1 || true
        durations+=("coverage=$(since "$t0")")
        run_crap "$out/lcov.info" "$out"
    else
        fail_collector coverage "cargo llvm-cov nextest exited $status (see $work/coverage.err)"
        skip crap "coverage not measured"
        durations+=("coverage=$(since "$t0")")
    fi
fi

# ------------------------------------------------------------------ modules
# cargo-modules' own `--acyclic` runs before its filters, so every type that
# owns a method that uses the type reads as a cycle. The module graph is
# dumped as DOT instead (modules only: no fns, traits or types) and
# collect.py finds the strongly connected components itself. Orphans are
# per target: a module a binary declares is not an orphan of the library,
# so a crate's orphans are the files every one of its targets orphans.
# --all-features so a feature-gated module is seen; --cfg-test so a test
# module is.
if [ "$want_modules" -eq 0 ]; then
    skip modules "$mode mode"
elif ! command -v cargo-modules >/dev/null 2>&1; then
    skip modules "cargo-modules not installed (scripts/metrics/install-tools.sh)"
else
    t0="$(now)"
    mkdir -p "$work/modules"
    : > "$work/modules.jsonl"
    while read -r crate; do
        [ -n "$crate" ] || continue
        # One line per target: "lib" or "bin <name>".
        python3 - "$work/metadata.json" "$crate" <<'PY' > "$work/modules/$crate.targets"
import json, sys
meta = json.load(open(sys.argv[1]))
pkg = next(p for p in meta["packages"] if p["name"] == sys.argv[2])
for t in pkg["targets"]:
    if "lib" in t["kind"] or "proc-macro" in t["kind"]:
        print("lib")
    elif "bin" in t["kind"]:
        print("bin " + t["name"])
PY
        targets_json=""
        while read -r kind name; do
            [ -n "$kind" ] || continue
            if [ "$kind" = "lib" ]; then sel=(--lib); label="lib"; else sel=(--bin "$name"); label="bin-$name"; fi
            dot="$work/modules/$crate.$label.dot"
            err="$work/modules/$crate.$label.err"
            error=null
            if ! cargo modules dependencies -p "$crate" ${sel[@]+"${sel[@]}"} --all-features --cfg-test --no-externs \
                    --no-sysroot --no-fns --no-traits --no-types > "$dot" 2> "$err"; then
                error="$(head -c 300 "$err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
            fi
            orphans_file="$work/modules/$crate.$label.orphans"
            cargo modules orphans -p "$crate" ${sel[@]+"${sel[@]}"} --all-features --cfg-test --deny 2>&1 \
                | grep -oE 'at crates/[^[:space:]]+' | sed 's/^at //' | sort -u > "$orphans_file" || true
            orphans_json="$(python3 -c 'import json,sys; print(json.dumps([l.strip() for l in open(sys.argv[1]) if l.strip()]))' "$orphans_file")"
            targets_json="$targets_json{\"target\": \"$label\", \"dot\": \"$dot\", \"orphans\": $orphans_json, \"error\": $error}, "
        done < "$work/modules/$crate.targets"
        printf '{"crate": "%s", "targets": [%s]}\n' "$crate" "${targets_json%, }" >> "$work/modules.jsonl"
    done < "$work/scope.txt"
    collect_args+=(--modules "$work/modules.jsonl")
    durations+=("modules=$(since "$t0")")
fi

# ------------------------------------------------------------- experimental
# Coupling and design metrics from young tools, recorded per crate and read
# by no gate (QM-005). Nothing in this step can fail the run: a missing tool
# is a skip, a tool that cannot run is a skip with its reason, and a crate
# rustqual chokes on carries the error in its own block.
if [ "$want_experimental" -eq 0 ]; then
    skip experimental.rustqual "$mode mode"
    skip experimental.anatomy "$mode mode"
else
    if command -v rustqual >/dev/null 2>&1; then
        t0="$(now)"
        mkdir -p "$work/rustqual" "$out/rustqual"
        while read -r crate; do
            [ -n "$crate" ] || continue
            # A source-level tool: the generated crate has no source to read,
            # so it is left out rather than scored on an empty tree.
            [ "$crate" = "remote-proto" ] && continue
            src="$(python3 -c 'import json,os,sys; meta=json.load(open(sys.argv[1])); pkg=next(p for p in meta["packages"] if p["name"]==sys.argv[2]); print(os.path.dirname(pkg["manifest_path"]))' "$work/metadata.json" "$crate")/src"
            [ -d "$src" ] || continue
            # Exit 1 means findings, which is the point; anything else did not run.
            status=0
            rustqual "$src" --format json > "$work/rustqual/$crate.json" 2> "$work/rustqual/$crate.err" || status=$?
            if [ "$status" -gt 1 ] || ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$work/rustqual/$crate.json" 2>/dev/null; then
                printf '{"error": "rustqual exited %s (%s)"}\n' "$status" "$(head -c 200 "$work/rustqual/$crate.err" | tr '\n"' '  ')" > "$work/rustqual/$crate.json"
                echo "metrics: experimental.rustqual: $crate not analysed (exit $status)" >&2
            fi
            # The SARIF copy is an artifact for a person's viewer; nothing reads it.
            rustqual "$src" --format sarif > "$out/rustqual/$crate.sarif" 2>/dev/null || true
        done < "$work/scope.txt"
        collect_args+=(--rustqual-dir "$work/rustqual")
        durations+=("experimental.rustqual=$(since "$t0")")
    else
        skip experimental.rustqual "rustqual not installed (scripts/metrics/install-tools.sh --experimental)"
    fi
    if command -v cargo-anatomy >/dev/null 2>&1; then
        t0="$(now)"
        status=0
        # Compact JSON over the whole workspace is its default output.
        cargo anatomy > "$work/anatomy.json" 2> "$work/anatomy.err" || status=$?
        if [ "$status" -eq 0 ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$work/anatomy.json" 2>/dev/null; then
            collect_args+=(--anatomy "$work/anatomy.json")
        else
            skip experimental.anatomy "cargo anatomy exited $status ($(head -c 200 "$work/anatomy.err" | tr '\n' ' '))"
        fi
        durations+=("experimental.anatomy=$(since "$t0")")
    else
        skip experimental.anatomy "cargo-anatomy not installed (scripts/metrics/install-tools.sh --experimental)"
    fi
fi

# ------------------------------------------------------------------ mutants
# A mutant survives when the suite still passes with it in, so the suite has
# to pass without it first; cargo-mutants runs that baseline itself and stops
# when it fails. The baseline is green only on Linux (.minimal/minimal.toml).
if [ "$want_mutants" -eq 0 ]; then
    skip mutants "$mode mode"
elif [ "$(uname -s)" = "Darwin" ]; then
    skip mutants "darwin host: the baseline suite is green only on Linux"
elif ! command -v cargo-mutants >/dev/null 2>&1 || ! command -v cargo-nextest >/dev/null 2>&1; then
    # In mutants mode the mutation run is all that was asked for, so a
    # missing tool fails the run (exit 3) instead of passing it empty.
    missing_tool="cargo-mutants"
    command -v cargo-mutants >/dev/null 2>&1 && missing_tool="cargo-nextest"
    if [ "$mode" = "mutants" ]; then
        fail_collector mutants "$missing_tool not installed (scripts/metrics/install-tools.sh --only cargo-mutants --only cargo-nextest)"
    else
        skip mutants "$missing_tool not installed (scripts/metrics/install-tools.sh)"
    fi
else
    mutants_args=(--test-tool nextest --timeout-multiplier 1.5 --output "$out/mutants")
    scope_args=()
    run_mutants=1
    if [ "$mode" = "mutants" ]; then
        # The changed lines, computed as scripts/clippy-strict.sh computes
        # them (the base-ref reasoning is there): the merge-base with
        # origin/main unless BASE says otherwise, the working tree rather
        # than HEAD so an uncommitted edit counts, -U0 so a hunk is the
        # lines the change touched and nothing around them (QM-017). A
        # brand-new file is untracked, so it is not in the diff; it is listed
        # as outside the scope instead.
        [ -n "$base" ] || base="$(git merge-base origin/main HEAD 2>/dev/null || git merge-base main HEAD)"
        merge_base="$(git merge-base "$base" HEAD)"
        git diff -U0 --no-color --no-ext-diff --no-textconv --diff-filter=d \
            "$merge_base" -- '*.rs' > "$work/mutants.diff"
        git ls-files --others --exclude-standard -- '*.rs' > "$work/mutants-untracked.txt"
        collect_args+=(--mutants-untracked "$work/mutants-untracked.txt")
        if [ -s "$work/mutants.diff" ]; then
            mutants_args+=(--in-diff "$work/mutants.diff")
            scope_args=(--mutants-scope in-diff)
        else
            skip mutants "no Rust changes since $base"
            run_mutants=0
        fi
    else
        # The nightly tests the lines changed since the previous snapshot: a
        # workspace shard is thousands of mutants and a night is not enough
        # for one, while yesterday's changes are bounded and are what the
        # history should say something about (QM-017). `--since` names the
        # reference; `auto` takes the newest snapshot in the history dir,
        # then the merge-base with origin/main on a branch, and skips when
        # neither names a commit other than HEAD.
        ref=""
        if [ "$mutants_since" = "auto" ]; then
            # Newest by date, then by commit time within a day (prune.py).
            newest=""
            [ -d "$history_dir" ] && newest="$(python3 "$here/prune.py" --newest "$history_dir" 2>/dev/null || true)"
            if [ -n "$newest" ]; then
                sha7="$(basename "$newest" .json | sed 's/^[0-9-]*-//')"
                git rev-parse --verify --quiet "$sha7^{commit}" >/dev/null 2>&1 && ref="$sha7"
            fi
            if [ -z "$ref" ]; then
                mb="$(git merge-base origin/main HEAD 2>/dev/null || git merge-base main HEAD 2>/dev/null || true)"
                [ -n "$mb" ] && [ "$mb" != "$(git rev-parse HEAD)" ] && ref="$mb"
            fi
        else
            git rev-parse --verify --quiet "$mutants_since^{commit}" >/dev/null 2>&1 && ref="$mutants_since"
        fi
        if [ -z "$ref" ]; then
            skip mutants "no reference commit for the nightly diff (--since)"
            run_mutants=0
        else
            git diff -U0 --no-color --no-ext-diff --no-textconv --diff-filter=d \
                "$ref" -- '*.rs' > "$work/mutants.diff"
            if [ -s "$work/mutants.diff" ]; then
                mutants_args+=(--in-diff "$work/mutants.diff")
                scope_args=(--mutants-scope since --mutants-since "$(git rev-parse --short=7 "$ref")")
            else
                skip mutants "no Rust changes since $ref"
                run_mutants=0
            fi
        fi
    fi
    if [ "$run_mutants" -eq 1 ]; then
        t0="$(now)"
        status=0
        rm -rf "$out/mutants/mutants.out"
        # A time budget, so one large change cannot take the whole run with
        # it. cargo-mutants rewrites outcomes.json after every mutant, so an
        # interrupted run still reports what it tested, marked as partial.
        budget_cmd=()
        if command -v timeout >/dev/null 2>&1; then
            budget_cmd=(timeout --signal=INT --kill-after=60 "$mutants_budget")
        fi
        ${budget_cmd[@]+"${budget_cmd[@]}"} cargo mutants ${mutants_args[@]+"${mutants_args[@]}"} > "$work/mutants.log" 2> "$work/mutants.err" || status=$?
        outcomes="$out/mutants/mutants.out/outcomes.json"
        if [ "$status" -eq 124 ]; then
            echo "metrics: mutants stopped at the ${mutants_budget}s budget; partial result" >&2
            scope_args+=(--mutants-budget-exhausted)
        fi
        # Exit 2 is missed mutants, 3 timeouts, 4 unviable ones: results, not
        # failures. 4 is also a failed baseline, so the proof that the run
        # happened is the baseline's own outcome in the file. A diff that
        # reaches no mutant (comments, signatures) exits 0 and writes no
        # mutants.out at all: nothing was measured, and nothing failed.
        if { [ "$status" -eq 0 ] || [ "$status" -eq 124 ]; } && [ ! -f "$outcomes" ]; then
            skip mutants "no mutants in the changed lines"
        elif [ -f "$outcomes" ] && python3 - "$outcomes" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
ok = any(o.get("scenario") == "Baseline" and o.get("summary") == "Success" for o in doc["outcomes"])
sys.exit(0 if ok else 1)
PY
        then
            collect_args+=(--mutants "$outcomes" ${scope_args[@]+"${scope_args[@]}"})
        else
            fail_collector mutants "cargo mutants exited $status (see $work/mutants.err)"
        fi
        durations+=("mutants=$(since "$t0")")
    fi
fi

# ------------------------------------------------------------------ collect
[ "$want_hotspots" -eq 1 ] || collect_args+=(--no-hotspots)
for nm in ${not_measured[@]+"${not_measured[@]}"}; do collect_args+=(--not-measured "$nm"); done
for d in ${durations[@]+"${durations[@]}"}; do collect_args+=(--duration "$d"); done
run_mode="$mode"
[ "$(uname -s)" = "Darwin" ] && [ "$mode" = "full" ] && run_mode="darwin"

rm -f "$out/snapshot.json"
status=0
# The grading modes append their report to the step summary; the others
# append the snapshot's own page (QM-011 covers the report; this is the
# nightly's glance at the run).
summary_args=()
[ "$grading" -eq 1 ] || summary_args=(--summary)
python3 "$here/collect.py" --out "$out" --mode "$run_mode" --metadata "$work/metadata.json" ${summary_args[@]+"${summary_args[@]}"} \
    --tools "$work/tools.json" --toolchain "$work/toolchain.json" --started "$started" \
    --excluded "remote-proto=generated OUT_DIR code is invisible to source-level tools" \
    ${collect_args[@]+"${collect_args[@]}"} || status=$?
# argparse also exits 2, so the file is the proof that collection happened.
if [ ! -f "$out/snapshot.json" ] || { [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; }; then
    echo "metrics: collect.py failed (exit $status); no snapshot written" >&2
    exit 1
fi
echo "metrics: wrote $out/snapshot.json"

# -------------------------------------------------------------------- grade
# The snapshot's own verdict used the head's thresholds and no baseline; the
# report's verdict is the one that grades the change, so it replaces it here.
if [ "$grading" -eq 1 ]; then
    diff_args=(--head "$out" --out "$out" --history-ref "$history_ref"
               --changed "$work/changed.diff" --untracked "$work/untracked.txt")
    [ -n "$base_ref" ] && diff_args+=(--base-ref "$base_ref")
    status=0
    rm -f "$out/report.json"
    python3 "$here/diff.py" ${diff_args[@]+"${diff_args[@]}"} || status=$?
    if [ ! -f "$out/report.json" ] || { [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; }; then
        echo "metrics: diff.py failed (exit $status); no report written" >&2
        exit 1
    fi
    echo "metrics: wrote $out/report.md"
    verdict="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$out/report.json")"
    digest="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$out/report.json")"
    [ "$failed" -eq 0 ] || echo "metrics: a collector could not run; the snapshot is incomplete" >&2
    echo "quality-gate: $verdict report=$out/report.json sha256=$digest"
    # A failed gate outranks an incomplete snapshot: the change fails on what
    # was measured, and what was not measured cannot pass it.
    [ "$status" -eq 2 ] && exit 2
    [ "$failed" -eq 0 ] || exit 3
    exit "$status"
fi

# Here an incomplete snapshot outranks a failed verdict: the nightly reads
# exit 3 as "do not publish", and a snapshot with a collector missing would
# leave a hole in the history the ratchets grade against.
if [ "$failed" -eq 1 ]; then
    echo "metrics: a collector could not run; the snapshot is incomplete" >&2
    exit 3
fi
exit "$status"
