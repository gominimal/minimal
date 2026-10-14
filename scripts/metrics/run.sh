#!/usr/bin/env bash
# Architectural-health snapshot: run the collectors, hand their output to
# collect.py (spec 30).
#
# Usage: scripts/metrics/run.sh MODE [OPTIONS] [-p CRATE ...]
#
#   MODE      full    every collector; the nightly run and `just metrics`
#             static  no compiler: layers, size, unused deps, hotspots from
#                     history. What the gate tier and a cold sandbox can afford.
#   --out DIR         where snapshot.json, clippy-hits.json and meta.json land
#                     (default .scratch/metrics/<mode>)
#   --no-coverage, --no-modules, --no-clippy, --no-hotspots, --no-experimental
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
#   2  snapshot written, verdict fail
#   3  snapshot written, but a collector could not run (read it as incomplete)
#   1  nothing written: a crash, or no python3
# None of the non-zero ones is ever read as clean.
#
# Tool versions are read from the binaries and recorded, so the snapshot says
# what measured it; install-tools.sh holds the pins.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
here="scripts/metrics"
mode="${1:-}"
case "$mode" in
    full|static) shift ;;
    "") echo "usage: $0 full|static [--out DIR] [--no-coverage] [--no-modules] [--no-clippy] [--no-hotspots] [--no-experimental] [-p CRATE]..." >&2; exit 1 ;;
    *) echo "metrics: unknown mode '$mode'" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "metrics: python3 is required" >&2; exit 127; }

out=".scratch/metrics/$mode"
want_coverage=1 want_modules=1 want_clippy=1 want_hotspots=1 want_experimental=1
scope=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --no-coverage) want_coverage=0; shift ;;
        --no-modules) want_modules=0; shift ;;
        --no-clippy) want_clippy=0; shift ;;
        --no-hotspots) want_hotspots=0; shift ;;
        --no-experimental) want_experimental=0; shift ;;
        -p) scope+=("$2"); shift 2 ;;
        -p*) scope+=("${1#-p}"); shift ;;
        *) echo "metrics: unknown argument '$1'" >&2; exit 1 ;;
    esac
done
if [ "$mode" = "static" ]; then
    want_coverage=0 want_modules=0 want_clippy=0 want_experimental=0
fi

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

# ---------------------------------------------------------------- toolchain
rustc_v="$(tool_version rustc rustc --version)"
cargo_v="$(tool_version cargo cargo --version)"
channel="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null | head -n1)"
printf '{"channel": "%s", "rustc": "%s", "cargo": "%s"}\n' "$channel" "$rustc_v" "$cargo_v" > "$work/toolchain.json"

tools_json="{"
add_tool() { tools_json="$tools_json\"$1\": \"$2\", "; }
add_tool tokei "$(tool_version tokei tokei --version)"
add_tool cargo-shear "$(tool_version cargo-shear cargo shear --version)"
add_tool cargo-llvm-cov "$(tool_version cargo-llvm-cov cargo llvm-cov --version)"
add_tool cargo-modules "$(tool_version cargo-modules cargo modules --version)"
add_tool cargo-nextest "$(tool_version cargo-nextest cargo nextest --version)"
add_tool clippy "$(tool_version cargo-clippy cargo clippy --version)"
add_tool rustqual "$(tool_version rustqual rustqual --version)"
add_tool cargo-anatomy "$(tool_version cargo-anatomy cargo anatomy -V)"
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
    printf '%s\n' "${scope[@]}" > "$work/scope.txt"
    cargo_scope=()
    for c in "${scope[@]}"; do cargo_scope+=(-p "$c"); done
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
if command -v cargo-shear >/dev/null 2>&1; then
    t0="$(now)"
    status=0
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
    skip clippy "$mode mode"
else
    lint_args=()
    while read -r lint; do lint_args+=(-W "$lint"); done < "$work/strict-lints.txt"
    for lint in clippy::cognitive_complexity clippy::too_many_lines clippy::too_many_arguments; do
        lint_args+=(-W "$lint")
    done
    t0="$(now)"
    status=0
    cargo clippy "${cargo_scope[@]}" --all-targets --locked --message-format=json -- "${lint_args[@]}" \
        > "$work/clippy.json" 2> "$work/clippy.err" || status=$?
    if [ "$status" -eq 0 ]; then
        collect_args+=(--clippy "$work/clippy.json" "${clippy_complete[@]}")
    else
        fail_collector clippy "cargo clippy exited $status (see $work/clippy.err)"
    fi
    durations+=("clippy=$(since "$t0")")
fi

# ----------------------------------------------------------------- coverage
if [ "$want_coverage" -eq 0 ]; then
    skip coverage "$mode mode"
elif ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    skip coverage "cargo-llvm-cov not installed (scripts/metrics/install-tools.sh)"
elif ! command -v cargo-nextest >/dev/null 2>&1; then
    skip coverage "cargo-nextest not installed"
elif ! ls "$(rustc --print target-libdir 2>/dev/null)"/libprofiler_builtins-*.rlib >/dev/null 2>&1; then
    # A toolchain built without the profiler runtime cannot compile with
    # -C instrument-coverage (rustc E0463 on every build script). rustup's
    # toolchains ship it; some distribution builds do not. Say so up front
    # rather than after a cold instrumented build fails.
    skip coverage "toolchain has no profiler runtime (libprofiler_builtins); use a rustup toolchain"
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
    cargo llvm-cov nextest "${cargo_scope[@]}" --locked --profile coverage --no-tests=fail \
        --ignore-filename-regex '(^|/)(tests|benches|fuzz|examples)/|build\.rs$|/target/' \
        --json --summary-only --output-path "$work/llvm-cov.json" \
        > "$work/coverage.out" 2> "$work/coverage.err" || status=$?
    if [ "$status" -eq 0 ]; then
        collect_args+=(--coverage "$work/llvm-cov.json")
        cargo llvm-cov report --lcov --output-path "$out/lcov.info" >/dev/null 2>&1 || true
    else
        fail_collector coverage "cargo llvm-cov nextest exited $status (see $work/coverage.err)"
    fi
    durations+=("coverage=$(since "$t0")")
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
            if [ "$kind" = "lib" ]; then sel=(--lib); label="lib"; else sel=(--bin "$name"); label="bin:$name"; fi
            dot="$work/modules/$crate.$label.dot"
            err="$work/modules/$crate.$label.err"
            error=null
            if ! cargo modules dependencies -p "$crate" "${sel[@]}" --all-features --cfg-test --no-externs \
                    --no-sysroot --no-fns --no-traits --no-types > "$dot" 2> "$err"; then
                error="$(head -c 300 "$err" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
            fi
            orphans_file="$work/modules/$crate.$label.orphans"
            cargo modules orphans -p "$crate" "${sel[@]}" --all-features --cfg-test --deny 2>&1 \
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

# ------------------------------------------------------------------ collect
[ "$want_hotspots" -eq 1 ] || collect_args+=(--no-hotspots)
for nm in "${not_measured[@]}"; do collect_args+=(--not-measured "$nm"); done
for d in "${durations[@]}"; do collect_args+=(--duration "$d"); done
run_mode="$mode"
[ "$(uname -s)" = "Darwin" ] && [ "$mode" = "full" ] && run_mode="darwin"

rm -f "$out/snapshot.json"
status=0
python3 "$here/collect.py" --out "$out" --mode "$run_mode" --metadata "$work/metadata.json" \
    --tools "$work/tools.json" --toolchain "$work/toolchain.json" --started "$started" \
    --excluded "remote-proto=generated OUT_DIR code is invisible to source-level tools" \
    "${collect_args[@]}" || status=$?
# argparse also exits 2, so the file is the proof that collection happened.
if [ ! -f "$out/snapshot.json" ] || { [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; }; then
    echo "metrics: collect.py failed (exit $status); no snapshot written" >&2
    exit 1
fi
echo "metrics: wrote $out/snapshot.json"
if [ "$failed" -eq 1 ]; then
    echo "metrics: a collector could not run; the snapshot is incomplete" >&2
    exit 3
fi
exit "$status"
