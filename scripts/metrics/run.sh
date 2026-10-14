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
#   --no-coverage, --no-modules, --no-clippy, --no-hotspots
#                     skip one collector; it is recorded as not measured
#   -p CRATE          pin the compiling collectors to these crates (the
#                     justfile does this on macOS); repeatable
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
    "") echo "usage: $0 full|static [--out DIR] [--no-coverage] [--no-modules] [--no-clippy] [--no-hotspots] [-p CRATE]..." >&2; exit 1 ;;
    *) echo "metrics: unknown mode '$mode'" >&2; exit 1 ;;
esac
command -v python3 >/dev/null 2>&1 || { echo "metrics: python3 is required" >&2; exit 127; }

out=".scratch/metrics/$mode"
want_coverage=1 want_modules=1 want_clippy=1 want_hotspots=1
scope=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --out) out="$2"; shift 2 ;;
        --no-coverage) want_coverage=0; shift ;;
        --no-modules) want_modules=0; shift ;;
        --no-clippy) want_clippy=0; shift ;;
        --no-hotspots) want_hotspots=0; shift ;;
        -p) scope+=("$2"); shift 2 ;;
        -p*) scope+=("${1#-p}"); shift ;;
        *) echo "metrics: unknown argument '$1'" >&2; exit 1 ;;
    esac
done
if [ "$mode" = "static" ]; then
    want_coverage=0 want_modules=0 want_clippy=0
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
if [ "$want_modules" -eq 0 ]; then
    skip modules "$mode mode"
elif ! command -v cargo-modules >/dev/null 2>&1; then
    skip modules "cargo-modules not installed (scripts/metrics/install-tools.sh)"
else
    t0="$(now)"
    : > "$work/modules.jsonl"
    while read -r crate; do
        [ -n "$crate" ] || continue
        # A crate with no lib target is analysed through its first bin.
        target=(--lib)
        if ! python3 - "$work/metadata.json" "$crate" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1]))
pkg = next(p for p in meta["packages"] if p["name"] == sys.argv[2])
sys.exit(0 if any("lib" in t["kind"] or "proc-macro" in t["kind"] for t in pkg["targets"]) else 1)
PY
        then
            bin_name="$(python3 -c 'import json,sys; meta=json.load(open(sys.argv[1])); pkg=next(p for p in meta["packages"] if p["name"]==sys.argv[2]); print(next(t["name"] for t in pkg["targets"] if "bin" in t["kind"]))' "$work/metadata.json" "$crate")"
            target=(--bin "$bin_name")
        fi
        acyclic=true; error=""
        if ! cargo modules dependencies -p "$crate" "${target[@]}" --no-externs --no-sysroot --no-fns \
                --no-traits --no-types --acyclic > /dev/null 2> "$work/modules-$crate.err"; then
            if grep -qi "cycl" "$work/modules-$crate.err"; then acyclic=false; else error="$(head -c 300 "$work/modules-$crate.err" | tr '\n"' '  ')"; fi
        fi
        orphans=0
        if ! cargo modules orphans -p "$crate" "${target[@]}" --deny > "$work/orphans-$crate.out" 2>> "$work/modules-$crate.err"; then
            orphans="$(grep -c '^' "$work/orphans-$crate.out" || true)"
        fi
        printf '{"crate": "%s", "acyclic": %s, "orphans": %s, "error": %s}\n' \
            "$crate" "$acyclic" "$orphans" "$([ -n "$error" ] && printf '"%s"' "$error" || echo null)" >> "$work/modules.jsonl"
    done < "$work/scope.txt"
    collect_args+=(--modules "$work/modules.jsonl")
    durations+=("modules=$(since "$t0")")
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
