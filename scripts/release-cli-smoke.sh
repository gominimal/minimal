#!/usr/bin/env bash
# Exercise the shipped-binary CLI invocations the release job makes.
#
# WHY THIS EXISTS
# ---------------
# `release.yml`'s "Generate completions" step shells out to the freshly built
# `mip` / `min` / `minimald` binaries. Those nine invocations only ever run on a
# `workflow_dispatch` release, so a breaking CLI change passes every PR gate,
# merges, and sits until someone cuts a release — where it takes the GCS upload,
# the GitHub Release, and `stage-installer` down with it after an hour of build
# time. That is exactly what #1009 (`completions <shell>` → `completions print
# <shell>`) did, twenty days after merging (#1034 fixed the call site).
#
# Widening the release job to gate itself would mean editing
# `.github/workflows/`, which is frozen and CODEOWNER-gated. Instead this
# harness READS the invocations out of `release.yml` and replays them against
# locally built debug binaries; CI picks it up through a convention-discovered
# workspace test (crates/common/tests/release_cli_smoke.rs) and `just
# test-release-cli` — the reviewed-code extension point CI schedules over
# (docs/ci-strategy.md §10).
#
# Nothing here is a hand-maintained copy of the release job's command list: both
# the artifact→binary map ("Rename binaries with platform suffix") and the
# invocations themselves are parsed out of the workflow, so a call site the
# release job adds or edits is covered on the next run without touching this
# file. Discovering zero invocations is a hard failure, never a green skip.
#
# Each invocation is checked three ways, because exit 0 alone is too weak: the
# #737 binary rename (`minimal` → `min`) left the release job writing `min`'s
# completions to files named `minimal`, which a shell never autoloads — an
# exit-code-only gate would have shipped that silently, as it did until #1034.
#
#   1. exits 0 and writes a non-empty file;
#   2. the shell it generates for matches the directory it is written to;
#   3. the shim registers the command its destination FILENAME implies —
#      `bash/<cmd>`, `zsh/_<cmd>`, `fish/<cmd>.fish`.
#
# SCOPE
# -----
# The "Generate completions" step is, as of this writing, the only place the
# release or `stage-installer` jobs invoke a shipped binary — everything else
# they run is `gcloud`, `gh`, `tar`, or a reviewed `scripts/` helper with its own
# harness (install.sh → install_test.sh, verify-nightly-provenance.sh →
# verify-nightly-provenance_test.sh). If a later step starts calling one of the
# binaries, widen the discovery pattern at the bottom of the loop to reach it.
#
# Usage: scripts/release-cli-smoke.sh [--build]
#   --build  cargo-build any missing binary first (default: a missing binary is
#            an error, so a stale target/ can never quietly narrow the check).
# Env: BIN_DIR overrides where the binaries are looked up (default
#      ${CARGO_TARGET_DIR:-<repo>/target}/debug).
set -euo pipefail

build_missing=0
case "${1:-}" in
    --build) build_missing=1 ;;
    "") ;;
    *) echo "usage: $0 [--build]" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
workflow="$root/.github/workflows/release.yml"
bin_dir="${BIN_DIR:-${CARGO_TARGET_DIR:-$root/target}/debug}"

[ -f "$workflow" ] || { echo "release-cli-smoke: no such workflow: $workflow" >&2; exit 1; }

# `minimald` does not build on macOS (its sandbox stack is Linux-only — see the
# platform matrix in AGENTS.md), so its invocations are skipped there and gated
# by the Linux lanes. Every other binary is checked on every platform.
skip_on_this_os() {
    [ "$1" = minimald ] && [ "$(uname -s)" != Linux ]
}

# artifact name -> binary name, from the release job's rename step
# (`mv min minimal-linux-amd64`), as "<artifact> <binary>" lines. Sorted unique,
# so the same rename repeated per architecture collapses to one entry and a
# genuine conflict shows up as two lines for one artifact.
# `|| true`: no matches is grep's exit 1, which `pipefail` would otherwise turn
# into a silent early exit here. An empty map surfaces per-invocation instead.
rename_map="$(
    { grep -E '^[[:space:]]*mv [^[:space:]]+ [^[:space:]]+-(linux|darwin)-(amd64|arm64)$' "$workflow" |
        awk '{print $3, $2}' | sort -u; } || true
)"

bin_for_artifact() {
    awk -v want="$1" '$1 == want { print $2 }' <<<"$rename_map" | sort -u
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

discovered=0
checked=0
skipped=0
failed=0

fail() {
    echo "FAIL  $1" >&2
    failed=$((failed + 1))
}

# Replay every `artifacts/<binary> ... > artifacts/completions/<shell>/<file>`
# line in the workflow.
while IFS= read -r line; do
    discovered=$((discovered + 1))
    cmd="${line%%>*}"
    dest="${line#*>}"
    # shellcheck disable=SC2086 # deliberate: re-split the recorded argv
    set -- $cmd
    artifact="$(basename "$1")"
    shift
    args=("$@")
    # shellcheck disable=SC2086
    set -- $dest
    dest="$1"

    shell_dir="$(basename "$(dirname "$dest")")"
    file="$(basename "$dest")"
    invocation="$artifact ${args[*]} > $shell_dir/$file"

    bin="$(bin_for_artifact "$artifact")"
    if [ -z "$bin" ]; then
        fail "$invocation: no rename step maps $artifact to a binary"
        continue
    fi
    if [ "$(printf '%s\n' "$bin" | wc -l)" -ne 1 ]; then
        fail "$invocation: $artifact maps to more than one binary ($(tr '\n' ' ' <<<"$bin"))"
        continue
    fi

    if skip_on_this_os "$bin"; then
        echo "SKIP  $invocation ($bin does not build on $(uname -s))"
        skipped=$((skipped + 1))
        continue
    fi
    checked=$((checked + 1))

    # The shell the shim is generated for has to match the directory it lands
    # in; the release job passes it as the last argument.
    gen_shell="${args[$((${#args[@]} - 1))]}"
    if [ "$gen_shell" != "$shell_dir" ]; then
        fail "$invocation: generates for $gen_shell but is written to $shell_dir/"
        continue
    fi

    # The command a shell will autoload this file for, per its naming rule.
    case "$shell_dir" in
        bash) cmd_name="$file" ;;
        zsh)  cmd_name="${file#_}"; [ "_$cmd_name" = "$file" ] || cmd_name="" ;;
        fish) cmd_name="${file%.fish}"; [ "$cmd_name.fish" = "$file" ] || cmd_name="" ;;
        *) fail "$invocation: unknown completion shell directory '$shell_dir'"; continue ;;
    esac
    if [ -z "$cmd_name" ] || ! [[ "$cmd_name" =~ ^[A-Za-z0-9_.-]+$ ]]; then
        fail "$invocation: '$file' is not a valid $shell_dir completion filename"
        continue
    fi

    exe="$bin_dir/$bin"
    if [ ! -x "$exe" ]; then
        if [ "$build_missing" = 1 ]; then
            # `--workspace --bin`, not `-p <package> --bin`: selecting the whole
            # workspace resolves features exactly as the workspace test build
            # does, so this is a link (or a no-op) rather than a rebuild of every
            # shared dependency under a narrower feature set. It also means no
            # binary→package table to keep in sync (`min` comes from the
            # `minimal` crate — the naming footgun in AGENTS.md).
            echo "release-cli-smoke: building $bin" >&2
            (cd "$root" && cargo build --locked --workspace --bin "$bin" >&2)
            if [ ! -x "$exe" ]; then
                fail "$invocation: built $bin but $exe is still missing (BIN_DIR mismatch?)"
                continue
            fi
        else
            fail "$invocation: $exe not built (run with --build, or \`cargo build\` it)"
            continue
        fi
    fi

    out="$tmp/$shell_dir/$file"
    mkdir -p "$(dirname "$out")"
    rc=0
    "$exe" "${args[@]}" >"$out" 2>"$tmp/stderr" || rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$invocation: exited $rc — $(tr '\n' ' ' <"$tmp/stderr")"
        continue
    fi
    if [ ! -s "$out" ]; then
        fail "$invocation: wrote an empty completion file"
        continue
    fi

    # The registration line, in whichever form the binary emits: clap's static
    # (aot) generator and its dynamic (env) shim differ in flag spelling but
    # both name the command they complete.
    case "$shell_dir" in
        bash) pattern="^[[:space:]]*complete[[:space:]].*[[:space:]]$cmd_name\$" ;;
        zsh)  pattern="^#compdef[[:space:]]+$cmd_name([[:space:]]|\$)" ;;
        fish) pattern="(^|[[:space:]])(-c|--command)[[:space:]]+$cmd_name([[:space:]]|\$)" ;;
    esac
    if ! grep -qE "$pattern" "$out"; then
        fail "$invocation: does not register the command '$cmd_name' that '$file' completes"
        continue
    fi

    echo "ok    $invocation"
done < <(grep -E '^[[:space:]]*artifacts/[^[:space:]]+ .*>[[:space:]]*artifacts/completions/' "$workflow")

if [ "$discovered" -eq 0 ]; then
    # Discovery broke (the step moved, renamed, or changed shape) — never pass
    # green having replayed nothing; that is the false signal this exists to end.
    echo "release-cli-smoke: found no release-job CLI invocations in $workflow" >&2
    exit 1
fi
if [ "$failed" -gt 0 ]; then
    echo "release-cli-smoke: $failed of $discovered invocation(s) failed" >&2
    exit 1
fi
summary="release-cli-smoke: $checked invocation(s) passed"
if [ "$skipped" -gt 0 ]; then
    summary="$summary, $skipped skipped"
fi
echo "$summary"
