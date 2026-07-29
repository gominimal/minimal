#!/usr/bin/env bash
# Generate the shell completions the release ships.
#
# WHY THIS EXISTS
# ---------------
# `release.yml` used to inline these invocations in its "Generate completions"
# step, where they only ever ran on a `workflow_dispatch` release — so a
# breaking CLI change cleared every PR gate, merged, and sat until someone cut a
# release, taking the GCS upload, the GitHub Release and `stage-installer` down
# with it an hour of build time in. That is how #1009 (`completions <shell>` →
# `completions print <shell>`) shipped broken for twenty days (#1034, #1035).
#
# So this is the single definition of what the release generates, called both by
# that step (against the built artifacts) and by
# crates/common/tests/release_completions.rs (against `target/debug`) — the
# convention-discovered workspace test the always-running Linux lanes execute.
# Since the release path and the pre-merge gate are now the same code, they
# cannot disagree; `.github/workflows/` stays frozen either way.
#
# The destination filenames are derived from the command name, never spelled out
# per row, because a shell only autoloads completions from a file named for the
# command they complete. The #737 binary rename (`minimal` → `min`) left the
# release job writing `min`'s completions to files named `minimal` — inert, and
# invisible to any exit-code check — until #1034. Deriving them makes that class
# of mismatch unrepresentable rather than merely tested.
#
# Usage: scripts/gen-completions.sh <outdir> [binary...]
#   binary...  which of mip / min / minimald to generate (default: all three).
# Env: BIN_DIR                          where to find them (default target/debug)
#      MIP_BIN / MIN_BIN / MINIMALD_BIN explicit path to one binary, which is how
#                                       the release job points at its
#                                       platform-suffixed artifacts.
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <outdir> [binary...]" >&2
    exit 2
fi
out="$1"
shift

root="$(cd "$(dirname "$0")/.." && pwd)"
bin_dir="${BIN_DIR:-$root/target/debug}"

binaries=("$@")
if [ "${#binaries[@]}" -eq 0 ]; then
    binaries=(mip min minimald)
fi

mkdir -p "$out/bash" "$out/zsh" "$out/fish"

generated=0
for name in "${binaries[@]}"; do
    # Per binary: where it lives, and the verb that prints a completion script.
    # `min` splits printing from installing (`completions print <shell>`, #1009);
    # `mip` and `minimald` keep the flat verb.
    case "$name" in
        mip)      exe="${MIP_BIN:-$bin_dir/mip}";           verb=(completions) ;;
        min)      exe="${MIN_BIN:-$bin_dir/min}";           verb=(completions print) ;;
        minimald) exe="${MINIMALD_BIN:-$bin_dir/minimald}"; verb=(completions) ;;
        *) echo "gen-completions: unknown binary '$name'" >&2; exit 2 ;;
    esac

    if [ ! -x "$exe" ]; then
        echo "gen-completions: $exe is not an executable" >&2
        exit 1
    fi

    for shell in bash zsh fish; do
        # Each shell's autoload name for the command `$name`.
        case "$shell" in
            bash) dest="$out/bash/$name" ;;
            zsh)  dest="$out/zsh/_$name" ;;
            fish) dest="$out/fish/$name.fish" ;;
        esac
        "$exe" "${verb[@]}" "$shell" >"$dest"
        if [ ! -s "$dest" ]; then
            echo "gen-completions: $name wrote an empty $shell completion" >&2
            exit 1
        fi
        generated=$((generated + 1))
    done
done

echo "gen-completions: wrote $generated completion file(s) to $out"
