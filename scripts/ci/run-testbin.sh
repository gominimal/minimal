#!/usr/bin/env bash
# Run a prebuilt cargo test harness by target name, resolved through the
# testbins.json manifest the build job wrote next to the binaries. Replaces
# the fragile `ls -1t target/debug/deps/<name>-* | grep -v .d | head -1`
# pattern: the manifest records exactly which hash-suffixed binary cargo
# produced, so a stale sibling from an older build can never be picked up.
#
# Usage: run-testbin.sh <testbed-dir> <target-name> [harness args...]
#   testbins.json: {"<target-name>": "<binary basename>", ...}
set -euo pipefail

TESTBED="${1:?usage: run-testbin.sh <testbed-dir> <target-name> [args...]}"
NAME="${2:?usage: run-testbin.sh <testbed-dir> <target-name> [args...]}"
shift 2

MANIFEST="$TESTBED/testbins.json"
test -f "$MANIFEST" || { echo "::error::no manifest at $MANIFEST" >&2; exit 1; }

bin="$(jq -er --arg name "$NAME" '.[$name]' "$MANIFEST")" \
  || { echo "::error::no '$NAME' entry in $MANIFEST" >&2; exit 1; }
exe="$TESTBED/$bin"
test -x "$exe" || { echo "::error::test binary $exe missing or not executable" >&2; exit 1; }

exec "$exe" "$@"
