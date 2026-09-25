#!/usr/bin/env bash
#
# testlib.sh — the scaffolding every scripts/*_test.sh harness shares.
#
# Not a harness: it is sourced, never run, and is deliberately NOT named
# *_test.sh so the convention-discovered gate
# (crates/common/tests/shell_harnesses.rs) and `just test-shell` skip it. A
# harness sources it next to its own `here`:
#
#     here="$(cd "$(dirname "$0")" && pwd)"
#     . "$here/testlib.sh"
#
# Provides:
#   ok / bad <description>       count and print one passing / failing check
#   expect <rc> <substring> <description> -- <command...>
#   require_tools <tool>...      self-skip (exit 0) when a prerequisite is absent
#   source_function <script> <name>   reuse a production helper definition
#   finish                       print the summary; non-zero if any check failed
#
# Each harness still owns its fixtures and its own skip logic; this file only
# removes the boilerplate they all rewrote. It defines nothing that runs at
# source time, and sets no shell options — the harness owns `set -euo pipefail`.

pass=0 fail=0

# ok / bad <description> — count and print one passing / failing case.
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# expect <want_rc> <want_substring> <description> -- <command...>
# Run the command, capture its combined output, and count a check: it passes
# when the exit status AND a substring of interest both match. The `--`
# separator is mandatory, so a test bug that forgets it is reported rather
# than silently comparing the wrong arguments.
expect() {
    local want_rc="$1" want_msg="$2" desc="$3"; shift 3
    [ "${1:-}" = "--" ] || { bad "$desc (test bug: missing -- separator)"; return; }
    shift
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    if [ "$rc" -eq "$want_rc" ] && [[ "$out" == *"$want_msg"* ]]; then
        ok "$desc"
    else
        bad "$desc (want rc=$want_rc and '$want_msg'; got rc=$rc, out: $out)"
    fi
}

# require_tools <tool>... — print the harness's conventional skip note and exit
# 0 when any tool is missing, so a harness self-skips where its prerequisites
# are absent (the repo's self-skip-locally convention).
require_tools() {
    local missing="" tool
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
    done
    [ -z "$missing" ] || { echo "${0##*/}: skipping, no$missing on PATH"; exit 0; }
}

# source_function <script> <name> — eval one function definition out of another
# script, so a harness reuses the production helper instead of copying it (one
# definition, no drift). Fails loudly if the function cannot be found: an
# extraction that silently yields nothing would make every later assertion
# meaningless.
source_function() {
    local from="$1" name="$2"
    # shellcheck disable=SC2294  # eval of our own extracted definition
    eval "$(sed -n "/^${name}()/,/^}/p" "$from")"
    [ "$(type -t "$name")" = "function" ] \
        || { echo "${0##*/}: cannot extract $name from $from" >&2; exit 1; }
}

# finish — print the summary and exit non-zero if any check failed (so the
# harness's exit status is the gate's).
finish() {
    printf '\n%d passed, %d failed\n' "$pass" "$fail"
    [ "$fail" -eq 0 ]
}
