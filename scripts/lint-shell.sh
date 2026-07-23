#!/usr/bin/env bash
# Lint every shell script under scripts/ with shellcheck.
#
# WHY THIS EXISTS
# ---------------
# The frozen `ci-shell-installer.yml` shellcheck job only lints
# `scripts/install.sh` and `scripts/install_test.sh`; every other script in
# this directory was unchecked, so a PR touching them reported a misleading
# "skipping" shellcheck context (issue #899). Widening that job means editing
# `.github/workflows/`, which is CODEOWNER-gated and frozen. Instead this
# harness lints the whole directory and is picked up by CI through a
# convention-discovered workspace test (crates/common/tests/shell_lint.rs) and
# the `just lint-shell` recipe — the reviewed-code extension point CI schedules
# over (docs/ci-strategy.md §10).
#
# Dialect is taken from each script's own shebang (shellcheck auto-detects it),
# matching the `apparmor` job's shebang-based `shellcheck` call. install.sh and
# install_test.sh carry `#!/bin/sh`, so they are still linted as strict POSIX
# sh here, in addition to the dedicated frozen gate.
#
# When shellcheck is not installed this skips with a clear message and exits 0,
# so local runs on machines without it (and CI lanes that lack it) do not hard
# fail. Pass --strict, or set LINT_SHELL_STRICT=1, to make a missing shellcheck
# an error instead. The primary Linux CI lane (ubuntu-latest) ships shellcheck,
# so the gate runs for real there and fails on findings.
set -euo pipefail

strict="${LINT_SHELL_STRICT:-0}"
case "${1:-}" in
    --strict) strict=1 ;;
    "") ;;
    *) echo "usage: $0 [--strict]" >&2; exit 2 ;;
esac

# Resolve the repo's scripts/ directory relative to this file, so the harness
# works regardless of the caller's working directory.
here="$(cd "$(dirname "$0")" && pwd)"

if ! command -v shellcheck >/dev/null 2>&1; then
    msg="shellcheck not installed"
    if [ "$strict" = "1" ]; then
        echo "lint-shell: $msg (strict mode)" >&2
        exit 1
    fi
    echo "lint-shell: $msg — skipping static check" >&2
    exit 0
fi

failed=0
checked=0
for f in "$here"/*.sh; do
    [ -e "$f" ] || continue
    # Only lint files that actually declare a shell interpreter.
    read -r shebang <"$f" || true
    case "$shebang" in
        '#!'*sh*) ;;
        *) continue ;;
    esac
    checked=$((checked + 1))
    if ! shellcheck "$f"; then
        failed=$((failed + 1))
    fi
done

if [ "$checked" -eq 0 ]; then
    # Discovery broke (moved scripts, wrong $here) — never pass green having
    # linted nothing; that is the exact false-signal this harness exists to end.
    echo "lint-shell: found no scripts to check under $here" >&2
    exit 1
fi
if [ "$failed" -gt 0 ]; then
    echo "lint-shell: $failed of $checked script(s) failed shellcheck" >&2
    exit 1
fi
echo "lint-shell: $checked script(s) passed shellcheck"
