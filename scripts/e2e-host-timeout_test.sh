#!/usr/bin/env bash
#
# e2e-host-timeout_test.sh — test harness for e2e-host-timeout.sh.
#
# Runs e2e_timeout with a PATH that has no `timeout` and no `gtimeout`, as on
# a stock Mac, so the background fallback is the code under test. Run
# directly or via `just test-shell`.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
source "$here/e2e-host-timeout.sh"

root="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-timeouttest)"
trap 'rm -rf "$root"' EXIT

# A bin directory with only the tools the cases run.
mkdir "$root/bin"
# ps is optional: the helper uses it to spot a zombie, and works without it.
for tool in sleep cat sh ps; do
  path="$(command -v "$tool" || true)"
  if [ -z "$path" ]; then
    [ "$tool" = ps ] && continue
    echo "FAIL - $tool is not on PATH"
    exit 1
  fi
  ln -s "$path" "$root/bin/$tool"
done

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf 'ok   - %s\n' "$*"; }
bad() { fail=$((fail + 1)); printf 'FAIL - %s\n' "$*"; }

# Each case runs in a subshell with the reduced PATH.
(
  PATH="$root/bin"
  hash -r
  command -v timeout >/dev/null 2>&1 && exit 10
  command -v gtimeout >/dev/null 2>&1 && exit 11
  exit 0
) || { echo "FAIL - the reduced PATH still has timeout or gtimeout"; exit 1; }

rc=0
(PATH="$root/bin"; e2e_timeout 5 sh -c 'exit 7') || rc=$?
if [ "$rc" -eq 7 ]; then ok "exit code 7 passes through"; else bad "exit code: got $rc, want 7"; fi

rc=0
(PATH="$root/bin"; e2e_timeout 5 sh -c 'exit 0') || rc=$?
if [ "$rc" -eq 0 ]; then ok "exit code 0 passes through"; else bad "exit code: got $rc, want 0"; fi

rc=0
out="$(printf 'two\n' | (PATH="$root/bin"; e2e_timeout 5 cat))" || rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "two" ]; then
  ok "stdin from a pipe reaches the command"
else
  bad "stdin: got '$out' with exit $rc, want 'two' with exit 0"
fi

rc=0
t0=$SECONDS
(PATH="$root/bin"; e2e_timeout 1 sleep 30) || rc=$?
elapsed=$((SECONDS - t0))
if [ "$rc" -eq 124 ] && [ "$elapsed" -lt 10 ]; then
  ok "a long sleep ends with 124 after ${elapsed}s"
else
  bad "long sleep: got exit $rc after ${elapsed}s, want 124 well before 30s"
fi

printf '%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
