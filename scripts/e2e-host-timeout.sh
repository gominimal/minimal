#!/usr/bin/env bash
#
# e2e-host-timeout.sh — a host-side timeout for the e2e scripts.
#
# Source this file. It defines one function:
#
#   e2e_timeout SECS CMD [ARG...]
#
# It runs CMD with its arguments and ends it after SECS seconds, with exit
# 124, as GNU timeout does. It uses `timeout` when PATH has it, else
# `gtimeout` (Homebrew coreutils). A stock Mac has neither, so the last
# fallback runs CMD in the background, keeps its stdin, and sends it SIGTERM
# after SECS. CMD's own exit code passes through when it ends in time.
#
# The function is safe under `set -e`: it returns the code and does not exit.

e2e_timeout() {
  local secs="$1"
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
    return
  fi
  if command -v gtimeout >/dev/null 2>&1; then
    gtimeout "$secs" "$@"
    return
  fi

  # Without job control, bash gives a background command /dev/null as its
  # stdin. The explicit <&0 keeps the caller's stdin, such as a pipe.
  local cmd_pid watch_pid rc=0 watch_rc=0
  "$@" <&0 &
  cmd_pid=$!
  # The watcher exits 3 when it ended CMD. It exits 0 when it is stopped first.
  (
    sleep_pid=
    trap '[ -n "$sleep_pid" ] && kill "$sleep_pid" 2>/dev/null; exit 0' TERM
    sleep "$secs" &
    sleep_pid=$!
    wait "$sleep_pid"
    # CMD can end before the parent reaps it. kill still succeeds on that
    # zombie, so check the state first: a zombie ended in time. Without ps
    # the check finds nothing and the kill decides.
    case "$(ps -o stat= -p "$cmd_pid" 2>/dev/null)" in
      Z*) exit 0 ;;
    esac
    # CMD can still end between the check and the kill. Then it ended at the
    # limit, and 124 is the GNU timeout answer for that case too.
    if kill -TERM "$cmd_pid" 2>/dev/null; then exit 3; fi
    exit 0
  ) </dev/null &
  watch_pid=$!

  wait "$cmd_pid" || rc=$?
  kill -TERM "$watch_pid" 2>/dev/null || true
  wait "$watch_pid" || watch_rc=$?
  if [ "$watch_rc" -eq 3 ]; then
    return 124
  fi
  return "$rc"
}
