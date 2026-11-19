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
# Set E2E_TIMEOUT_KILL_AFTER to a number of seconds to also send SIGKILL
# when CMD is still running that long after the SIGTERM, on every path. The
# result is still 124. Unset, only SIGTERM is sent, and a CMD that does not
# exit on it keeps the call waiting.
#
# The function is safe under `set -e`: it returns the code and does not exit.

e2e_timeout() {
  local secs="$1" kill_after="${E2E_TIMEOUT_KILL_AFTER:-}"
  shift
  local gnu=""
  if command -v timeout >/dev/null 2>&1; then
    gnu=timeout
  elif command -v gtimeout >/dev/null 2>&1; then
    gnu=gtimeout
  fi
  if [ -n "$gnu" ]; then
    if [ -z "$kill_after" ]; then
      "$gnu" "$secs" "$@"
      return
    fi
    # With -k, GNU timeout exits 137 when it had to send the SIGKILL. That
    # is still a timeout, so it is reported as one. A command that is killed
    # some other way before the limit also ends with 137, so the elapsed
    # time decides which it was.
    local grc=0 started=$SECONDS
    "$gnu" -k "$kill_after" "$secs" "$@" || grc=$?
    if [ "$grc" -eq 137 ] && [ $((SECONDS - started)) -ge "$secs" ]; then
      return 124
    fi
    return "$grc"
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
    # The limit has passed, and from here the verdict is this watcher's own.
    # The caller stops the watcher as soon as CMD ends, and CMD ends because
    # of the kill below: a TERM that lands between that kill and the exit
    # would run the trap, exit 0, and report an ended CMD as one that ended
    # by itself with 143. So TERM is ignored from here on.
    trap '' TERM
    # CMD can end before the parent reaps it. kill still succeeds on that
    # zombie, so check the state first: a zombie ended in time. Without ps
    # the check finds nothing and the kill decides.
    case "$(ps -o stat= -p "$cmd_pid" 2>/dev/null)" in
      Z*) exit 0 ;;
    esac
    # CMD can still end between the check and the kill. Then it ended at the
    # limit, and 124 is the GNU timeout answer for that case too.
    kill -TERM "$cmd_pid" 2>/dev/null || exit 0
    # With E2E_TIMEOUT_KILL_AFTER set, give CMD that long to exit on the
    # TERM, checking once a second so the call returns as soon as it does,
    # then send SIGKILL.
    if [ -n "$kill_after" ]; then
      waited=0
      while [ "$waited" -lt "$kill_after" ] && kill -0 "$cmd_pid" 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
      done
      kill -KILL "$cmd_pid" 2>/dev/null || true
    fi
    exit 3
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
