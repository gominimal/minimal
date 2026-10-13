#!/usr/bin/env bash
#
# zoned-macos-e2e.sh — prove the macOS box-name service install end to end:
# the privileged command `min` hands an operator, run for real, leaves a
# root-owned minzoned LaunchDaemon that answers `*.min.internal` through the
# system resolver, serves its channel to the operator, refuses root, survives
# a restart, and tears down without a trace.
#
# WHY: session-e2e.sh holds these proofs too, but behind
# MINIMAL_E2E_PRIVILEGED=1, and the self-hosted Mac fleet runs without sudo
# (it runs PR code, so sudo there is root for any PR). GitHub-hosted macOS
# runners are ephemeral and grant sudo, but cannot boot a VM — so this
# script proves the service with no VM: scripts/zoned-e2e-publisher.py
# stands in for the node and publishes a box row over the channel.
#
# The service is installed the way a release installs it: from an app bundle.
# A release ships `minzoned` inside a signed Minimal.app, the command copies
# the bundle to a root-owned path, and both launchd jobs run the program
# inside that copy. This script assembles the same bundle, unsigned, beside
# `min` (scripts/build-app-bundle.sh), so `min` finds it as a release's `min`
# does, and removes it again on exit.
#
# What it does NOT prove: the codesign requirement, and how macOS lists the
# jobs under Login Items & Extensions. A debug `min` pins every installed
# file by SHA but skips the signing-identity check, the hosted runner has no
# signing identity to check against, and macOS names a job after its bundle
# only when the bundle is signed with a Developer ID.
#
# Usage: MINIMAL_E2E_PRIVILEGED=1 scripts/zoned-macos-e2e.sh MIN_BIN
#   MIN_BIN is a debug `min` with `minzoned` beside it. The script refuses a
#   host that already carries the service or the resolver file, and its EXIT
#   trap removes everything the command installed.
set -euo pipefail

LABEL=dev.gominimal.zone
PLIST=/Library/LaunchDaemons/$LABEL.plist
BUNDLE=/Library/PrivilegedHelperTools/Minimal.app
PROGRAM=$BUNDLE/Contents/MacOS/minzoned
# Where an install from before the bundle put the program.
LEGACY_PROGRAM=/Library/PrivilegedHelperTools/minzoned
CHANNEL="/Library/Application Support/minimal/run/answerer.sock"
RANGE_LABEL=dev.minimal.local-range
RANGE_VERB=reserve-local-range
# The script a range unit runs where no bundle is installed; this install
# leaves none.
RANGE_SCRIPT=/Library/PrivilegedHelperTools/$RANGE_LABEL
RANGE_PLIST=/Library/LaunchDaemons/$RANGE_LABEL.plist
RESOLVER=/etc/resolver/min.internal
PORT=7656
BOX=zoned-e2e
NODE=zoned-e2e-node

here="$(cd "$(dirname "$0")" && pwd)"
publisher="$here/zoned-e2e-publisher.py"

fail() {
  echo "::error::$*"
  exit 1
}

# --- 0. Preconditions --------------------------------------------------------

[ "$(uname -s)" = Darwin ] || fail "this proof is macOS only"
[ "${MINIMAL_E2E_PRIVILEGED:-}" = 1 ] \
  || fail "set MINIMAL_E2E_PRIVILEGED=1: this script installs a root LaunchDaemon"
sudo -n true 2>/dev/null || fail "this proof needs sudo without a password"
[ $# = 1 ] || fail "usage: $0 MIN_BIN"
min_bin="$1"
zoned_bin="$(dirname "$min_bin")/minzoned"
[ -x "$min_bin" ] || fail "no executable min at $min_bin"
[ -x "$zoned_bin" ] || fail "no executable minzoned beside min at $zoned_bin"
for tool in dig python3 plutil launchctl lsof dscacheutil; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH"
done
for path in "$PLIST" "$BUNDLE" "$LEGACY_PROGRAM" "$RANGE_PLIST" "$RESOLVER"; do
  [ ! -e "$path" ] || fail "$path already exists; this proof needs a host without the service"
done

work="$(mktemp -d)"
publisher_pid=

# The app bundle beside min, as a release lays it down. One that is already
# there is used as it is and left in place.
source_bundle="$(dirname "$min_bin")/Minimal.app"
made_source_bundle=
if [ ! -e "$source_bundle" ]; then
  "$here/build-app-bundle.sh" assemble "$zoned_bin" "$source_bundle"
  made_source_bundle=yes
fi
BUNDLE_FILES="Contents/MacOS/minzoned Contents/Info.plist Contents/Resources/AppIcon.icns"

# --- Teardown ----------------------------------------------------------------

# Removes everything the command installs, idempotently and best-effort.
remove_service() {
  sudo launchctl bootout "system/$LABEL" >/dev/null 2>&1 || true
  sudo launchctl bootout "system/$RANGE_LABEL" >/dev/null 2>&1 || true
  sudo rm -f "$PLIST" "$LEGACY_PROGRAM" "$CHANNEL" "$RANGE_PLIST" "$RANGE_SCRIPT" "$RESOLVER" || true
  sudo rm -rf "$BUNDLE" "$BUNDLE.old" || true
  sudo rmdir "$(dirname "$CHANNEL")" 2>/dev/null || true
  for n in $(seq 1 254); do
    sudo ifconfig lo0 -alias 127.0.64."$n" >/dev/null 2>&1 || true
  done
}

stop_publisher() {
  [ -n "$publisher_pid" ] || return 0
  kill "$publisher_pid" 2>/dev/null || true
  wait "$publisher_pid" 2>/dev/null || true
  publisher_pid=
}

on_exit() {
  local status=$?
  set +e
  stop_publisher
  if [ "$status" != 0 ]; then
    echo "--- publisher log"
    cat "$work/publisher.log" 2>/dev/null
    echo "--- launchctl print system/$LABEL"
    sudo launchctl print "system/$LABEL" 2>&1 | head -60
    echo "--- minzoned log"
    sudo log show --last 5m --style compact --predicate 'process == "minzoned"' 2>/dev/null | tail -60
  fi
  remove_service
  [ -z "$made_source_bundle" ] || rm -rf "$source_bundle"
  rm -rf "$work"
  exit "$status"
}
trap on_exit EXIT

# Answers for NAME from the service, as `STATUS ADDRESS...`.
query() {
  local out status
  out="$(dig +time=2 +tries=1 -p "$PORT" @127.0.0.1 "$1" A +noall +comments +answer)"
  status="$(sed -n 's/.*status: \([A-Z]*\),.*/\1/p' <<<"$out" | head -1)"
  echo "$status $(awk '$4 == "A" { print $5 }' <<<"$out" | xargs)"
}

# Waits up to ~10 s for NAME to answer EXPECTED (`STATUS ADDRESS...`).
expect_answer() {
  local name="$1" expected="$2" got=
  for _ in $(seq 1 40); do
    got="$(query "$name" 2>/dev/null || true)"
    got="${got% }"
    [ "$got" = "$expected" ] && return 0
    sleep 0.25
  done
  fail "$name answered '$got', expected '$expected'"
}

service_pid() {
  sudo launchctl print "system/$LABEL" 2>/dev/null | awk '$1 == "pid" { print $3; exit }'
}

# --- 1. The command ----------------------------------------------------------

echo "::group::the install command"
cmd="$("$min_bin" debug-answerer-command)"
printf '%s\n' "$cmd"
grep -q "minzoned" <<<"$cmd" || fail "the command does not install minzoned"
grep -q 'Minimal.app/Contents/Info.plist' <<<"$cmd" \
  || fail "the command does not install the app bundle beside min"
grep -q "launchctl bootstrap system $PLIST" <<<"$cmd" \
  || fail "the command does not bootstrap $LABEL"
# `min finalize-install` runs this script with `sudo sh`, its one elevation, so
# no step may call sudo itself (comment lines may name it).
case "$cmd" in '#!/bin/sh'*) ;; *) fail "the command is not a /bin/sh script" ;; esac
if grep -v '^[[:space:]]*#' <<<"$cmd" | grep -q 'sudo'; then
  fail "a step of the command calls sudo itself"
fi
echo "::endgroup::"

# --- 2. Run it ---------------------------------------------------------------

echo "::group::run the command"
sudo -n sh -c "$cmd" || fail "the install command exited non-zero"
echo "::endgroup::"

# --- 3. Custody --------------------------------------------------------------

echo "::group::custody"
for spec in "$BUNDLE 755" "$BUNDLE/Contents 755" "$BUNDLE/Contents/MacOS 755" "$PROGRAM 755" \
  "$BUNDLE/Contents/Info.plist 644" "$BUNDLE/Contents/Resources/AppIcon.icns 644" \
  "$PLIST 644" "$RANGE_PLIST 644" "$RESOLVER 644"; do
  path="${spec% *}"
  mode="${spec##* }"
  got="$(stat -f '%u %Lp' "$path")" || fail "$path is missing"
  [ "$got" = "0 $mode" ] || fail "$path is '$got' (uid mode), expected '0 $mode'"
done
[ "$(plutil -extract ProgramArguments.0 raw -o - "$PLIST")" = "$PROGRAM" ] \
  || fail "the plist does not run $PROGRAM"
[ "$(plutil -extract UserName raw -o - "$PLIST")" = "$(id -un)" ] \
  || fail "the plist does not run the service as the operator ($(id -un))"
# The range unit runs the same program, by its one verb, and has no script.
[ "$(plutil -extract ProgramArguments.0 raw -o - "$RANGE_PLIST")" = "$PROGRAM" ] \
  || fail "the range plist does not run $PROGRAM"
[ "$(plutil -extract ProgramArguments.1 raw -o - "$RANGE_PLIST")" = "$RANGE_VERB" ] \
  || fail "the range plist does not run the $RANGE_VERB verb"
[ ! -e "$RANGE_SCRIPT" ] || fail "$RANGE_SCRIPT exists; the range unit runs the bundle's program"
[ ! -e "$LEGACY_PROGRAM" ] || fail "$LEGACY_PROGRAM exists; the program is installed in the bundle"
# Both units name the bundle they run from.
bundle_id="$(plutil -extract CFBundleIdentifier raw -o - "$BUNDLE/Contents/Info.plist")" \
  || fail "the installed bundle's Info.plist names no identifier"
for plist in "$PLIST" "$RANGE_PLIST"; do
  [ "$(plutil -extract AssociatedBundleIdentifiers.0 raw -o - "$plist")" = "$bundle_id" ] \
    || fail "$plist does not name the bundle $bundle_id"
done
for file in $BUNDLE_FILES; do
  cmp -s "$source_bundle/$file" "$BUNDLE/$file" \
    || fail "the installed $file differs from its source"
done
for left in /Library/PrivilegedHelperTools/.Minimal.app.* "$BUNDLE.old"; do
  [ ! -e "$left" ] || fail "the install left $left behind"
done
version="$("$PROGRAM" --protocol-version)" || fail "the installed minzoned does not run"
echo "channel protocol version $version"
grep -q "port $PORT" "$RESOLVER" || fail "$RESOLVER does not point at port $PORT"
echo "custody OK: root-owned bundle, plists and resolver file; service runs as $(id -un)"
echo "::endgroup::"

# --- 4. The service is up ----------------------------------------------------

echo "::group::the service is up"
sudo launchctl print "system/$LABEL" >/dev/null || fail "launchd does not hold $LABEL"
for _ in $(seq 1 40); do
  [ -S "$CHANNEL" ] && break
  sleep 0.25
done
[ -S "$CHANNEL" ] || fail "the channel socket $CHANNEL is missing"
binds="$(sudo lsof -nP -iUDP:"$PORT" | awk 'NR > 1 { print $9 }' | sort -u)"
[ "$binds" = "127.0.0.1:$PORT" ] || fail "UDP $PORT binds '$binds', expected only 127.0.0.1:$PORT"
expect_answer host.min.internal "NOERROR 127.0.0.1"
expect_answer nobody.min.internal "NXDOMAIN"
got="$(query example.com)"
[ "${got%% *}" = REFUSED ] || fail "an out-of-zone name answered '$got', expected REFUSED"
# The range job adds its aliases one ifconfig call at a time after load,
# so the count climbs for a while.
aliases=0
for _ in $(seq 1 120); do
  aliases="$(ifconfig lo0 | grep -c -- 'inet 127\.0\.64\.' || true)"
  [ "$aliases" = 254 ] && break
  sleep 0.5
done
[ "$aliases" = 254 ] || fail "lo0 carries $aliases of 254 range aliases after 60 s"
dscacheutil -q host -a name host.min.internal | grep -q 'ip_address: 127.0.0.1' \
  || fail "the system resolver does not answer host.min.internal"
echo "::endgroup::"

# --- 5. A node publishes -----------------------------------------------------

echo "::group::a node publishes a box"
python3 "$publisher" hold "$CHANNEL" "$NODE" "$BOX" "$version" "$work/address" >"$work/publisher.log" 2>&1 &
publisher_pid=$!
for _ in $(seq 1 40); do
  [ -s "$work/address" ] && break
  sleep 0.25
done
[ -s "$work/address" ] || fail "the publisher never got an address"
address="$(cat "$work/address")"
case "$address" in 127.0.64.*) ;; *) fail "the allocated address $address is outside 127.0.64.0/24" ;; esac
expect_answer "$BOX.min.internal" "NOERROR $address"
dscacheutil -q host -a name "$BOX.min.internal" | grep -q "ip_address: $address" \
  || fail "the system resolver does not answer $BOX.min.internal"
echo "$BOX.min.internal -> $address"
echo "::endgroup::"

echo "::group::root is refused"
# The log is the operator's file: the redirect stays outside sudo on purpose.
# shellcheck disable=SC2024
if sudo python3 "$publisher" once "$CHANNEL" root-node intruder "$version" \
  >"$work/root.log" 2>&1; then
  cat "$work/root.log"
  fail "a root publisher was accepted"
fi
grep -q "is refused" "$work/root.log" || { cat "$work/root.log"; fail "root was not refused by the uid gate"; }
expect_answer intruder.min.internal "NXDOMAIN"
echo "::endgroup::"

# --- 6. Restart --------------------------------------------------------------

echo "::group::the service survives a restart"
before="$(service_pid)"
[ -n "$before" ] || fail "the service has no pid"
sudo launchctl kickstart -k "system/$LABEL" || fail "kickstart -k failed"
after=
for _ in $(seq 1 40); do
  after="$(service_pid)"
  [ -n "$after" ] && [ "$after" != "$before" ] && break
  sleep 0.25
done
if [ -z "$after" ] || [ "$after" = "$before" ]; then
  fail "the service pid did not change ($before -> $after)"
fi
expect_answer host.min.internal "NOERROR 127.0.0.1"
expect_answer "$BOX.min.internal" "NOERROR $(cat "$work/address")"
echo "restarted ($before -> $after); the node re-published"
echo "::endgroup::"

echo "::group::a closed connection withdraws its rows"
stop_publisher
expect_answer "$BOX.min.internal" "NXDOMAIN"
echo "::endgroup::"

# --- 7. Re-run ---------------------------------------------------------------

echo "::group::the command re-runs clean"
sudo -n sh -c "$cmd" || fail "re-running the install command exited non-zero"
expect_answer host.min.internal "NOERROR 127.0.0.1"
# The re-run replaced the bundle whole, under a running service.
for file in $BUNDLE_FILES; do
  cmp -s "$source_bundle/$file" "$BUNDLE/$file" \
    || fail "after the re-run the installed $file differs from its source"
done
for left in /Library/PrivilegedHelperTools/.Minimal.app.* "$BUNDLE.old"; do
  [ ! -e "$left" ] || fail "the re-run left $left behind"
done
echo "::endgroup::"

# --- 8. Teardown leaves nothing ----------------------------------------------

echo "::group::teardown leaves nothing"
remove_service
if sudo launchctl print "system/$LABEL" >/dev/null 2>&1; then fail "launchd still holds $LABEL"; fi
for path in "$PLIST" "$BUNDLE" "$LEGACY_PROGRAM" "$CHANNEL" "$RANGE_PLIST" "$RANGE_SCRIPT" "$RESOLVER"; do
  [ ! -e "$path" ] || fail "$path survived the teardown"
done
if sudo lsof -nP -iUDP:"$PORT" >/dev/null 2>&1; then fail "UDP $PORT is still bound"; fi
left="$(ifconfig lo0 | grep -c -- 'inet 127\.0\.64\.' || true)"
[ "$left" = 0 ] || fail "$left range aliases survived the teardown"
echo "::endgroup::"

echo "minzoned macOS service proof OK"
