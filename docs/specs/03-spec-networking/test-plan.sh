#!/usr/bin/env bash
# minimald Networking Epic (#478) — CLI test plan, executable form.
#
# RULE: never use `attach -c`. Every per-session networking assertion runs INSIDE
# the sandbox via the full interactive session path (`minimal attach <sess>`),
# driven with a real PTY via expect. attach -c / the exec path runs on the daemon
# host in the guest ROOT netns and bypasses the sandbox, so it cannot prove a
# session's isolation or own-ip behaviour.
#
# RULE: one pty per process. Every concurrently-live session gets its OWN OS
# process draining its OWN pty (one `run_in_session`/expect per session,
# backgrounded). NEVER drive two `attach` sessions from a single expect via two
# spawn ids read one-at-a-time: `attach` exec's `ssh -tt`, whose pty has a fixed
# ~16KB kernel buffer. While the one process drains session A, session B's ssh
# keeps writing shell-setup into B's pty; nobody reads it, it fills, ssh blocks on
# write, and B's RequestShell never reaches the daemon. boot.log then shows a
# second attach that "wedged" — but it is the client starving its own pty, not a
# server-side hang. Warm each session once before any timed/concurrent trial so
# the first-attach sandbox build (up to ATTACH_TIMEOUT) doesn't mask the signal.
#
# PORTABILITY: targets the minvmd VM deployment (DM1) — macOS/HVF and Linux/KVM
# are identical (the sandbox guest is Linux on every host; the CLI + expect + host
# curls are the same). The only host-specific bit is the mTLS cert dir (CERT_DIR
# below). On native Linux (DM2, minimald with no VM) the same test commands apply,
# but bring-up is minimald-native (no `just up`) and the proxies bind host loopback
# directly (no gvproxy host-expose).
#
# Run from the repo root with the daemon up (DM1: `just up`).
# In-session tools: sh bash curl getent coreutils socat. NOT present: ip nc wget python.
# Switch-IP discovery therefore uses /proc/net/fib_trie, not `ip`.
set -u
M="$PWD/target/debug/minimal"
ATTACH_TIMEOUT=180     # first attach builds the sandbox; be generous
# mTLS client-cert dir written by `minimal login` (dirs crate): macOS uses
# Application Support, Linux/XDG uses ~/.config.
case "$(uname -s)" in
  Darwin) CERT_DIR="$HOME/Library/Application Support/minimal" ;;
  *)      CERT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/minimal" ;;
esac
command -v expect >/dev/null || { echo "FATAL: expect not found"; exit 1; }

# Per-step wall-clock guard. A flaky own-ip attach (intermittent vsock
# missed-wakeup) can wedge an `expect` block with no internal bound; cap every
# step so one hang can't stall the whole plan. macOS ships `gtimeout` (coreutils),
# Linux ships `timeout`; degrade to no guard if neither exists.
STEP_TIMEOUT="${STEP_TIMEOUT:-360}"
if command -v gtimeout >/dev/null; then TO="gtimeout $STEP_TIMEOUT"
elif command -v timeout >/dev/null; then TO="timeout $STEP_TIMEOUT"
else TO=""; fi

banner() { printf '\n########## %s ##########\n' "$*"; }
destroy() { for s in "$@"; do "$M" destroy "$s" >/dev/null 2>&1; done; }

# Best-effort cleanup on ANY exit (success, error, or interrupt): tear down every
# session the plan can create and kill any backgrounded job (the TC8 ssh-forward),
# so an early exit never leaves running sessions or a stray port-forward behind.
ALL_SESSIONS="bad1 bad2 bad3 demo dev peer tc1 tc1b tc4 tc6 tc7 web"
cleanup() {
  local pids
  pids="$(jobs -p)"
  [ -n "$pids" ] && kill $pids 2>/dev/null
  destroy $ALL_SESSIONS
}
trap cleanup EXIT INT TERM

# run_in_session <sess> <bash-script>
# Opens the interactive sandbox shell, runs the script, prints everything between
# __RIS_BEGIN__ and __RIS_END__:<rc>. Pure full-session-path; no attach -c.
run_in_session() {
  local sess="$1" script="$2"
  RIS_SESS="$sess" RIS_SCRIPT="$script" RIS_TO="$ATTACH_TIMEOUT" RIS_M="$M" $TO expect <<'EXP'
set sess   $env(RIS_SESS)
set script $env(RIS_SCRIPT)
set m      $env(RIS_M)
set timeout $env(RIS_TO)
# Line-buffer stdout so a per-step SIGKILL (gtimeout) can't discard a verdict
# still sitting in expect's block buffer when it writes to a pipe.
fconfigure stdout -buffering line
log_user 0
spawn $m attach $sess
# Readiness: poll a marker until the in-sandbox bash echoes it back. Absorbs the
# slow first attach (sandbox build) without depending on the prompt string.
set ready 0
for {set i 0} {$i < 90} {incr i} {
  send "echo __RIS_READY__\r"
  expect {
    -timeout 4 "__RIS_READY__\r\n" { set ready 1 }
    timeout {}
  }
  if {$ready} break
}
if {!$ready} { send "exit\r"; puts "__RIS_BEGIN__"; puts "RIS_NOT_READY (attach never reached a shell)"; puts "__RIS_END__:255"; exit 0 }
# Quiet the terminal so only command output is captured.
send "stty -echo; PS1=''\r"
expect -timeout 5 "__RIS_READY__" {} timeout {}
log_user 1
send "echo __RIS_BEGIN__\r"
send "$script\r"
send "echo __RIS_END__:\$?\r"
expect {
  -timeout $env(RIS_TO) -re "__RIS_END__:(\[0-9\]+)" {}
  timeout { puts "\n__RIS_END__:254 (timeout)" }
}
log_user 0
send "exit\r"
expect eof
EXP
}

# capture_only <sess> <script> : strip ANSI + readiness noise, return BEGIN..END body
session_out() {
  run_in_session "$1" "$2" 2>&1 \
    | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' \
    | awk '/__RIS_BEGIN__/{f=1;next} /__RIS_END__/{print "EXIT="substr($0,index($0,":")+1);f=0} f'
}

banner "BRING-UP"
"$M" ls

banner "TC1 — UC1 NoNet isolation (faithful, in-sandbox)"
destroy tc1
"$M" activate -n tc1 --network no-net . >/dev/null 2>&1
echo "-- in-sandbox: expect only 'lo', curl FAILS, getent FAILS --"
session_out tc1 'echo IFACES=$(ls /sys/class/net/ | tr "\n" ","); curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com 2>&1 || echo CURL_FAILED; getent hosts github.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED'
destroy tc1

banner "TC1b — host-net egress (positive control, in-sandbox)"
destroy tc1b
"$M" activate -n tc1b --network host-net . >/dev/null 2>&1
echo "-- in-sandbox: curl 200 + DNS resolves --"
session_out tc1b 'curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com; getent hosts github.com | head -1'
destroy tc1b

banner "TC2 — UC6 OwnIp egress + same-host peer (two full sessions)"
destroy demo peer
"$M" activate -n demo --network own-ip . >/dev/null 2>&1
"$M" activate -n peer --network own-ip . >/dev/null 2>&1
echo "-- demo egress (in-sandbox, via shuttle): expect 200 --"
session_out demo 'curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com'
echo "-- peer<-demo over the switch: socat listener in peer, curl from demo --"
# CONCURRENCY RULE (see header): peer and demo are live at the same time, so each
# runs in its OWN process/pty — NOT one expect multiplexing two spawn ids. The
# peer listener is a backgrounded `run_in_session`; demo dials it from a separate
# `session_out`. Reading peer's switch IP first also warms peer's sandbox, so the
# timed listener trial isn't racing a cold first-attach build.
peer_ip="$(session_out peer 'grep -oE "100\.64\.[0-9]+\.[0-9]+" /proc/net/fib_trie | grep -v "\.0$" | head -1' | grep -aoE '100\.64\.[0-9]+\.[0-9]+' | head -1)"
echo "peer switch IP: ${peer_ip:-UNKNOWN}"
# peer listener: its own process/pty, backgrounded. socat runs in the background;
# the `sleep` keeps the session (hence its pty, drained by this process) alive
# while demo connects. Killed once demo is done.
run_in_session peer 'socat TCP-LISTEN:9000,reuseaddr,fork SYSTEM:"printf PEER_REACHED" & sleep 45' >/dev/null 2>&1 &
peer_job=$!
sleep 3   # give the backgrounded listener process time to attach + bind
if [ -n "$peer_ip" ]; then
  # Retry inside the sandbox so listener-bind latency (the peer attach + socat
  # startup) can't cause a false negative — poll for up to ~12s. Track success in
  # an explicit flag (a trailing `$?` would just be the loop's `sleep`, always 0),
  # and assert on the response BODY: socat's `printf PEER_REACHED` is a raw
  # (HTTP/0.9) reply, so curl's exit status is unreliable — `--http0.9` lets curl
  # surface the body, which we grep for the actual proof of reachability.
  session_out demo "reached=NO; for i in \$(seq 1 12); do if curl --max-time 3 -sS --http0.9 http://$peer_ip:9000/ 2>/dev/null | grep -q PEER_REACHED; then reached=YES; break; fi; sleep 1; done; echo TC2_PEER=\$reached"
else
  echo "TC2_PEER=peer-ip-unavailable"
fi
kill "$peer_job" 2>/dev/null; wait "$peer_job" 2>/dev/null
destroy demo peer

banner "TC3 — UC2 managed DNS via host proxy :7654 (server in-sandbox, host curls)"
destroy web
"$M" activate -n web --network own-ip . >/dev/null 2>&1
# Start an http server INSIDE the session and keep it alive while the host curls.
RIS_M="$M" SESS=web RIS_TO="$ATTACH_TIMEOUT" $TO expect <<'EXP' 2>&1 | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' | grep -aE 'TC3_'
set m $env(RIS_M); set timeout $env(RIS_TO)
fconfigure stdout -buffering line
proc ready {} { for {set i 0} {$i<90} {incr i} { send "echo __R__\r"; expect { -timeout 4 "__R__\r\n" {return 1} timeout {} } }; return 0 }
spawn $m attach $env(SESS); ready
send "stty -echo; PS1=''\r"
send "socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf \"HTTP/1.0 200 OK\\r\\n\\r\\nWEB_OK\"' & sleep 1; echo SERVER_UP\r"
expect -timeout 15 "SERVER_UP" {}
# host-side check while the in-session server is alive:
set rc [catch {exec curl --max-time 6 -sS -x http://127.0.0.1:7654 -w "TC3_HTTP=%{http_code}\n" http://web.local.min.internal/} out]
puts "TC3_HOST_RESULT: $out"
send "exit\r"; expect eof
EXP
destroy web

banner "TC4 — UC4 static ingress 18080:80 (server in-sandbox, host curls)"
destroy tc4
"$M" activate -n tc4 --network own-ip --ingress 18080:80 . >/dev/null 2>&1
"$M" session policy tc4
RIS_M="$M" SESS=tc4 RIS_TO="$ATTACH_TIMEOUT" $TO expect <<'EXP' 2>&1 | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' | grep -aE 'TC4_'
set m $env(RIS_M); set timeout $env(RIS_TO)
fconfigure stdout -buffering line
proc ready {} { for {set i 0} {$i<90} {incr i} { send "echo __R__\r"; expect { -timeout 4 "__R__\r\n" {return 1} timeout {} } }; return 0 }
spawn $m attach $env(SESS); ready
send "stty -echo; PS1=''\r"
send "socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf \"HTTP/1.0 200 OK\\r\\n\\r\\nINGRESS_OK\"' & sleep 1; echo SERVER_UP\r"
expect -timeout 15 "SERVER_UP" {}
set rc [catch {exec curl --max-time 6 -sS -o /dev/null -w "TC4_HTTP=%{http_code}\n" http://127.0.0.1:18080/} out]
puts "TC4_HOST_RESULT: $out"
send "exit\r"; expect eof
EXP
destroy tc4

banner "TC5 — policy validation (CLI-only; expect REJECTIONS, no session)"
destroy bad1 bad2 bad3
"$M" activate -n bad1 --network host-net --ingress 18080:80 .    # ingress requires own-ip
"$M" activate -n bad2 --network own-ip  --ingress 80:80 .        # privileged host port
"$M" activate -n bad3 --network own-ip  --ingress 18080:80/icmp . # bad proto
echo "-- none should exist --"; "$M" ls
destroy bad1 bad2 bad3

banner "TC6 — live policy round-trip (CLI-only; no attach needed)"
destroy tc6
"$M" activate -n tc6 --network own-ip --ingress 18080:80/tcp . >/dev/null 2>&1
"$M" session policy tc6
destroy tc6

banner "TC7 — UC2b mTLS reverse proxy :7655 (backend in-sandbox, host curls)"
"$M" login
ls -l "$CERT_DIR/" 2>&1 | tail -4
destroy tc7
"$M" activate -n tc7 --network own-ip . >/dev/null 2>&1
RIS_M="$M" SESS=tc7 CERTDIR="$CERT_DIR" RIS_TO="$ATTACH_TIMEOUT" $TO expect <<'EXP' 2>&1 | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' | grep -aE 'TC7_'
set m $env(RIS_M); set timeout $env(RIS_TO); set cd $env(CERTDIR)
fconfigure stdout -buffering line
proc ready {} { for {set i 0} {$i<90} {incr i} { send "echo __R__\r"; expect { -timeout 4 "__R__\r\n" {return 1} timeout {} } }; return 0 }
spawn $m attach $env(SESS); ready
send "stty -echo; PS1=''\r"
send "socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf \"HTTP/1.0 200 OK\\r\\n\\r\\nBACKEND_OK\"' & sleep 1; echo SERVER_UP\r"
expect -timeout 15 "SERVER_UP" {}
set rc1 [catch {exec curl --max-time 6 -sS -o /dev/null -w "TC7_WITHCERT=%{http_code}\n" --cacert "$cd/ca.pem" --cert "$cd/client.pem" --key "$cd/client.key" https://localhost:7655/} o1]
puts "TC7_WITHCERT_RESULT: $o1"
set rc2 [catch {exec curl --max-time 6 -sS -k -o /dev/null -w "TC7_NOCERT=%{http_code}\n" https://localhost:7655/} o2]
puts "TC7_NOCERT_RESULT: $o2"
send "exit\r"; expect eof
EXP
destroy tc7

banner "TC8 — ssh-forward (server in-sandbox, host curls through the forward)"
destroy dev
"$M" activate -n dev --network own-ip --ingress 18080:80 . >/dev/null 2>&1
RIS_M="$M" SESS=dev RIS_TO="$ATTACH_TIMEOUT" $TO expect <<'EXP' 2>&1 | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' | grep -aE 'TC8_'
set m $env(RIS_M); set timeout $env(RIS_TO)
fconfigure stdout -buffering line
proc ready {} { for {set i 0} {$i<90} {incr i} { send "echo __R__\r"; expect { -timeout 4 "__R__\r\n" {return 1} timeout {} } }; return 0 }
spawn $m attach $env(SESS); ready
send "stty -echo; PS1=''\r"
send "socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf \"HTTP/1.0 200 OK\\r\\n\\r\\nFORWARD_OK\"' & sleep 1; echo SERVER_UP\r"
expect -timeout 15 "SERVER_UP" {}
# set up the forward + curl through it (both host-side) while the in-session server lives
set fpid [exec $m ssh-forward $env(SESS) 18080:127.0.0.1:80 >/tmp/fwd.log 2>&1 &]
after 3000
set rc [catch {exec curl --max-time 6 -sS -o /dev/null -w "TC8_HTTP=%{http_code}\n" http://localhost:18080/} out]
puts "TC8_HOST_RESULT: $out"
catch {exec kill $fpid}
send "exit\r"; expect eof
EXP
destroy dev

banner "TC9 — UC7 WireGuard mesh (CLI surface; data-path is Linux-netns only)"
"$M" mesh status
"$M" mesh join 127.0.0.1:51820
"$M" mesh leave

banner "DONE"
