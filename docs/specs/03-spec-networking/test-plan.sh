#!/usr/bin/env bash
# minimald Networking Epic (#478) — CLI test plan, executable form.
#
# RULE: never use `attach -c`. Every per-session networking assertion runs INSIDE
# the sandbox via the full interactive session path (`minimal attach <sess>`),
# driven with a real PTY via expect. attach -c / the exec path runs on the daemon
# host in the guest ROOT netns and bypasses the sandbox, so it cannot prove a
# session's isolation or own-ip behaviour.
#
# RULE: detach, never exit. A session is like tmux: DETACH (ctrl-w) leaves the
# shell — and its network (own-ip lease + gvproxy switch attachment) — running;
# `exit` ends the shell, which by design tears the network down. So every helper
# here DETACHES when done, and only an explicit `destroy` ends a session. This is
# what keeps a backgrounded in-session server alive while the host curls it, and
# what keeps an own-ip lease STABLE across the multiple attaches a test makes
# (discover the lease once, reuse it) instead of churning a new lease per attach.
#
# RULE: one pty per process. Every concurrently-live session gets its OWN OS
# process draining its OWN pty (one `run_in_session`/expect per session). NEVER
# drive two live `attach` sessions from a single expect via two spawn ids read
# one-at-a-time: `attach` exec's `ssh -tt`, whose pty has a fixed ~16KB kernel
# buffer; while one is drained the other's ssh blocks on write and its
# RequestShell never lands. Because detach keeps sessions alive, tests here run
# their per-session steps SEQUENTIALLY (one expect at a time), not concurrently.
#
# RULE: unprivileged ports only. The sandbox runs unprivileged (uid != 0,
# CapEff=0), so it CANNOT bind ports < 1024 — `socat TCP-LISTEN:80` fails with
# EACCES. Every in-session server binds :8080 (or another high port); ingress and
# proxy checks target that port accordingly.
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
# The own-ip local switch address of a session, read from inside its sandbox
# (no `ip`): the /32 host route in the CGNAT block is this PTask's lease.
LEASE_CMD='grep -B1 "host LOCAL" /proc/net/fib_trie | grep -oE "100\.64\.0\.[0-9]+" | head -1'
# mTLS client-cert dir written by `minimal login` (dirs crate): macOS uses
# Application Support, Linux/XDG uses ~/.config.
case "$(uname -s)" in
  Darwin) CERT_DIR="$HOME/Library/Application Support/minimal" ;;
  *)      CERT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/minimal" ;;
esac
command -v expect >/dev/null || { echo "FATAL: expect not found"; exit 1; }

# Per-step wall-clock guard. A flaky attach can wedge an `expect` block with no
# internal bound; cap every step so one hang can't stall the whole plan. macOS
# ships `gtimeout` (coreutils), Linux ships `timeout`; degrade to none if absent.
STEP_TIMEOUT="${STEP_TIMEOUT:-120}"
if command -v gtimeout >/dev/null; then TO="gtimeout $STEP_TIMEOUT"
elif command -v timeout >/dev/null; then TO="timeout $STEP_TIMEOUT"
else TO=""; fi

banner() { printf '\n########## %s ##########\n' "$*"; }
destroy() { for s in "$@"; do "$M" destroy "$s" >/dev/null 2>&1; done; }

# Best-effort cleanup on ANY exit: tear down every session the plan can create
# and kill any backgrounded job (the TC8 ssh-forward), so an early exit never
# leaves running sessions or a stray port-forward behind.
ALL_SESSIONS="bad1 bad2 bad3 demo dev peer tc1 tc1b tc4 tc6 tc7 web"
cleanup() {
  local pids
  pids="$(jobs -p)"
  [ -n "$pids" ] && kill $pids 2>/dev/null
  destroy $ALL_SESSIONS
}
trap cleanup EXIT INT TERM

# run_in_session <sess> <bash-script> <nonce>
# Opens the interactive sandbox shell, runs the script, then DETACHES (ctrl-w) so
# the shell — and any backgrounded server + its network — stays alive. Emits
# everything between __RB_<nonce>__ and __RE_<nonce>__:<rc>. The nonce makes the
# markers unique per call so a reattach's replayed screen state (which may still
# show a PRIOR call's markers) can't be mistaken for this call's output. Pure
# full-session-path; no attach -c, no exit.
run_in_session() {
  local sess="$1" script="$2" nonce="$3"
  RIS_SESS="$sess" RIS_SCRIPT="$script" RIS_TO="$ATTACH_TIMEOUT" RIS_M="$M" RIS_NONCE="$nonce" $TO expect <<'EXP'
set sess   $env(RIS_SESS)
set script $env(RIS_SCRIPT)
set m      $env(RIS_M)
set timeout $env(RIS_TO)
set n      $env(RIS_NONCE)
# Line-buffer stdout so a per-step SIGKILL can't discard a verdict still sitting
# in expect's block buffer when it writes to a pipe.
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
if {!$ready} { send "\x17"; puts "__RB_${n}__"; puts "RIS_NOT_READY (attach never reached a shell)"; puts "__RE_${n}__:255"; exit 0 }
# Quiet the terminal so only command output is captured.
send "stty -echo; PS1=''\r"
expect -timeout 5 "__RIS_READY__" {} timeout {}
log_user 1
send "echo __RB_${n}__\r"
send "$script\r"
send "echo __RE_${n}__:\$?\r"
expect {
  -timeout $env(RIS_TO) -re "__RE_${n}__:(\[0-9\]+)" {}
  timeout { puts "\n__RE_${n}__:254 (timeout)" }
}
log_user 0
# DETACH (ctrl-w 0x17) -- do NOT `exit`. Keeps the shell + its network alive so a
# later attach reuses the SAME shell and SAME own-ip lease, and any backgrounded
# server keeps serving. `destroy` is the only thing that ends the session.
send "\x17"
expect eof
EXP
}

# session_out <sess> <script> : run <script> in the session, print the BEGIN..END
# body with a trailing EXIT=<rc>. ANSI + readiness noise stripped. The session is
# left ATTACHED-then-detached (alive) afterwards.
session_out() {
  local nonce="${RANDOM}${RANDOM}${RANDOM}"
  run_in_session "$1" "$2" "$nonce" 2>&1 \
    | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g' \
    | awk -v n="$nonce" '$0 ~ ("__RB_"n"__"){f=1;next} f && $0 ~ ("__RE_"n"__"){print "EXIT="substr($0,index($0,":")+1);f=0} f'
}

banner "BRING-UP"
"$M" ls

banner "TC1 — UC1 NoNet isolation (faithful, in-sandbox)"
destroy tc1
"$M" activate -n tc1 --network no-net . >/dev/null 2>&1
echo "-- in-sandbox: expect only 'lo', curl FAILS, getent FAILS --"
session_out tc1 'echo IFACES=$(ls /sys/class/net/ 2>/dev/null | tr "\n" ","); curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com 2>&1 || echo CURL_FAILED; getent hosts github.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED'
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
echo "-- demo egress (in-sandbox, via the switch): expect 200 --"
session_out demo 'curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com'
# Same-host peer: start a listener in `peer` on an UNPRIVILEGED port and read
# peer's own switch lease in the SAME attach, then DETACH. Because detach keeps
# the shell + lease alive, the listener keeps serving and the discovered IP stays
# valid for demo's dial. (The old plan read the IP in one attach and started the
# listener in another — which, per-attach leasing, targeted a stale IP. Detach
# semantics make the lease stable, so one discovery is authoritative.)
peer_ip="$(session_out peer 'socat TCP-LISTEN:8080,reuseaddr,fork "SYSTEM:printf PEER_REACHED" & sleep 1; echo PEERIP=$('"$LEASE_CMD"')' | grep -aoE '100\.64\.0\.[0-9]+' | head -1)"
echo "peer switch IP: ${peer_ip:-UNKNOWN}"
if [ -n "$peer_ip" ]; then
  # demo dials peer over the switch. socat's `printf PEER_REACHED` is a raw
  # (HTTP/0.9) reply, so assert on the BODY (curl exit status is unreliable for
  # 0.9). Retry briefly to absorb listener-bind latency; track success in an
  # explicit flag (a trailing $? would be the loop's `sleep`, always 0).
  session_out demo "reached=NO; for i in \$(seq 1 8); do if curl --max-time 3 -sS --http0.9 http://$peer_ip:8080/ 2>/dev/null | grep -q PEER_REACHED; then reached=YES; break; fi; sleep 1; done; echo TC2_PEER=\$reached"
else
  echo "TC2_PEER=peer-ip-unavailable"
fi
destroy demo peer

banner "TC3 — UC2a managed DNS via host proxy :7654 (server in-sandbox, host curls)"
destroy web
# UC2a reaches a PTask BY HOSTNAME through its PUBLISHED port (published-loopback
# model): the ingress forward publishes the PTask's :8080 on host 127.0.0.1:18080,
# minimald registers the hostname -> 127.0.0.1 (R3.1), and the :7654 proxy routes
# `web.local.min.internal:18080` to 127.0.0.1:18080 -> gvproxy -> lease:8080.
"$M" activate -n web --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
# Start an HTTP/1.0 server INSIDE the session on :8080, then DETACH (it keeps
# serving). \r\n survives bash double-quotes as a literal escape for printf.
session_out web "socat TCP-LISTEN:8080,reuseaddr,fork \"SYSTEM:printf 'HTTP/1.0 200 OK\r\n\r\nWEB_OK'\" & sleep 1; echo SERVER_UP"
echo "-- host via :7654 proxy -> web.local.min.internal:18080 (published port) --"
curl --max-time 8 -sS -x http://127.0.0.1:7654 -o /dev/null -w "TC3_HTTP=%{http_code}\n" http://web.local.min.internal:18080/ 2>&1 || echo "TC3_HTTP=curl-failed"
destroy web

banner "TC4 — UC4 static ingress 18080:8080 (server in-sandbox, host curls)"
destroy tc4
"$M" activate -n tc4 --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
"$M" session policy tc4
session_out tc4 "socat TCP-LISTEN:8080,reuseaddr,fork \"SYSTEM:printf 'HTTP/1.0 200 OK\r\n\r\nINGRESS_OK'\" & sleep 1; echo SERVER_UP"
echo "-- host -> 127.0.0.1:18080 (ingress forward -> lease:8080) --"
curl --max-time 8 -sS -o /dev/null -w "TC4_HTTP=%{http_code}\n" http://127.0.0.1:18080/ 2>&1 || echo "TC4_HTTP=curl-failed"
destroy tc4

banner "TC5 — policy validation (CLI-only; expect REJECTIONS, no session)"
destroy bad1 bad2 bad3
"$M" activate -n bad1 --network host-net --ingress 18080:8080 .    # ingress requires own-ip
"$M" activate -n bad2 --network own-ip  --ingress 80:8080 .        # privileged host port
"$M" activate -n bad3 --network own-ip  --ingress 18080:8080/icmp . # bad proto
echo "-- none should exist --"; "$M" ls
destroy bad1 bad2 bad3

banner "TC6 — live policy round-trip (CLI-only; no attach needed)"
destroy tc6
"$M" activate -n tc6 --network own-ip --ingress 18080:8080/tcp . >/dev/null 2>&1
"$M" session policy tc6
destroy tc6

banner "TC7 — UC2b mTLS reverse proxy :7655 (backend in-sandbox, host curls)"
"$M" login
ls -l "$CERT_DIR/" 2>&1 | tail -4
destroy tc7
"$M" activate -n tc7 --network own-ip . >/dev/null 2>&1
session_out tc7 "socat TCP-LISTEN:8080,reuseaddr,fork \"SYSTEM:printf 'HTTP/1.0 200 OK\r\n\r\nBACKEND_OK'\" & sleep 1; echo SERVER_UP"
echo "-- host (with cert) -> :7655 : expect 200 --"
curl --max-time 8 -sS -o /dev/null -w "TC7_WITHCERT=%{http_code}\n" --cacert "$CERT_DIR/ca.pem" --cert "$CERT_DIR/client.pem" --key "$CERT_DIR/client.key" https://localhost:7655/ 2>&1 || echo "TC7_WITHCERT=curl-failed"
echo "-- host (no cert) -> :7655 : expect 401 --"
curl --max-time 8 -sS -k -o /dev/null -w "TC7_NOCERT=%{http_code}\n" https://localhost:7655/ 2>&1 || echo "TC7_NOCERT=curl-failed"
destroy tc7

banner "TC8 — ssh-forward (server in-sandbox, host curls through the forward)"
destroy dev
"$M" activate -n dev --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
session_out dev "socat TCP-LISTEN:8080,reuseaddr,fork \"SYSTEM:printf 'HTTP/1.0 200 OK\r\n\r\nFORWARD_OK'\" & sleep 1; echo SERVER_UP"
"$M" ssh-forward dev 18080:127.0.0.1:8080 >/tmp/fwd.log 2>&1 &
fwd_pid=$!
sleep 3
echo "-- host -> localhost:18080 (through the ssh-forward) --"
curl --max-time 8 -sS -o /dev/null -w "TC8_HTTP=%{http_code}\n" http://localhost:18080/ 2>&1 || echo "TC8_HTTP=curl-failed"
kill "$fwd_pid" 2>/dev/null; wait "$fwd_pid" 2>/dev/null
destroy dev

banner "TC9 — UC7 WireGuard mesh (CLI surface; data-path is Linux-netns only)"
"$M" mesh status
"$M" mesh join 127.0.0.1:51820
"$M" mesh leave

banner "DONE"
