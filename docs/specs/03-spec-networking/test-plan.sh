#!/usr/bin/env bash
# minimald Networking Epic (#478) — CLI test plan, executable form, all DMs.
#
# USAGE: DM=dm1|dm2|dm3|dm4 ./test-plan.sh   (auto-detected when DM is unset:
# Darwin -> dm1; Linux -> dm3 if the minvmd bridge socket exists, else dm2).
# DM5 has no runnable surface (SPEC-GAP G-N2 in test-plan.md) and exits with a
# banner. A DM that does not match the current OS exits 0 with a SKIP banner so
# CI matrices can invoke every DM unconditionally.
#
# Bring-up is NOT done here — run the matching justfile target first:
#   dm1: just dm1     dm2: just dm2     dm3: just dm3     dm4: just dm3 && just dm2
# Teardown: dm1/dm3: just stop; dm2: just dm2-down; dm4: both.
#
# RULE: never use `attach -c`. Every per-session networking assertion runs INSIDE
# the sandbox via the full interactive session path (`minimal attach <sess>`).
# attach -c / the exec path runs on the daemon host in the guest ROOT netns and
# bypasses the sandbox, so it cannot prove a session's isolation or own-ip
# behaviour.
#
# DRIVER: heredoc-fed stdin, NOT expect. The attach client accepts a piped
# stdin: commands queue in the pty and execute once the in-sandbox shell is up
# (the slow first attach — sandbox build — just delays execution; nothing is
# lost). An earlier revision drove the pty with `expect` readiness-polling,
# which wedged intermittently; the pipe driver has no polling to wedge. Two
# shapes:
#   - ONE-SHOT (`session_out`): feed the script, then `exit`. The shell exits,
#     which by design tears the session's network down — fine for pure
#     assertions, since `destroy` follows immediately.
#   - HELD-OPEN (`session_hold`): feed the script, then hold stdin open
#     (`sleep`) so the shell — and its own-ip lease + switch attachment + any
#     backgrounded server — stays ALIVE while the host curls it. This replaces
#     the expect driver's detach(ctrl-w) semantics: same product behaviour (a
#     live client keeps the network up), no pty chords. The lease is read in
#     the SAME attach that starts the server, so it cannot go stale.
#
# RULE: nonce markers. A reattach replays prior screen content, so every call
# brackets its output with per-call __RB_<nonce>__/__RE_<nonce>__ markers — a
# replayed PRIOR marker can never be mistaken for this call's output.
#
# RULE: one pty per process. Every concurrently-live attach is its OWN OS
# process draining its OWN pty (a held-open background pipeline, or the
# foreground one-shot). Never multiplex two attaches through one driver.
#
# RULE: unprivileged ports only. The sandbox runs unprivileged (uid != 0,
# CapEff=0), so it CANNOT bind ports < 1024 — `socat TCP-LISTEN:80` fails with
# EACCES. Every in-session server binds :8080 (or another high port); ingress and
# proxy checks target that port accordingly.
#
# In-session tools: sh bash curl getent coreutils socat. NOT present: ip nc wget python.
# Switch-IP discovery therefore uses /proc/net/fib_trie, not `ip`.
set -u
M="$PWD/target/debug/minimal"
ATTACH_TIMEOUT=180     # first attach builds the sandbox; be generous
HOLD_SECS="${HOLD_SECS:-300}"   # how long a held-open attach keeps its shell alive
# The own-ip local switch address of a session, read from inside its sandbox
# (no `ip`): the /32 host route in the CGNAT block is this PTask's lease.
LEASE_CMD='grep -B1 "host LOCAL" /proc/net/fib_trie | grep -oE "100\.64\.0\.[0-9]+" | head -1'
# mTLS client-cert dir written by `minimal login` (dirs crate): macOS uses
# Application Support, Linux/XDG uses ~/.config.
case "$(uname -s)" in
  Darwin) CERT_DIR="$HOME/Library/Application Support/minimal" ;;
  *)      CERT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/minimal" ;;
esac
SCRATCH="${TMPDIR:-/tmp}/minimal-test-plan.$$"
mkdir -p "$SCRATCH"

banner() { printf '\n########## %s ##########\n' "$*"; }
skip()   { printf '\n########## SKIP %s ##########\n' "$*"; }

# ── DM selection ─────────────────────────────────────────────────────────────
OS="$(uname -s)"
if [ -z "${DM:-}" ]; then
  case "$OS" in
    Darwin) DM=dm1 ;;
    Linux)  if [ -S "${XDG_RUNTIME_DIR:-$HOME/.minimal/local}/minimal/minimald.sock" ]; then DM=dm3; else DM=dm2; fi ;;
    *) echo "unsupported host $OS"; exit 1 ;;
  esac
  echo "DM auto-detected: $DM"
fi
case "$DM" in
  dm1)
    [ "$OS" = Darwin ] || { skip "DM1 needs macOS (Hypervisor.framework); host is $OS"; exit 0; } ;;
  dm2|dm3|dm4)
    [ "$OS" = Linux ] || { skip "$DM needs Linux; host is $OS"; exit 0; } ;;
  dm5)
    skip "DM5 is a SPEC-GAP (G-N2): no --server flag, UDS-only control plane, proxies bind loopback only — see test-plan.md TC16"
    exit 0 ;;
  *) echo "unknown DM='$DM' (want dm1|dm2|dm3|dm4)"; exit 2 ;;
esac

# DM2's daemon runs under a dedicated state dir (`just dm2`); every CLI call
# against it needs --minimal-dir. On dm4 that is the SECONDARY control plane
# (TC15); the primary suite runs against the VM daemon's default state dir.
DM2_DIR="${DM2_DIR:-$PWD/.scratch/dm2-state}"
MARGS=""
[ "$DM" = dm2 ] && MARGS="--minimal-dir $DM2_DIR"
mcli() {
  # shellcheck disable=SC2086  # MARGS is intentionally word-split
  "$M" $MARGS "$@"
}

# Per-step wall-clock guard: cap every one-shot attach so a wedged daemon can't
# stall the whole plan. macOS ships `gtimeout` (coreutils), Linux `timeout`;
# degrade to none if absent. Sized to ATTACH_TIMEOUT: the first attach builds
# the sandbox before the piped commands run.
STEP_TIMEOUT="${STEP_TIMEOUT:-$ATTACH_TIMEOUT}"
if command -v gtimeout >/dev/null; then TO="gtimeout $STEP_TIMEOUT"
elif command -v timeout >/dev/null; then TO="timeout $STEP_TIMEOUT"
else TO=""; fi

destroy() { for s in "$@"; do mcli destroy "$s" >/dev/null 2>&1; done; }

# Best-effort cleanup on ANY exit: tear down every session the plan can create
# and kill any backgrounded job (held-open attaches, the TC8 ssh-forward), so an
# early exit never leaves running sessions, feeder sleeps, or a stray forward.
ALL_SESSIONS="bad1 bad2 bad3 demo dev peer tc1 tc1b tc4 tc6 tc7 web tc15a tc15b"
cleanup() {
  local pids
  pids="$(jobs -p)"
  [ -n "$pids" ] && kill $pids 2>/dev/null
  destroy $ALL_SESSIONS
  # DM4 runs a SECOND daemon (native, --minimal-dir $DM2_DIR) for TC15; the
  # destroy above only reaches the primary (mcli/MARGS) daemon, so also sweep
  # tc15b against the secondary daemon on abnormal exit.
  [ "$DM" = dm4 ] && "$M" --minimal-dir "$DM2_DIR" destroy tc15b >/dev/null 2>&1
  rm -rf "$SCRATCH"
}
trap cleanup EXIT INT TERM

# Count host-loopback LISTEN sockets on a TCP port (TC10/TC15); prints a number.
listeners_on() {
  local port="$1"
  if command -v ss >/dev/null; then ss -ltnH "sport = :$port" 2>/dev/null | wc -l | tr -d ' '
  else lsof -nP -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | tail -n +2 | wc -l | tr -d ' '
  fi
}

# Strip ANSI escapes + CRs from a pty transcript.
clean() { sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\r//g'; }

# Print the body between this call's nonce markers, with a trailing EXIT=<rc>.
# Markers must be EXACT lines: on the slow first attach the shell echoes the
# queued input before `stty -echo` has executed, so `echo __RB_<n>__` command
# text appears in the transcript — exact-line matching keeps it out.
extract() {
  awk -v n="$1" '$0 == ("__RB_"n"__"){f=1;next} f && $0 ~ ("^__RE_"n"__:"){print "EXIT="substr($0,index($0,":")+1);f=0} f'
}

# session_out <sess> <bash-script> : ONE-SHOT. Pipes the script into an attach,
# verbatim (no local expansion — remote $() and $VAR run in the sandbox), then
# `exit`s the shell. Emits the marker-bracketed body + EXIT=<rc>. The session's
# network is torn down by the exit — callers destroy the session right after.
session_out() {
  local sess="$1" script="$2" nonce="${RANDOM}${RANDOM}${RANDOM}"
  {
    # Quiet the pty FIRST: with echo on, the shell replays each fed command
    # line, and a replayed `echo __RB_...__` would false-trigger extract's
    # markers. After this line only command OUTPUT reaches the transcript.
    printf "stty -echo; PS1=''\n"
    printf 'echo __RB_%s__\n' "$nonce"
    printf '%s\n' "$script"
    printf 'echo __RE_%s__:$?\nexit\n' "$nonce"
  } | $TO "$M" $MARGS attach "$sess" 2>&1 | clean | extract "$nonce"
}

# session_hold <sess> <bash-script> <logfile> : HELD-OPEN. Pipes the script in,
# then holds stdin open (sleep) so the shell + its network + any backgrounded
# server stay alive while the host probes. Output streams to <logfile>; poll it
# with hold_wait. Ended by `destroy <sess>` (the client exits when the session
# dies) or by cleanup's job kill.
session_hold() {
  local sess="$1" script="$2" log="$3" nonce="$4"
  {
    # Quiet the pty first (see session_out) — otherwise hold_wait's grep can
    # fire on the REPLAYED command text (e.g. `echo SERVER_UP`) before the
    # server has actually started.
    printf "stty -echo; PS1=''\n"
    printf 'echo __RB_%s__\n' "$nonce"
    printf '%s\n' "$script"
    printf 'echo __RD_%s__\n' "$nonce"
    sleep "$HOLD_SECS"
  } | "$M" $MARGS attach "$sess" > "$log" 2>&1 &
}

# hold_wait <logfile> <line-prefix> : poll a held-open attach's log until a
# LINE STARTING WITH <line-prefix> appears (bounded by ATTACH_TIMEOUT — the
# first attach builds the sandbox). Anchored to line start so echoed command
# text (`echo SERVER_UP`, replayed before `stty -echo` executes on a slow
# first attach) cannot satisfy the wait before the server is actually up.
hold_wait() {
  local log="$1" pat="$2" i
  for i in $(seq 1 $((ATTACH_TIMEOUT / 2))); do
    clean < "$log" 2>/dev/null | grep -aq "^$pat" && return 0
    sleep 2
  done
  echo "hold_wait: line starting '$pat' never appeared in $log" >&2
  return 1
}

banner "BRING-UP ($DM)"
mcli ls

banner "TC10 — topology preflight ($DM)"
tc10_fail=0
case "$DM" in
  dm1)
    pgrep -x minvmd >/dev/null && echo "minvmd: RUNNING" || { echo "minvmd: MISSING"; tc10_fail=1; }
    pgrep -f gvproxy >/dev/null && echo "gvproxy: RUNNING" || echo "gvproxy: not running (informational — spawns with the first own-ip PTask)"
    echo "proxy listeners: :7654=$(listeners_on 7654) :7655=$(listeners_on 7655) (informational)"
    ;;
  dm2)
    [ -S "$DM2_DIR/providers/local-0/ssh.sock" ] && echo "dm2 UDS: PRESENT" || { echo "dm2 UDS: MISSING ($DM2_DIR — run 'just dm2')"; tc10_fail=1; }
    pgrep -x minvmd >/dev/null && { echo "minvmd: RUNNING (unexpected for pure DM2 — is this DM4?)"; } || echo "minvmd: absent (correct)"
    ;;
  dm3)
    [ -e /dev/kvm ] && [ -w /dev/kvm ] && echo "/dev/kvm: OK" || { echo "/dev/kvm: MISSING or not writable"; tc10_fail=1; }
    pgrep -x minvmd >/dev/null && echo "minvmd: RUNNING" || { echo "minvmd: MISSING (run 'just dm3')"; tc10_fail=1; }
    ;;
  dm4)
    [ -e /dev/kvm ] && [ -w /dev/kvm ] && echo "/dev/kvm: OK" || { echo "/dev/kvm: MISSING"; tc10_fail=1; }
    pgrep -x minvmd >/dev/null && echo "minvmd (VM half): RUNNING" || { echo "minvmd: MISSING (run 'just dm3')"; tc10_fail=1; }
    [ -S "$DM2_DIR/providers/local-0/ssh.sock" ] && echo "dm2 UDS (native half): PRESENT" || { echo "dm2 UDS: MISSING (run 'just dm2')"; tc10_fail=1; }
    # G-N1 observed, not hidden: exactly ONE daemon owns each hardcoded proxy port.
    echo "G-N1 proxy-port contention: :7654=$(listeners_on 7654) listener(s), :7655=$(listeners_on 7655) listener(s) (expect 1 each; the second daemon's bind warns and loses)"
    ;;
esac
[ "$tc10_fail" = 0 ] && echo "TC10=PASS" || { echo "TC10=FAIL — topology wrong for $DM; aborting (verdicts below would test the wrong DM)"; exit 1; }

banner "TC1 — UC1 NoNet isolation (faithful, in-sandbox)"
destroy tc1
mcli activate -n tc1 --network no-net . >/dev/null 2>&1
echo "-- in-sandbox: no interfaces, curl FAILS, getent FAILS --"
session_out tc1 'echo IFACES=$(ls /sys/class/net/ 2>/dev/null | tr "\n" ","); curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com 2>&1 || echo CURL_FAILED; getent hosts github.com >/dev/null 2>&1 && echo DNS_OK || echo DNS_FAILED'
destroy tc1

banner "TC1b — host-net egress (positive control, in-sandbox)"
destroy tc1b
mcli activate -n tc1b --network host-net . >/dev/null 2>&1
echo "-- in-sandbox: curl 200 + DNS resolves --"
session_out tc1b 'curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com; getent hosts github.com | head -1'
destroy tc1b

banner "TC2 — UC6 OwnIp egress + same-host peer (two full sessions)"
destroy demo peer
mcli activate -n demo --network own-ip . >/dev/null 2>&1
mcli activate -n peer --network own-ip . >/dev/null 2>&1
echo "-- demo egress (in-sandbox, via the switch): expect 200 --"
session_out demo 'curl --max-time 8 -sS -o /dev/null -w "HTTP=%{http_code}\n" http://example.com'
# Same-host peer: HELD-OPEN attach starts the listener on an UNPRIVILEGED port
# and reads peer's own switch lease in the SAME attach, then holds the shell —
# and therefore the lease + listener — alive while demo dials it. One discovery
# is authoritative; nothing can go stale while the hold lasts.
nonce_p="${RANDOM}${RANDOM}${RANDOM}"
session_hold peer 'socat TCP-LISTEN:8080,reuseaddr,fork "SYSTEM:printf PEER_REACHED" & sleep 1; echo PEERIP=$('"$LEASE_CMD"')' "$SCRATCH/peer.log" "$nonce_p"
hold_wait "$SCRATCH/peer.log" "PEERIP=100"
peer_ip="$(clean < "$SCRATCH/peer.log" | grep -aoE 'PEERIP=100\.64\.0\.[0-9]+' | head -1 | cut -d= -f2)"
echo "peer switch IP: ${peer_ip:-UNKNOWN}"
if [ -n "$peer_ip" ]; then
  # demo dials peer over the switch. socat's `printf PEER_REACHED` is a raw
  # (HTTP/0.9) reply, so assert on the BODY (curl exit status is unreliable for
  # 0.9). Retry briefly to absorb listener-bind latency; track success in an
  # explicit flag (a trailing $? would be the loop's `sleep`, always 0).
  session_out demo 'reached=NO; for i in $(seq 1 8); do if curl --max-time 3 -sS --http0.9 http://'"$peer_ip"':8080/ 2>/dev/null | grep -q PEER_REACHED; then reached=YES; break; fi; sleep 1; done; echo TC2_PEER=$reached'
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
mcli activate -n web --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
# HTTP/1.0 server INSIDE the session on :8080, held alive while the host curls.
# The response is written to a file by the sandbox shell (which interprets the
# \r\n) and served verbatim with `cat`. Building it INSIDE socat's `SYSTEM:`
# address instead mangles the printf quoting and emits a non-HTTP reply
# (curl: "Received HTTP/0.9 when not allowed" -> http_code 000) — a backend bug
# that previously masqueraded as a forwarding failure.
session_hold web "printf 'HTTP/1.0 200 OK\r\n\r\nWEB_OK' > /tmp/rsp; socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'cat /tmp/rsp' & sleep 1; echo SERVER_UP" "$SCRATCH/web.log" "${RANDOM}${RANDOM}"
hold_wait "$SCRATCH/web.log" "SERVER_UP"
echo "-- host via :7654 proxy -> web.local.min.internal:18080 (published port) --"
curl --max-time 8 -sS -x http://127.0.0.1:7654 -o /dev/null -w "TC3_HTTP=%{http_code}\n" http://web.local.min.internal:18080/ 2>&1 || echo "TC3_HTTP=curl-failed"
destroy web

banner "TC4 — UC4 static ingress 18080:8080 (server in-sandbox, host curls)"
destroy tc4
mcli activate -n tc4 --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
mcli session policy tc4
session_hold tc4 "printf 'HTTP/1.0 200 OK\r\n\r\nINGRESS_OK' > /tmp/rsp; socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'cat /tmp/rsp' & sleep 1; echo SERVER_UP" "$SCRATCH/tc4.log" "${RANDOM}${RANDOM}"
hold_wait "$SCRATCH/tc4.log" "SERVER_UP"
echo "-- host -> 127.0.0.1:18080 (ingress forward -> lease:8080) --"
curl --max-time 8 -sS -o /dev/null -w "TC4_HTTP=%{http_code}\n" http://127.0.0.1:18080/ 2>&1 || echo "TC4_HTTP=curl-failed"
destroy tc4

banner "TC5 — policy validation (CLI-only; expect REJECTIONS, no session)"
destroy bad1 bad2 bad3
mcli activate -n bad1 --network host-net --ingress 18080:8080 .    # ingress requires own-ip
mcli activate -n bad2 --network own-ip  --ingress 80:8080 .        # privileged host port
mcli activate -n bad3 --network own-ip  --ingress 18080:8080/icmp . # bad proto
echo "-- none should exist --"; mcli ls
destroy bad1 bad2 bad3

banner "TC6 — live policy round-trip (CLI-only; no attach needed)"
destroy tc6
mcli activate -n tc6 --network own-ip --ingress 18080:8080/tcp . >/dev/null 2>&1
mcli session policy tc6
destroy tc6

banner "TC7 — UC2b mTLS reverse proxy :7655 (backend in-sandbox, host curls)"
mcli login
ls -l "$CERT_DIR/" 2>&1 | tail -4
destroy tc7
# The :7655 proxy routes by the Host: header authority (hostname + PUBLISHED
# port — same router as :7654; TLS SNI stays localhost), so publish the backend.
mcli activate -n tc7 --network own-ip --ingress 18081:8080 . >/dev/null 2>&1
session_hold tc7 "printf 'HTTP/1.0 200 OK\r\n\r\nBACKEND_OK' > /tmp/rsp; socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'cat /tmp/rsp' & sleep 1; echo SERVER_UP" "$SCRATCH/tc7.log" "${RANDOM}${RANDOM}"
hold_wait "$SCRATCH/tc7.log" "SERVER_UP"
echo "-- host (with cert) -> :7655, Host: tc7.local.min.internal:18081 : expect 200 --"
curl --max-time 8 -sS -o /dev/null -w "TC7_WITHCERT=%{http_code}\n" --cacert "$CERT_DIR/ca.pem" --cert "$CERT_DIR/client.pem" --key "$CERT_DIR/client.key" -H "Host: tc7.local.min.internal:18081" https://localhost:7655/ 2>&1 || echo "TC7_WITHCERT=curl-failed"
echo "-- host (no cert) -> :7655 : expect 401 --"
curl --max-time 8 -sS -k -o /dev/null -w "TC7_NOCERT=%{http_code}\n" https://localhost:7655/ 2>&1 || echo "TC7_NOCERT=curl-failed"
destroy tc7

banner "TC8 — ssh-forward (server in-sandbox, host curls through the forward)"
destroy dev
mcli activate -n dev --network own-ip --ingress 18080:8080 . >/dev/null 2>&1
session_hold dev "printf 'HTTP/1.0 200 OK\r\n\r\nFORWARD_OK' > /tmp/rsp; socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'cat /tmp/rsp' & sleep 1; echo SERVER_UP" "$SCRATCH/dev.log" "${RANDOM}${RANDOM}"
hold_wait "$SCRATCH/dev.log" "SERVER_UP"
# The local port must NOT be the ingress external port (18080): gvproxy already
# binds host 18080 for `dev`'s ingress, so `ssh -L 18080` fails to bind and the
# curl would silently hit the ingress forwarder instead of the ssh path. Use a
# distinct local port so TC8 actually exercises `direct-tcpip`.
mcli ssh-forward dev 19090:127.0.0.1:8080 >"$SCRATCH/fwd.log" 2>&1 &
fwd_pid=$!
sleep 3
echo "-- host -> localhost:19090 (through the ssh-forward) --"
curl --max-time 8 -sS -o /dev/null -w "TC8_HTTP=%{http_code}\n" http://localhost:19090/ 2>&1 || echo "TC8_HTTP=curl-failed"
kill "$fwd_pid" 2>/dev/null; wait "$fwd_pid" 2>/dev/null
destroy dev

banner "TC9 — UC7 WireGuard mesh (CLI surface; data-path is TC17, blocked)"
mcli mesh status
mcli mesh join 127.0.0.1:51820
mcli mesh leave

# ── Blocked / gap TCs: banners only, with the citation (see test-plan.md) ────
skip "TC12 UC5 vm_egress — BLOCKED(G-N3): VmConfig.vm_egress has types + R2.5 validation (crates/minvmd/src/vm.rs:119-150) but no runtime config surface; enforcement pending #553"
skip "TC13 UC3 per-PTask egress — BLOCKED(G-N4): CLI hardcodes egress: None (crates/minimal/src/main.rs:459); no --egress/spec surface"
skip "TC14 R2.4 dynamic port-map — BLOCKED(G-N5): RPC type exists (crates/minimald-rpc/src/lib.rs:401), no daemon handler"
skip "TC16 DM5 remote authenticated access — SPEC-GAP(G-N2): no --server, UDS-only control plane, proxies loopback-only"
skip "TC17 UC7 mesh data path — BLOCKED(G-N6): daemon never consumes mesh enrolment; set_mesh is test-only (crates/minimald/src/rpc.rs:1001)"

if [ "$DM" = dm4 ]; then
  banner "TC15 — DM4 co-residency (both control planes; G-N1 observed)"
  # Primary (VM daemon, default state dir) already ran TC1-TC9 above. Here:
  # both control planes answer, and each serves an isolated session.
  echo "-- VM daemon (default state dir) --";     "$M" ls
  echo "-- native daemon ($DM2_DIR) --";          "$M" --minimal-dir "$DM2_DIR" ls
  "$M" --minimal-dir "$DM2_DIR" destroy tc15b >/dev/null 2>&1
  "$M" destroy tc15a >/dev/null 2>&1
  "$M" activate -n tc15a --network no-net . >/dev/null 2>&1 && echo "tc15a (VM daemon): activated"
  "$M" --minimal-dir "$DM2_DIR" activate -n tc15b --network no-net . >/dev/null 2>&1 && echo "tc15b (native daemon): activated"
  "$M" ls; "$M" --minimal-dir "$DM2_DIR" ls
  "$M" destroy tc15a >/dev/null 2>&1; "$M" --minimal-dir "$DM2_DIR" destroy tc15b >/dev/null 2>&1
  echo "-- G-N1: proxy-bind warning in the losing daemon's log --"
  grep -h "proxy" "$PWD/.scratch/dm2-minimald.log" 2>/dev/null | grep -i "bind\|unavailable" | tail -3 || echo "(no bind warning found in .scratch/dm2-minimald.log — check which daemon started second)"
  echo "TC15: :7654=$(listeners_on 7654) listener(s) — the first daemon's proxy owns the port (G-N1)"
fi

banner "DONE ($DM)"
