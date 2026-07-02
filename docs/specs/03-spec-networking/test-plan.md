# minimald Networking Epic (#478) — CLI Test Plan (full-session-path)

Every per-session networking assertion runs **inside the sandbox** via the full
interactive session path. **`attach -c` is never used** — that exec path runs on
the daemon host in the guest **root** netns and bypasses the sandbox, so it can
never prove a session's isolation or own-ip behaviour.

Run from the repo root with the daemon up. `M=target/debug/minimal`.

**Portability:** targets the minvmd VM deployment (DM1) — macOS/HVF and Linux/KVM
are identical (the sandbox guest is Linux on every host; the CLI, `expect`, and
host curls are the same). The only host-specific bit is the mTLS cert dir
(`~/Library/Application Support/minimal` on macOS, `~/.config/minimal` on
Linux/XDG) — the script picks it per-OS. On native Linux (DM2, no VM) the same
test commands apply, but bring-up is minimald-native (no `just up`) and the
proxies bind host loopback directly (no gvproxy host-expose).

## Environment & driver

- **The full session path:** `minimal attach <sess>` (no `-c`) opens an
  interactive PTY shell — `shell_request` → `SandboxLauncher` → a hakoniwa
  sandbox running `bash --noprofile -l` with the session's `NetworkMode`.
  Commands typed there run in the sandbox netns. This is the only faithful path.
- **Driving it:** a real PTY is required, so the executable plan uses `expect`
  (`/usr/bin/expect`) — one reusable `run_in_session <sess> <script>` helper that
  spawns the attach, polls a readiness marker (to absorb the slow first attach
  while the sandbox builds), runs the script, captures output, and exits.
- **Detach, don't exit.** The driver DETACHES (ctrl-w) when a step is done, never
  `exit`. A session is tmux-like: detach keeps the shell — and its own-ip lease +
  switch attachment — alive; `exit` ends the shell, which by design tears the
  network down. Detach keeps the lease STABLE across the multiple attaches a test
  makes (so peer/backend IPs discovered once stay valid) and keeps backgrounded
  servers serving. Only `destroy` ends a session.
- **Unprivileged ports only.** The sandbox is unprivileged (`CapEff=0`) and cannot
  bind ports <1024 (`socat TCP-LISTEN:80` → EACCES). Servers bind `:8080`; ingress
  and proxy checks target that port.
- **In-session tools:** `sh bash curl getent coreutils socat`. **Absent:**
  `ip` (iproute2), `nc`, `wget`, `python`. So:
  - listeners / tiny servers → `socat` on an unprivileged port (`:8080`);
  - own-ip switch-IP discovery (no `ip`) → the /32 host route in the CGNAT block:
    `grep -B1 'host LOCAL' /proc/net/fib_trie | grep -oE '100\.64\.0\.[0-9]+' | head -1`;
  - interface check (no `ip`) → `ls /sys/class/net/`.
- **Host → PTask tests (TC3/4/7/8):** the server runs **inside** the session
  (backgrounded `socat`) and the session is DETACHED (which keeps it + the server
  alive) while the host-side `curl`/`ssh-forward` runs, then the session is
  `destroy`ed.

## Current status (last run on this branch — DM2 native)

| TC | Verdict | Evidence |
|----|---------|----------|
| TC1 no-net isolation | **PASS** | in-sandbox curl→000, DNS fails; only `lo` |
| TC1b host-net egress | **PASS** | in-sandbox curl→200; DNS resolves |
| TC2 own-ip egress + peer | **PASS** | egress→200; demo→peer `:8080`→`PEER_REACHED` (`TC2_PEER=YES`) |
| TC3 managed DNS :7654 | **routing landed; e2e pending** | #542: OwnIp registers `web`→`127.0.0.1`; proxy resolves `web.local.min.internal:18080`→`127.0.0.1:18080`→gvproxy→lease (verified reaching the lease). Full 200 pending a stable in-session backend (env attach flake). |
| TC4 static ingress | **path verified; e2e pending** | `session policy` round-trips (PASS); gvproxy binds `127.0.0.1:18080`→`lease:8080` (`ss` + `/forwarder/all`), host→gvproxy→lease reaches the lease (RST w/o backend). Full 200 pending a stable backend. |
| TC5 policy validation | **PASS** | all 3 rejected with correct messages |
| TC6 policy round-trip | **PASS** | `session policy` returns the ingress JSON |
| TC7 mTLS :7655 | **PARTIAL** | no-cert→**401** PASS (proxy live); with-cert green pending the same published-port routing + a stable backend |
| TC8 ssh-forward | **e2e pending** | ssh-forward path is independent of the proxy; pending a stable in-session backend |
| TC9 mesh CLI | **PASS** | status/join/leave OK |

Own-ip PTask attach and **same-host peer routing work** (gvproxy L2-switches
between two leases on one host — TC2). Two earlier symptoms were harness
artifacts, now fixed in `test-plan.sh`: (1) the "own-ip attach hangs" was the
inline `expect` readiness block, and (2) the "peer unreachable" / per-attach lease
churn was the harness sending `exit` between steps. A session is tmux-like: it is
now DETACHED (ctrl-w) between assertions, so its shell + own-ip lease stay stable;
`exit` correctly tears the network down. Servers bind unprivileged ports (`:8080`)
because the sandbox has no `CAP_NET_BIND_SERVICE`.

**Host→guest reachability — resolved by the published-loopback model.** Per the
DM2 topology in `networking-with-diagrams.md` (the decided model), the daemon is
**not** on the switch; host→PTask goes through a gvproxy-**published loopback
port** (`127.0.0.1:<external>` → `lease:<internal>`, the same forwarder `apply_ingress`
uses — verified to reach the lease). #542 is landed: an OwnIp PTask registers its
hostname → `127.0.0.1`, and the `:7654`/`:7655` proxies route by `Host:` header to
that published port (spec R3.1/R3.3/R4.4 updated to this model; `own_ip` proxy test
updated). UC2a therefore requires the accessed port to be published (ingress),
which is why TC3 now activates `web` with `--ingress 18080:8080` and curls
`web.local.min.internal:18080`. The only thing between here and green TC3/4/7/8 is
a reliable in-session backend — currently blocked by an intermittent
attach-readiness wedge in this environment (orthogonal to networking).

---

## TC1 — UC1 NoNet isolation
A `no-net` session must have **no egress** (no route, no DNS). Faithful: assert
inside the sandbox.
```bash
$M activate -n tc1 --network no-net .
# in the interactive shell (no -c):
#   ls /sys/class/net/        -> only `lo`
#   curl --max-time 8 http://example.com   -> FAILS (no route / cannot resolve)
#   getent hosts github.com   -> fails
$M destroy tc1
```
Expect: isolated. Status today: **PASS** (only `lo`; in-sandbox curl fails, no route or DNS).

## TC1b — host-net egress (positive control)
```bash
$M activate -n tc1b --network host-net .
# in the interactive shell: curl http://example.com -> 200 ; getent hosts github.com -> resolves
$M destroy tc1b
```
Status today: **PASS** (in-sandbox curl returns 200; DNS resolves).

## TC2 — UC6 OwnIp egress + same-host peer
Two own-ip sessions; both via the full session path. The listener runs on an
**unprivileged** port (the sandbox can't bind <1024), and peer's lease is read in
the SAME attach that starts the listener, then that session is DETACHED (not
exited) so the lease stays stable and the listener keeps serving.
```bash
$M activate -n demo --network own-ip .
$M activate -n peer --network own-ip .
# demo shell: curl http://example.com -> 200 (egress via the switch)
# peer shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf PEER_REACHED' &   then read
#             PIP=$(grep -B1 'host LOCAL' /proc/net/fib_trie | grep -oE '100\.64\.0\.[0-9]+' | head -1)   and DETACH
# demo shell: curl --http0.9 http://$PIP:8080/  -> PEER_REACHED
$M destroy demo peer
```
Status today: **PASS** (`TC2_PEER=YES`; gvproxy L2-switches between the two leases).

## TC3 — UC2a managed DNS via host proxy :7654
Published-loopback model: the PTask's port is published on host loopback via
ingress, its hostname registers → `127.0.0.1` (R3.1/#542), and the `:7654` proxy
routes `Host:` → `127.0.0.1:<published>`. The client uses the published external
port in the authority.
```bash
$M activate -n web --network own-ip --ingress 18080:8080 .
# web shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nWEB_OK"' &  then DETACH
# host:      curl -x http://127.0.0.1:7654 http://web.local.min.internal:18080/   -> want 200 WEB_OK
$M destroy web
```
Status today: routing landed (registers → `127.0.0.1`; proxy resolves to the
published port; gvproxy forward verified reaching the lease). Full 200 pending a
stable in-session backend (see the note above).

## TC4 — UC4 static ingress 18080:8080
```bash
$M activate -n tc4 --network own-ip --ingress 18080:8080 .
$M session policy tc4          # shows the mapping (CLI-only, works today)
# tc4 shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nINGRESS_OK"' &  then DETACH
# host:      curl http://127.0.0.1:18080/   -> want 200 INGRESS_OK
$M destroy tc4
```
Status today: policy round-trip **PASS**; data path **BLOCKED** (host→`:18080`→lease `:8080` fails — same host→guest routing gap).

## TC5 — policy validation (CLI-only; expect rejections)
No session is launched, so no attach is involved.
```bash
$M activate -n bad1 --network host-net --ingress 18080:80 .     # -> "ingress ... only valid for an own-IP PTask"
$M activate -n bad2 --network own-ip  --ingress 80:80 .         # -> privileged host port refused
$M activate -n bad3 --network own-ip  --ingress 18080:80/icmp . # -> "unsupported protocol 'icmp'"
$M ls                                                           # none created
```
Status today: **PASS**.

## TC6 — live policy round-trip (CLI-only)
```bash
$M activate -n tc6 --network own-ip --ingress 18080:80/tcp .
$M session policy tc6     # JSON reflects the launch policy
$M destroy tc6
```
Status today: **PASS**.

## TC7 — UC2b mTLS reverse proxy :7655
Backend in-sandbox; host hits the proxy with/without a client cert.
```bash
$M login                                  # writes ~/Library/Application Support/minimal/{ca,client}.pem, client.key
$M activate -n tc7 --network own-ip .
# tc7 shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nBACKEND_OK"' &  then DETACH
# host (cert):   curl --cacert .../ca.pem --cert .../client.pem --key .../client.key https://localhost:7655/  -> want 200
# host (no cert):curl -k https://localhost:7655/   -> 401
$M destroy tc7
```
Status today: `login` **PASS**; no-cert→**401 PASS** (proxy live); with-cert→**502** (proxy healthy but can't reach the backend lease — same host→guest routing gap).

## TC8 — ssh-forward
```bash
$M activate -n dev --network own-ip --ingress 18080:8080 .
# dev shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nFORWARD_OK"' &  then DETACH
# host: minimal ssh-forward dev 18080:127.0.0.1:8080 &
#       curl http://localhost:18080/   -> want 200 FORWARD_OK
$M destroy dev
```
Status today: **BLOCKED (data path)** — host→forward→`:8080` fails (000); same host→guest routing gap.

## TC9 — UC7 WireGuard mesh (CLI surface)
Data path is Linux-netns-only; here only the CLI surface.
```bash
$M mesh status     # prints key / advertised subnets / peers (or "no mesh configured")
$M mesh join 127.0.0.1:51820   # records enrolment, prints manual key-exchange steps
$M mesh leave
```
Status today: **PASS** (CLI surface).

---

Executable companion: `test-plan.sh` (same dir) — bash + a single `expect`
driver, idempotent cleanup, PASS/FAIL/BLOCKED banners, zero `attach -c`.
