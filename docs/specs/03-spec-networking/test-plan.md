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
- **In-session tools:** `sh bash curl getent coreutils socat`. **Absent:**
  `ip` (iproute2), `nc`, `wget`, `python`. So:
  - listeners / tiny servers → `socat`;
  - own-ip switch-IP discovery (no `ip`) → `grep -oE '100\.64\.[0-9]+\.[0-9]+' /proc/net/fib_trie`;
  - interface check (no `ip`) → `ls /sys/class/net/`.
- **Host → PTask tests (TC3/4/7/8):** the server runs **inside** the session and
  is kept alive (backgrounded `socat`, session left attached) while the host-side
  `curl`/`ssh-forward` runs, then the session is torn down.

## Current status (last run on this branch)

| TC | Verdict | Evidence |
|----|---------|----------|
| TC1 no-net isolation | **PASS** | in-sandbox curl fails (no route/DNS); zero reachability |
| TC1b host-net egress | **PASS** | in-sandbox curl→200; DNS resolves |
| TC2 own-ip egress + peer | **BLOCKED** | own-ip attach fails (see below) |
| TC3 managed DNS :7654 | **BLOCKED** | proxy reachable on host loopback (Slice 2), but own-ip backend can't launch |
| TC4 static ingress | **BLOCKED** (data path) | `session policy` shows the mapping (PASS); own-ip backend can't launch |
| TC5 policy validation | **PASS** | all 3 rejected with correct messages |
| TC6 policy round-trip | **PASS** | `session policy` returns the ingress JSON |
| TC7 mTLS :7655 | **PARTIAL** | no-cert→**401** PASS (proxy live + exposed); with-cert→200 needs an own-ip backend |
| TC8 ssh-forward | **BLOCKED** | own-ip backend can't launch |
| TC9 mesh CLI | **PASS** | status/join/leave OK |

**The one remaining blocker — own-ip PTask attach:** `attach_own_ip` succeeds the
gvproxy switch lease, then rolls back with a bare `session spawn: ENOENT`.
`move_tap_into_netns` (`crates/minimald/src/net/switch.rs`) shells out to
`ip`/`nsenter` to move + configure the tap in the PTask netns, and **neither is in
the guest rootfs** (base + socat only). This is the same class as the root-egress
fix (which uses ioctls instead of `ip`); the per-PTask tap path still shells out.
Fix options: configure the per-PTask tap via netlink/setns (no `ip`/`nsenter`), or
add iproute2/util-linux to the guest rootfs. Until then every own-ip TC blocks.

The proxy infrastructure (Slice 2) is verified: `:7655` mTLS returns 401 and
`:7654` is reachable on host loopback — the own-ip backend is the only gap for the
full 200/routing paths.

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
Two own-ip sessions; both via the full session path.
```bash
$M activate -n demo --network own-ip .
$M activate -n peer --network own-ip .
# demo shell: curl http://example.com -> 200 (egress via the shuttle)
# peer shell: PIP=$(grep -oE '100\.64\.[0-9]+\.[0-9]+' /proc/net/fib_trie | grep -v '\.0$' | head -1)
#             socat TCP-LISTEN:9000,reuseaddr,fork SYSTEM:'printf PEER_REACHED' &   (keep attached)
# demo shell: curl http://$PIP:9000/  -> PEER_REACHED
$M destroy demo peer
```
Status today: **BLOCKED (own-ip backend: guest rootfs lacks `ip`/`nsenter`)**.

## TC3 — UC2 managed DNS via host proxy :7654
Server in-sandbox; host resolves by hostname through the proxy.
```bash
$M activate -n web --network own-ip .
# web shell: socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nWEB_OK"' &  (keep attached)
# host:      curl -x http://127.0.0.1:7654 http://web.local.min.internal/   -> 200 WEB_OK
$M destroy web
```
Status today: **BLOCKED** (own-ip backend: guest rootfs lacks `ip`/`nsenter` for the in-session server; host loopback :7654 not wired).

## TC4 — UC4 static ingress 18080:80
```bash
$M activate -n tc4 --network own-ip --ingress 18080:80 .
$M session policy tc4          # shows the mapping (CLI-only, works today)
# tc4 shell: socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nINGRESS_OK"' &  (keep attached)
# host:      curl http://127.0.0.1:18080/   -> 200 INGRESS_OK
$M destroy tc4
```
Status today: policy round-trip **PASS**; data path **BLOCKED** (own-ip backend: guest rootfs lacks `ip`/`nsenter` + ingress applies on the sandboxed attach + host loopback not wired).

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
# tc7 shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nBACKEND_OK"' &  (keep attached)
# host (cert):   curl --cacert .../ca.pem --cert .../client.pem --key .../client.key https://localhost:7655/  -> 200
# host (no cert):curl -k https://localhost:7655/   -> 401
$M destroy tc7
```
Status today: `login` **PASS** (correct macOS cert path); proxy legs **BLOCKED** (own-ip backend: guest rootfs lacks `ip`/`nsenter` + :7655 not started/exposed in-VM).

## TC8 — ssh-forward
```bash
$M activate -n dev --network own-ip --ingress 18080:80 .
# dev shell: socat TCP-LISTEN:80,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nFORWARD_OK"' &  (keep attached)
# host: minimal ssh-forward dev 18080:127.0.0.1:80 &
#       curl http://localhost:18080/   -> 200 FORWARD_OK
$M destroy dev
```
Status today: **BLOCKED** (own-ip backend: guest rootfs lacks `ip`/`nsenter` for the in-session server).

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
