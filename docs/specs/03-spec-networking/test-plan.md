# minimald Networking Epic (#478) — CLI Test Plan, all deployment models (DM1–DM5)

Every per-session networking assertion runs **inside the sandbox** via the full
interactive session path. **`attach -c` is never used** — that exec path runs on
the daemon host in the guest **root** netns and bypasses the sandbox, so it can
never prove a session's isolation or own-ip behaviour.

Run from the repo root with the target deployment model brought up (see the
per-DM sections). `M=target/debug/minimal`. Executable companion:
`test-plan.sh` (same dir) — `DM=dm1|dm2|dm3|dm4 ./test-plan.sh`, auto-detected
when unset.

## Status markers

| Marker | Meaning |
|---|---|
| **RUNNABLE** | Executable today on that DM with `test-plan.sh` |
| **BLOCKED(impl-gap)** | Test is fully specified; a cited implementation gap prevents execution |
| **SPEC-GAP** | The spec surface itself is unimplemented; the test activates when it lands |
| **N/A** | Not applicable to that DM by design |

## DM × TC coverage matrix

DM5 is an *overlay* ("any of the above, network-exposed"), so per-session TCs are
N/A in its column; only TC16 tests the DM5 delta.

| TC | DM1 | DM2 | DM3 | DM4 | DM5 |
|----|-----|-----|-----|-----|-----|
| TC1 no-net isolation (UC1) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC1b host-net egress (UC1) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC2 own-ip egress + peer (UC1/UC6) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC3 managed DNS :7654 (UC2a) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE† | N/A |
| TC4 static ingress (UC4) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC5 policy validation | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC6 policy round-trip (R2.6) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC7 mTLS proxy :7655 (UC2b-B) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE† | N/A |
| TC8 ssh-forward (R4.9) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC9 mesh CLI surface (R4.6/R4.8) | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC10 topology preflight | RUNNABLE | RUNNABLE | RUNNABLE | RUNNABLE | N/A |
| TC11 DM3 parity run | N/A | N/A | RUNNABLE | N/A | N/A |
| TC12 UC5 `vm_egress` (R2.5) | BLOCKED(G-N3) | BLOCKED(G-N3)‡ | BLOCKED(G-N3) | BLOCKED(G-N3) | N/A |
| TC13 UC3 per-PTask egress (R2.1/R2.2) | BLOCKED(G-N4) | BLOCKED(G-N4) | BLOCKED(G-N4) | BLOCKED(G-N4) | N/A |
| TC14 R2.4 dynamic port-map | BLOCKED(G-N5) | BLOCKED(G-N5) | BLOCKED(G-N5) | BLOCKED(G-N5) | N/A |
| TC15 DM4 co-residency | N/A | N/A | N/A | RUNNABLE (partial, G-N1) | N/A |
| TC16 DM5 remote authenticated access (UC2c) | N/A | N/A | N/A | N/A | SPEC-GAP(G-N2) |
| TC17 UC7 mesh data path (R4.1–R4.3) | BLOCKED(G-N6) | BLOCKED(G-N6) | BLOCKED(G-N6) | BLOCKED(G-N6) | BLOCKED(G-N6) |

† On DM4 the `:7654`/`:7655` proxies belong to whichever daemon bound them first
(G-N1); TC3/TC7 run against that daemon only.
‡ On DM2 the R2.5 *rejection* half is what applies; it is unit-tested
(`VmConfig::validate_for`) but has no runtime trigger yet (G-N3).

## Environment & driver (all DMs)

- **The full session path:** `minimal attach <sess>` (no `-c`) opens an
  interactive PTY shell — `shell_request` → `SandboxLauncher` → a hakoniwa
  sandbox running `bash --noprofile -l` with the session's `NetworkMode`.
  Commands typed there run in the sandbox netns. This is the only faithful path.
- **Driving it: heredoc-fed stdin, not `expect`.** The attach client accepts a
  piped stdin; commands queue in the pty and execute once the in-sandbox shell
  is up (the slow first attach — sandbox build — just delays execution). An
  earlier revision drove the pty with `expect` readiness-polling, which wedged
  intermittently; the pipe driver has no polling to wedge. Every fed script
  starts with `stty -echo; PS1=''` (so replayed command text can't be mistaken
  for output) and brackets its output in per-call nonce markers.
- **Exit vs hold.** `exit` ends the shell, which by design tears the session's
  network (own-ip lease + switch attachment) down. So the driver has two shapes:
  *one-shot* (`session_out`) feeds the script then `exit`s — fine for pure
  assertions, `destroy` follows immediately; *held-open* (`session_hold`) feeds
  the script then holds stdin open (`sleep`) so the shell — and its lease +
  backgrounded server — stays alive while the host curls it. The lease is read
  in the SAME attach that starts the server, so it cannot go stale. Only
  `destroy` ends a session.
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
  (backgrounded `socat`) and the attach is HELD OPEN (which keeps the session +
  the server alive) while the host-side `curl`/`ssh-forward` runs, then the
  session is `destroy`ed.
- **mTLS cert dir** (`minimal login`): `~/Library/Application Support/minimal` on
  macOS, `~/.config/minimal` (XDG) on Linux — the script picks it per-OS.

## Deployment models — bring-up, teardown, topology

### DM1 — macOS (Apple Silicon) + libkrun Linux VM

- **Bring-up:** `just dm1` (= `just up` on macOS: builds artifacts + gvproxy +
  initramfs + minvmd + CLI, then `minimal ls` auto-spawns `minvmd run --detach`).
- **Teardown:** `just stop` (SIGTERM → SIGKILL on the supervised minvmd).
- **Expected topology (TC10):** `minvmd` process supervising the VM; host-side
  `gvproxy` child; minimald as initramfs pid-1 *inside* the VM; CLI dials the UDS
  at `<state>/minimal/providers/local-0/ssh.sock`; `:7654`/`:7655` proxies are
  bound in-VM on `0.0.0.0` and re-published to host loopback via gvproxy
  (`crates/minimald/src/server.rs` `expose_proxy_on_host`).
- **Runs on:** this Mac. CI: `ci-macos.yml`.

### DM2 — native Linux, host-native minimald (no VM)

- **Bring-up:** `just dm2` — builds minimald with the networking features and
  starts it under a dedicated state dir (`.scratch/dm2-state`), gvproxy pinned
  via `--gvproxy-bin`. All CLI calls then need `--minimal-dir .scratch/dm2-state`
  (the script handles this when `DM=dm2`).
- **Teardown:** `just dm2-down`.
- **Expected topology (TC10):** one native `minimald`; **no** `minvmd`; own-IP is
  rootless (hakoniwa RustSlirp builds the tap inside the sandbox's own user+net
  namespace); proxies bind host loopback `127.0.0.1:7654/7655` directly.
- **Runs on:** any Linux host / Lima VM (needs unprivileged user namespaces, not
  KVM). CI: `ci-netns.yml` covers the netns/gvproxy layer.

### DM3 — native Linux + libkrun Linux VM over KVM

- **Bring-up:** `just dm3` — requires writable `/dev/kvm` (`sg kvm -c 'just dm3'`
  if needed); boots the VM, then symlinks the CLI socket to minvmd's bridge
  (`$XDG_RUNTIME_DIR/minimal/minimald.sock`).
- **Teardown:** `just stop`.
- **Expected topology (TC10):** as DM1, on KVM instead of HVF. The sandbox guest
  is Linux on every host, so **TC1–TC8 assertions are byte-identical to DM1** —
  that is TC11's parity claim.
- **Runs on:** a Linux KVM host; the Lima host *if* it supports nested
  virtualization (vz backend, Apple M3+, macOS 15+ — otherwise `/dev/kvm` is
  absent inside Lima and `just dm3` exits early). CI: `ci-linux-kvm.yml` runs the
  boot/session/bridge E2Es under `MINVMD_E2E=1`.

### DM4 — DM2 + DM3 combined on one Linux host

- **Bring-up:** no `just dm4` target exists; compose it: `just dm3` **then**
  `just dm2`. The control planes do not collide — the VM daemon is reached via
  the bridged `providers/local-0/ssh.sock` under the default state dir, the
  native daemon via `--minimal-dir .scratch/dm2-state`.
- **Known defect (G-N1):** both daemons hardcode the proxy ports —
  `crates/minimald/src/net/proxy.rs:31-39` — and the bind is warn-only
  best-effort (`proxy.rs:154-172`), so whichever daemon starts first owns
  `127.0.0.1:7654/7655`; the loser's UC2a/UC2b surface silently vanishes.
  TC15 asserts this observably rather than pretending it works.
- **Expected topology (TC10):** both DM2 and DM3 shapes simultaneously; exactly
  one listener each on `:7654`/`:7655`.
- **Runs on:** same hosts as DM3 (KVM required for the VM half).

### DM5 — any of the above, network-accessible + authenticated

Entirely unimplemented (G-N2): the CLI has no `--server`/hostname flag
(`ActivateArgs`, `crates/minimal/src/main.rs:165-182`), dials UDS only
(`crates/minimal/src/client.rs`), and the daemon's RPC/session listener is
UDS-only. The `:7654`/`:7655` proxies bind loopback, never an external
interface. The minvmd bridge spec explicitly warns: "Do not expose the bridge
over TCP without rethinking auth"
(`docs/specs/01-spec-minvmd-host-daemon/01-spec-minvmd-host-daemon.md:445-447`).
TC16 specifies the tests that activate when DM5 lands.

## Per-DM results

Verdicts from `test-plan.sh` runs. DM2 column: 2026-06 run on the epic branch
(carried from the previous revision of this plan). DM1 column: 2026-07-02
`DM=dm1` runs on macOS/HVF — identical verdicts under both the expect driver
and the heredoc driver that replaced it, so the failures below are
driver-independent.

| TC | DM1 (macOS+VM, 2026-07-02) | DM2 (native Linux, 2026-06) | DM3 | DM4 |
|----|----------------------------|------------------------------|-----|-----|
| TC1 no-net | PASS — no interfaces visible; curl 000; DNS fails | PASS — only `lo`; curl fails; DNS fails | not yet run | not yet run |
| TC1b host-net | PASS — curl 200; DNS resolves | PASS — curl 200; DNS resolves | not yet run | not yet run |
| TC2 own-ip + peer | PASS — egress 200; `TC2_PEER=YES` (peer lease 100.64.0.3) | PASS — egress 200; `TC2_PEER=YES` | not yet run | not yet run |
| TC3 DNS :7654 | **FAIL 502** — proxy live + routes; backend leg fails (see note) | routing landed; e2e pending backend flake | not yet run | not yet run |
| TC4 static ingress | **FAIL 000** — host→`:18080` connection reset with backend live (see note) | path verified; e2e pending | not yet run | not yet run |
| TC5 policy validation | PASS — all 3 rejected with correct messages | PASS — all 3 rejected | not yet run | not yet run |
| TC6 policy round-trip | PASS — ingress JSON round-trips | PASS | not yet run | not yet run |
| TC7 mTLS :7655 | PARTIAL — no-cert 401 PASS; with-cert **502** (see note) | PARTIAL — no-cert 401 PASS; with-cert pending | not yet run | not yet run |
| TC8 ssh-forward | **FAIL 000** — connection reset through the forward (see note) | e2e pending | not yet run | not yet run |
| TC9 mesh CLI | PASS — status/join/leave OK | PASS | not yet run | not yet run |
| TC10 preflight | PASS — minvmd + gvproxy running; 1 listener each on :7654/:7655 | not yet run | not yet run | not yet run |
| TC12–TC17 | SKIP (blocked/gap — see matrix) | SKIP | SKIP | TC15 not yet run |

**DM1 finding (2026-07-02): the host→PTask data path fails with a LIVE
backend.** TC3 (502 via :7654), TC4 (RST on the published `127.0.0.1:18080`),
TC7 with-cert (502 via :7655), and TC8 (RST through ssh-forward) all reduce to
the same leg: published-loopback-port → gvproxy forward → lease:8080. In each
case the in-session `socat` backend was confirmed up (`SERVER_UP`) and the
session detached (lease stable), so this is **not** the DM2-era "backend
flake" — the forward itself does not reach the backend's lease. One suspect:
the ingress forward is applied at *activate* time while the own-ip lease is
created at first *attach*, and the allocator never reuses IPs — an
activate-time lease target would RST forever. Needs a daemon-side look at
which lease `apply_ingress` binds versus the lease the sandbox actually gets.

Historical note (DM2 run): own-ip attach + same-host peer routing work; two
earlier symptoms were harness artifacts fixed in `test-plan.sh` (inline-expect
readiness; `exit` instead of detach churning leases). Host→guest reachability is
resolved by the published-loopback model: the daemon is **not** on the switch;
host→PTask goes through a gvproxy-published loopback port (`127.0.0.1:<external>`
→ `lease:<internal>`), #542 landed the hostname → `127.0.0.1` registration, and
the `:7654`/`:7655` proxies route by `Host:` header to the published port
(spec R3.1/R3.3/R4.4).

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

## TC1b — host-net egress (positive control)
```bash
$M activate -n tc1b --network host-net .
# in the interactive shell: curl http://example.com -> 200 ; getent hosts github.com -> resolves
$M destroy tc1b
```

## TC2 — UC6 OwnIp egress + same-host peer
Two own-ip sessions; both via the full session path. The listener runs on an
**unprivileged** port (the sandbox can't bind <1024), and peer's lease is read in
the SAME attach that starts the listener; that attach is then HELD OPEN so the
lease stays stable and the listener keeps serving while demo dials it.
```bash
$M activate -n demo --network own-ip .
$M activate -n peer --network own-ip .
# demo shell: curl http://example.com -> 200 (egress via the switch)
# peer shell (held open): socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf PEER_REACHED' &   then read
#             PIP=$(grep -B1 'host LOCAL' /proc/net/fib_trie | grep -oE '100\.64\.0\.[0-9]+' | head -1)
# demo shell: curl --http0.9 http://$PIP:8080/  -> PEER_REACHED
$M destroy demo peer
```

## TC3 — UC2a managed DNS via host proxy :7654
Published-loopback model: the PTask's port is published on host loopback via
ingress, its hostname registers → `127.0.0.1` (R3.1/#542), and the `:7654` proxy
routes `Host:` → `127.0.0.1:<published>`. The client uses the published external
port in the authority.
```bash
$M activate -n web --network own-ip --ingress 18080:8080 .
# web shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nWEB_OK"' & (attach held open)
# host:      curl -x http://127.0.0.1:7654 http://web.local.min.internal:18080/   -> want 200 WEB_OK
$M destroy web
```

## TC4 — UC4 static ingress 18080:8080
```bash
$M activate -n tc4 --network own-ip --ingress 18080:8080 .
$M session policy tc4          # shows the mapping
# tc4 shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nINGRESS_OK"' & (attach held open)
# host:      curl http://127.0.0.1:18080/   -> want 200 INGRESS_OK
$M destroy tc4
```

## TC5 — policy validation (CLI-only; expect rejections)
No session is launched, so no attach is involved.
```bash
$M activate -n bad1 --network host-net --ingress 18080:80 .     # -> "ingress ... only valid for an own-IP PTask"
$M activate -n bad2 --network own-ip  --ingress 80:80 .         # -> privileged host port refused
$M activate -n bad3 --network own-ip  --ingress 18080:80/icmp . # -> "unsupported protocol 'icmp'"
$M ls                                                           # none created
```

## TC6 — live policy round-trip (CLI-only)
```bash
$M activate -n tc6 --network own-ip --ingress 18080:80/tcp .
$M session policy tc6     # JSON reflects the launch policy
$M destroy tc6
```

## TC7 — UC2b mTLS reverse proxy :7655
Backend in-sandbox; host hits the proxy with/without a client cert. The proxy
routes by the `Host:` header authority — `<name>.<host-id>.min.internal:<published-port>`
(same router as :7654; TLS SNI stays `localhost`, per
`mtls_valid_cert_routes_to_backend`, `crates/minimald/src/net/proxy.rs:892`) —
so the backend port must be published via ingress.
```bash
$M login                                  # writes <cert-dir>/{ca,client}.pem, client.key
$M activate -n tc7 --network own-ip --ingress 18081:8080 .
# tc7 shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nBACKEND_OK"' & (attach held open)
# host (cert):   curl --cacert .../ca.pem --cert .../client.pem --key .../client.key \
#                https://localhost:7655/ -H "Host: tc7.local.min.internal:18081"   -> want 200 BACKEND_OK
# host (no cert):curl -k https://localhost:7655/   -> 401
$M destroy tc7
```

## TC8 — ssh-forward (R4.9)
```bash
$M activate -n dev --network own-ip --ingress 18080:8080 .
# dev shell: socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:'printf "HTTP/1.0 200 OK\r\n\r\nFORWARD_OK"' & (attach held open)
# host: minimal ssh-forward dev 18080:127.0.0.1:8080 &
#       curl http://localhost:18080/   -> want 200 FORWARD_OK
$M destroy dev
```

## TC9 — UC7 WireGuard mesh (CLI surface)
Data path is covered by TC17 (blocked); here only the CLI surface.
```bash
$M mesh status     # prints key / advertised subnets / peers (or "no mesh configured")
$M mesh join 127.0.0.1:51820   # records enrolment, prints manual key-exchange steps
$M mesh leave
```

## TC10 — topology preflight (all DMs)
Asserts the selected DM's expected shape before the suite runs; a wrong shape
means the verdicts that follow would test the wrong deployment model.

- **DM1:** `minvmd` process present; `minvmd status` reports running; CLI UDS
  present; (informational) `:7654`/`:7655` listeners on host loopback.
- **DM2:** native `minimald` process present; **no** `minvmd` supervising it;
  UDS at `<dm2-state>/providers/local-0/ssh.sock`.
- **DM3:** `/dev/kvm` present + writable; `minvmd status` running; bridge
  symlink `providers/local-0/ssh.sock` → `$XDG_RUNTIME_DIR/minimal/minimald.sock`.
- **DM4:** DM2 *and* DM3 checks both pass; **exactly one** listener each on
  `:7654` and `:7655` (G-N1 observed, not hidden).

Pass = all checks for the selected DM hold; `minimal ls` answers on each
expected control plane.

## TC11 — DM3 parity run
`just dm3`, then run TC1–TC10 unchanged (`DM=dm3 ./test-plan.sh`). Pass =
verdicts identical to the DM1 column (the sandbox guest is Linux on every host;
HVF vs KVM must be invisible to every assertion). Divergence in any TC is a
finding against the shared-switch architecture's platform-uniformity claim.
Runs on a Linux KVM host, Lima-nested (M3+/macOS 15+), or `ci-linux-kvm.yml`.

## TC12 — UC5 `vm_egress` (R2.5) — BLOCKED(G-N3)
**Spec:** on DM1/DM3/DM4, a `vm_egress` allowlist (e.g. `allow_subnets` without
the test target's subnet) constrains **all** traffic from the VM:
1. a `host-net` session's `curl http://<disallowed-ip>` fails, `curl` to an
   allowed host succeeds;
2. an `own-ip` session is constrained identically (VM-wide applies regardless of
   per-PTask mode);
3. on DM2, supplying `vm_egress` is rejected as a configuration error naming
   the field ("VM-wide egress is not applicable on DM2").
**Today:** `VmConfig` carries `vm_egress` and `validate_for` implements the R2.5
acceptance/rejection per DM (`crates/minvmd/src/vm.rs:119-150`, unit-tested),
but no runtime surface populates it — `minvmd` reads only
`MINVMD_KERNEL_PATH`/`MINVMD_ROOTFS_PATH`/`MINVMD_INITRAMFS`/`MINVMD_MARKER_SOCK`
(`crates/minvmd/src/cmd/vmm_child.rs:8-10`), and enforcement is pending the
#553 layer (referenced in `vm.rs`). Activates when a config surface
(env/flag/VM-spec file) lands.

## TC13 — UC3 per-PTask egress (R2.1/R2.2) — BLOCKED(G-N4)
**Spec:** launch an own-ip session with `egress.allow_subnets=[<allowed>/32]`,
`allow_protocols=[tcp]`:
1. in-session `curl http://<allowed-ip>` succeeds; `curl http://<other-ip>`
   is dropped (not RST from the target — dropped at the switch);
2. UDP to anywhere fails (protocol not allowed);
3. the daemon emits the R2.2 rate-limited `tracing::warn!` on first drop;
4. `egress` on a `no-net`/`host-net` session is a parse-time error (R2.1).
**Today:** the CLI hardcodes `egress: None` at activate
(`crates/minimal/src/main.rs:459`) — there is no flag or spec-file field to set
it. Activates when an `--egress`/spec surface lands.

## TC14 — R2.4 dynamic port-map — BLOCKED(G-N5)
**Spec:** launch own-ip with `dynamic_allowed_ports=18100-18110`; from inside
the session request a mapping `18105:8080`; host `curl 127.0.0.1:18105` → 200;
request `19000:8080` → typed out-of-range rejection; `session policy` reflects
the live mapping.
**Today:** the RPC type exists (`crates/minimald-rpc/src/lib.rs:401`) but no
handler in `crates/minimald/src/` serves it and no in-sandbox client exists.

## TC15 — DM4 co-residency (partial; observes G-N1)
```bash
just dm3                                  # VM daemon first (owns :7654/:7655)
just dm2                                  # native daemon second (bind warns, loses)
# TC10 dm4 preflight: both control planes answer `ls`; exactly one :7654 listener
# Run TC1 + TC2 against the VM daemon      (default state dir)
# Run TC1 + TC2 against the native daemon  (--minimal-dir .scratch/dm2-state)
# Observe G-N1: grep the dm2 log for the proxy-bind warning; assert the :7654
# proxy still answers for the FIRST daemon's sessions (TC3 against dm3 only).
just dm2-down && just stop
```
Pass = both daemons serve isolated sessions concurrently; the port contention is
*observed and logged* (second daemon warns; first daemon's proxy unaffected).
The contention itself is the G-N1 defect — this TC documents it, it does not
accept it as correct.

## TC16 — DM5 remote authenticated access (UC2c) — SPEC-GAP(G-N2)
Activates when a network-accessible control plane lands. The tests, ready to run:
1. **UC2c control plane:** from a remote host, `minimal --server
   <hostname> ls/activate/attach` succeeds after authentication; the same
   commands with no/invalid credentials are rejected without leaking topology
   (R4.5's principle applied to the control plane).
2. **Remote UC2a:** `curl` from the remote host to the exposed `:7654` proxy
   reaches a published PTask port only with valid auth.
3. **Remote UC2b-B:** TC7's mTLS assertions executed from the remote host
   against the exposed `:7655` (today both proxies bind loopback only).
4. **Negative:** the RPC/bridge socket is never plain-TCP reachable
   (`01-spec-minvmd-host-daemon.md:445-447`).

## TC17 — UC7 mesh data path (R4.1–R4.3) — BLOCKED(G-N6)
**Spec:** two hosts (or two netns'd daemons), manual key exchange, then:
1. `mesh status` on both shows the peer with a recent handshake;
2. own-ip PTask on A reaches an own-ip PTask on B by switch IP over the tunnel
   (TCP and UDP);
3. laptop `mesh join` → browser reaches a remote PTask by hostname (UC2b-A).
**Today:** the boringtun data plane is real and integration-tested
(`crates/minimald/src/net/wg.rs`), but `mesh join` only writes a local
enrolment file the daemon never reads — `set_mesh` is called only from tests
(`crates/minimald/src/rpc.rs:1001`). Activates when daemon startup consumes the
enrolment/mesh config.

## CI mapping

| Workflow | Covers | Gap |
|---|---|---|
| `ci-macos.yml` | DM1 boot/session E2E | does not run this plan's TC suite |
| `ci-netns.yml` | DM2 netns + gvproxy layer (`crates/minimald/tests/netns.rs`) | not the full-session-path TCs |
| `ci-linux-kvm.yml` | DM3 boot/session/bridge E2E (`MINVMD_E2E=1`) | natural home for a TC11 job; not wired yet |

Wiring `DM=dm3 ./test-plan.sh` into `ci-linux-kvm.yml` (and `DM=dm2` into a
netns-capable runner) would make TC11 continuous; noted as follow-up, not done
by this plan.

## Gap register

| ID | Blocks | What's missing | Evidence |
|----|--------|----------------|----------|
| G-N1 | TC15; TC3/TC7 on DM4 | Proxy ports `7654`/`7655` hardcoded, no per-instance override; bind is warn-only so the second daemon silently loses its UC2a/UC2b surface | `crates/minimald/src/net/proxy.rs:31-39`, `:154-172` |
| G-N2 | TC16, all of DM5 | No `--server`/hostname in the CLI; UDS-only control plane; proxies loopback-only; bridge doc forbids naive TCP exposure | `crates/minimal/src/main.rs:165-182`; `crates/minimal/src/client.rs`; `01-spec-minvmd-host-daemon.md:445-447` |
| G-N3 | TC12 (UC5/R2.5) | `vm_egress` has types + validation but no runtime config surface, and enforcement is pending #553 | `crates/minvmd/src/vm.rs:119-150`; `crates/minvmd/src/cmd/vmm_child.rs:8-10` |
| G-N4 | TC13 (UC3/R2.1/R2.2) | No CLI/spec surface for per-PTask egress; hardcoded `egress: None` | `crates/minimal/src/main.rs:459` |
| G-N5 | TC14 (R2.4) | Dynamic port-map RPC type exists, no daemon handler, no in-sandbox client | `crates/minimald-rpc/src/lib.rs:401` |
| G-N6 | TC17 (UC7/R4.1–R4.3) | Daemon never consumes mesh enrolment; `set_mesh` test-only | `crates/minimald/src/rpc.rs:1001`; `crates/minimal/src/main.rs:716-751` |
| G-N7 | multi-VM variants of DM1/DM3 | Spec says "one or more" VMs; minvmd supervises exactly one (single `vmm.pid`/`state.toml`/`lifecycle.lock`) | `crates/minvmd/src/state.rs:6-9` |
