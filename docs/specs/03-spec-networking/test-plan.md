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

> **Correction (2026-07-07, DM1 macOS/HVF) — supersedes the TC3/TC4/TC7/TC8
> verdicts below.** Those failures were substantially a **test-harness
> artifact**: the in-session backend built its HTTP reply inside socat's
> `SYSTEM:` address, which mangled the `printf` and served a **non-HTTP** reply
> (`curl: Received HTTP/0.9 when not allowed` → `http_code 000`). The forward
> *delivered* the bytes; the reply was just malformed. A re-run with a corrected
> file-served backend on a clean DM1 stack gives:
>
> | TC | Corrected DM1 (2026-07-07) |
> |----|----------------------------|
> | TC3 DNS :7654 | **FAIL 502** — in-VM proxy dials in-VM `127.0.0.1:18080`; gvproxy's forwarder listens on the **host** loopback → connect fails (sub-break ii, not a forwarding-leg defect) |
> | TC4 static ingress | **PASS 200** — host→`127.0.0.1:18080`→gvproxy→`lease:8080` works end-to-end (prior `000` was the malformed backend) |
> | TC7 mTLS :7655 | PARTIAL — no-cert **401** PASS; with-cert **502** (same sub-break ii as TC3) |
> | TC8 ssh-forward | **FAIL 000** — `direct-tcpip` defect; the interim Part 1 change routes to host loopback, still wrong for the VM path |
>
> TC1/TC1b/TC2/TC5/TC6/TC9/TC10 re-verified PASS unchanged. The **DM2/DM3/DM4**
> columns below have since been **re-run with the fixed `test-plan.sh`**
> (2026-07-07): **DM2 now passes TC3/TC4/TC7/TC8 (200/200/200+401/200)** — the
> native shared-netns forwarder works end-to-end, confirming the old verdicts
> were the backend artifact. **DM3 initially still failed TC3/TC4/TC7/TC8 via
> G-N8** — first read as an ingress-`attach` hang, later pinned (2026-07-08) as a
> *fast* failure: gvproxy's forwarder response is dropped over the KVM vsock
> shuttle. With the `net::policy` keep-alive/`Content-Length` fix, **DM3
> TC3/TC4/TC7/TC8 now PASS (200/200/(401+200)/200)**, exercising the G-N9 lease
> route end-to-end on the VM. Full analysis:
> [`gn9-forwarding-findings.md`](gn9-forwarding-findings.md).

> **Re-run (2026-07-08, DM1 macOS/HVF), 4 passes — mixed; a new own-ip-churn
> interaction (G-N11) gates the proxy TCs.** Clean DM1 stack on HEAD `9443becb`
> with the G-N9 fix `9807ba99` built in. Two passes ran the plan as it stood
> (in-sandbox `curl` absent — G-N10); two ran after wiring `min add curl` into
> TC1b/TC2 to restore the egress probes. The proxy verdicts diverge by whether
> real own-ip egress ran *before* them:
>
> | TC | no `min add curl` (×2) | with `min add curl` (×2) |
> |----|------------------------|--------------------------|
> | TC1b host-net egress | curl absent → unproven | **PASS 200** + DNS |
> | TC2 own-ip egress / peer | curl absent → `TC2_PEER=NO` | **PASS 200 / `TC2_PEER=YES`** (peer 100.64.0.3) |
> | TC3 DNS :7654 | **PASS 200** ×2 | **FAIL 502** ×2 |
> | TC4 static ingress | PASS 200 | PASS 200 |
> | TC7 :7655 no-cert | 401 | 401 |
> | TC7 :7655 with-cert | 200 ×2 | **FAIL 000** ×2 (host curl/LibreSSL) |
> | TC8 ssh-forward | 000 / 200 (flaky) | 200 / 000 (flaky) |
>
> - **G-N9 proxy path works clean but is not robust to prior own-ip churn
>   (G-N11).** TC3's `:7654` proxy is 200 from a fresh VM with no prior own-ip
>   egress, but **reproducibly 502 (2/2)** once TC1b/TC2 drive real own-ip egress.
>   TC4 (direct ingress, no proxy lease-remap) stays 200 throughout, so the fault
>   is in the proxy lease-routing under prior switch usage, not the forwarder. The
>   first pass on the fresh VM already failed, so it is not slow state
>   accumulation. So the G-N9 register's "proxy consumers unit-tested only, DM1
>   runtime pending" is only *conditionally* closed: 200 in isolation, 502 after
>   churn.
> - **TC7 with-cert is a host-TLS issue, not the proxy.** no-cert 401 is stable
>   (the mTLS gate works). The with-cert leg fails at the *host* `curl 8.7.1 /
>   LibreSSL 3.3.6`, which rejects the (valid — OpenSSL parses it, pubkeys match)
>   P-256 client key from `minimal login` with `asn1 encoding routines … EVP
>   lib`; reproduces standalone, and `openssl s_client` shows a CA-chain mismatch
>   between the login cert and the proxy's server cert on this VM instance.
>   run1/run2 got 200 on an earlier instance, so it is host/PKI-instance
>   dependent — a dedicated cert/TLS pass, tracked as G-N12.
> - **TC8 remains flaky** (000/200 across all four passes) — see the 2026-07-08
>   root-cause below (G-N13): a session-liveness race, *not* a `direct-tcpip`
>   data-path defect.
> - **G-N10 fix confirmed:** `min add curl` restores in-sandbox curl (egress 200,
>   peer YES) and is now wired into TC1b/TC2. But because own-ip egress breaks the
>   proxy TCs (G-N11), a single pass cannot cleanly assert both curl-egress and
>   proxy-forwarding — read TC3/TC7 from a churn-free pass until G-N11 lands.
> - Stable PASS every pass: TC1 (no-net isolation), TC4, TC5, TC6, TC9, TC10.
>
> **Follow-up (same day) — `be711722` closes G-N11; verified on DM1.** The above
> was on HEAD `9443becb`; the Content-Length forwarder-framing fix `be711722`
> (which pinned and fixed G-N8, and "also repairs the in-VM `:7654`/`:7655`
> proxy-publish — same leg") landed shortly after. Re-run on HEAD `a686f703`
> (`be711722` built into the initramfs), **2 passes, both WITH the `min add curl`
> churn that previously forced 502**:
>
> | TC | a686f703 pass 1 | a686f703 pass 2 |
> |----|-----------------|-----------------|
> | TC3 DNS :7654 | **PASS 200** | **PASS 200** |
> | TC4 static ingress | 200 | 200 |
> | TC7 no-cert / with-cert | 401 / **200** | 401 / **200** |
> | TC8 ssh-forward | **000** | **200** |
>
> - **G-N11 RESOLVED.** TC3 is 200 *after* own-ip egress (2/2), not 502 — the
>   proxy-publish leg was the same forwarder-framing bug as G-N8; `be711722`
>   repairs both. So G-N9's in-VM proxy path is now DM1-runtime-verified
>   unconditionally.
> - **G-N12 not reproduced** on this instance: TC7 with-cert is 200 (2/2). It was
>   host/PKI-instance-dependent (the earlier VM's `login` cert tripped LibreSSL);
>   downgraded to a watch item.
> - **TC8 still flaky** (000 then 200) — root-caused 2026-07-08 as a **session-
>   liveness race under full-plan load (G-N13), not a `direct-tcpip` defect.** The
>   `000` is `direct-tcpip rejected: session not found`: the `ssh-forward`'s
>   `dev` session is reaped ~5s after its held attach (only in the full-plan
>   context — in isolation the same attach survives 6/6), so the forward's
>   channel validates a destroyed session and the client resets. `direct-tcpip`
>   is correctly failing closed; it never reaches the lease-dial code, so this is
>   unrelated to G-N9. Harness hardening (in-sandbox hold; settle+retry) did not
>   fix it — a settle *worsened* it to 0/16 by pushing the curl past the ~5s
>   reap, which is what pinned the mechanism. Needs daemon-side teardown-path
>   tracing (who reaps `dev`).

Verdicts from `test-plan.sh` runs. **DM2 and DM3 columns: 2026-07-07 `DM=dm2` /
`DM=dm3` runs on a native Linux/aarch64 host** (Ubuntu; unprivileged userns
unblocked via `kernel.apparmor_restrict_unprivileged_userns=0`; KVM + libkrun
for the VM half), with the **fixed `test-plan.sh` backend** and, for DM2, the
**G-N9 lease-routing code**. DM2's TC3/TC4/TC7/TC8 now PASS (the change is gated
to the VM/Vsock path, so DM2 is byte-identical to the pre-fix native path — the
PASS is the corrected backend + working shared-netns forwarder, not the lease
route). **DM3's TC3/TC4/TC7/TC8 now PASS (200/200/(401+200)/200) after the G-N8
fix (2026-07-08 `DM=dm3` re-run on the KVM VM), verifying the G-N9 lease path
end-to-end on the VM** — see the G-N8 gap-register row for the vsock-forwarder
response-drop root cause and the keep-alive fix. DM4 TC1–TC9 run against the VM
daemon and mirror the DM3 column (TC10/TC15 were the DM4-specific 2026-07-03
checks). DM1 column: 2026-07-02
`DM=dm1` runs on macOS/HVF — identical verdicts under both the expect driver and
the heredoc driver that replaced it, so the failures below are
driver-independent.

| TC | DM1 (macOS+VM, 2026-07-02) | DM2 (native Linux, 2026-07-07) | DM3 (Linux+KVM, 2026-07-07) | DM4 (2026-07-03) |
|----|----------------------------|--------------------------------|------------------------------|------------------|
| TC1 no-net | PASS — no interfaces visible; curl 000; DNS fails | PASS — no interfaces (`IFACES=`); curl 000; DNS fails | PASS — no interfaces; curl 000; DNS fails | = DM3 (VM daemon) |
| TC1b host-net | PASS — curl 200; DNS resolves | PASS — curl 200; DNS resolves | PASS — curl 200; DNS resolves | = DM3 (VM daemon) |
| TC2 own-ip + peer | PASS — egress 200; `TC2_PEER=YES` (peer lease 100.64.0.3) | PASS — egress 200; `TC2_PEER=YES` (peer 100.64.0.3) | PASS — egress 200; `TC2_PEER=YES` (peer 100.64.0.3) | = DM3 (VM daemon) |
| TC3 DNS :7654 | **FAIL 502** — proxy live + routes; backend leg fails (see note) | **PASS 200** — fixed backend; native loopback path (2026-07-07) | **PASS 200** — G-N8 fixed 2026-07-08 (in-VM `:7654` proxy → `lease:8080`) | = DM3 (VM daemon) |
| TC4 static ingress | **FAIL 000** — host→`:18080` connection reset with backend live (see note) | **PASS 200** — host→`:18080`→forwarder→`lease:8080` (2026-07-07) | **PASS 200** — G-N8 fixed 2026-07-08 (host→`:18080`→forwarder→`lease:8080`) | = DM3 (VM daemon) |
| TC5 policy validation | PASS — all 3 rejected with correct messages | PASS — all 3 rejected with correct messages | PASS — all 3 rejected | = DM3 (VM daemon) |
| TC6 policy round-trip | PASS — ingress JSON round-trips | PASS — ingress JSON round-trips | PASS — ingress JSON round-trips | = DM3 (VM daemon) |
| TC7 mTLS :7655 | PARTIAL — no-cert 401 PASS; with-cert **502** (see note) | **PASS** — no-cert 401; with-cert **200** (2026-07-07) | **PASS** — no-cert 401; with-cert **200** — G-N8 fixed 2026-07-08 | = DM3 (VM daemon) |
| TC8 ssh-forward | **FAIL 000** — connection reset through the forward (see note) | **PASS 200** — through the ssh-forward → `lease:8080` (2026-07-07); a 2026-07-08 re-run saw **000** (the session-liveness race G-N13, not a `direct-tcpip`/lease defect — unrelated to G-N8) | **PASS 200** — G-N8 fixed 2026-07-08 (ssh-forward → `direct-tcpip` → `lease:8080`, validating the G-N9 lease route on the VM path) | = DM3 (VM daemon) |
| TC9 mesh CLI | PASS — status/join/leave OK | PASS — status/join/leave OK | PASS — status/join/leave OK | = DM3 (VM daemon) |
| TC10 preflight | PASS — minvmd + gvproxy running; 1 listener each on :7654/:7655 | PASS — native minimald; no minvmd; UDS present | PASS — `/dev/kvm` OK; minvmd running | PASS — both control planes answer; **exactly 1** listener each on :7654/:7655 (G-N1) |
| TC15 co-residency | N/A | N/A | N/A | **PASS** — both daemons serve isolated sessions concurrently; the 2nd daemon (native) loses the proxy bind with `Address already in use`, one :7654 listener remains (G-N1 observed) |
| TC12–TC14, TC16–TC17 | SKIP (blocked/gap — see matrix) | SKIP | SKIP | SKIP |

**Cross-DM finding — CORRECTED (2026-07-07).** The earlier "host→PTask ingress
path is broken on every DM" conclusion was largely a **test-harness artifact**.
Re-run on DM1 with a valid, file-served backend:

- **TC4 (direct host→forwarder→lease) PASSES (200).** The published-loopback
  data path works end-to-end; the prior `000`/reset was the malformed backend
  (curl rejecting an HTTP/0.9 reply), not a forwarding failure. The gvproxy
  forwarder table registers `127.0.0.1:18080 → lease:8080` at attach and drops it
  at destroy, exactly as designed.
- **TC3 / TC7-with-cert still FAIL (502)** for a *narrow* defect (sub-break ii):
  the in-VM `:7654`/`:7655` proxies resolve own-ip hostnames to
  `127.0.0.1:<external>` (`crates/minimald/src/net/dns.rs` `register_own_ip` →
  `LOOPBACK`) and connect on the **in-VM** loopback, but gvproxy's forwarder
  listener is on the **host** loopback — unreachable from inside the VM. The
  daemon *can* reach `lease:<internal>` over the switch (verified 200 from the
  guest root netns via `attach -c`), so the fix routes in-VM consumers to the
  lease.
- **TC8 still FAILS** for the original `direct-tcpip` defect (raw connect in the
  daemon netns; `crates/minimald/src/connection.rs` `channel_open_direct_tcpip`).
  The interim Part 1 change resolves the ingress mapping but dials
  `127.0.0.1:<external>` (host loopback) — still wrong for the VM path.

Full evidence and fix design (store the lease per session; route `direct-tcpip`
and the proxies to `lease:<internal>`; keep the forwarder for host-direct access;
DM2 needs a transport-aware branch verified on Linux):
[`gn9-forwarding-findings.md`](gn9-forwarding-findings.md).

**Re-verified 2026-07-07:** DM2 TC3/4/7/8 now PASS (200/200/200+401/200) with the
fixed backend, confirming the old verdicts were the harness artifact.
**Re-verified 2026-07-08 (G-N8 fixed):** DM3 TC3/4/7/8 now PASS
(200/200/(401+200)/200) on the KVM VM. G-N8 was never an attach hang — the
own-ip+ingress attach *failed fast* because gvproxy's forwarder response was
dropped over the KVM vsock shuttle (the forward was applied, the reply lost); the
">200 s" was only the suite's `hold_wait` ceiling. With the keep-alive/
`Content-Length` fix in `net::policy`, the **G-N9 in-VM lease path is now
runtime-verified end-to-end on the VM** (TC8=200 exercises `direct-tcpip →
lease:8080`). DM4's VM half mirrors DM3. **Remaining runtime gap:** DM1 (macOS/HVF)
is off the Linux dev host, so the DM1 verdicts predate this fix (DM1 was never
G-N8-affected — HVF delivers the forwarder response).

*DM4 (co-residency) → G-N1.* TC15 PASS: both control planes serve isolated
sessions concurrently; the second daemon to start (native) loses the hardcoded
`:7654`/`:7655` bind (`Address already in use (os error 98)`, exactly one
listener remains), confirming G-N1 observably rather than accepting it.

Historical note (unchanged): host→guest reachability uses the published-loopback
model — the daemon is **not** on the switch; host→PTask goes through a
gvproxy-published loopback port (`127.0.0.1:<external>` → `lease:<internal>`), #542
landed the hostname → `127.0.0.1` registration, and the `:7654`/`:7655`
proxies route by `Host:` header to the published port (spec R3.1/R3.3/R4.4).

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
(`crates/minvmd/src/cmd/vmm_child.rs:8-10`), and enforcement is pending
the #553 layer (referenced in `vm.rs`). Activates when a config surface
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
| G-N7 | multi-VM variants of DM1/DM3 | **Resolved wontfix-by-spec-scope (2026-07-07, #633).** Single-VM is an explicit v0.1 Non-Goal in `01-spec-minvmd-host-daemon` ("single named VM (`default`); multi-VM is a v0.2+ concern"); only the networking spec's "one or more VMs" wording conflicted. Amended `03-spec-networking.md` with a v0.1 single-VM scope note. No code change. | `crates/minvmd/src/state.rs:6-9`; `01-spec-minvmd-host-daemon.md:323-324` |
| G-N8 | TC3/TC4/TC7/TC8 on DM3/DM4 (KVM) | **FIXED 2026-07-08.** Was mis-recorded as a hang: the own-ip `--ingress` attach *failed fast* (~8 s, `network attach failed: malformed gvproxy status line: ""`); the ">200 s" was only the suite's `hold_wait` ceiling (`session_hold` never checks the attach exit, so a fast failure and a hang look identical). Root cause: gvproxy's forwarder HTTP verbs (`/services/forwarder/expose`, the `:7654`/`:7655` proxy-publish) do not round-trip over the **KVM** libkrun `add_vsock_port2(listen=false)` shuttle — the request arrives and *is applied* (the forward appears in the host `gvproxy-switch.sock` `/services/forwarder/all` table), but gvproxy's `Connection: close` response is dropped by the splice, so the guest reads 0 bytes and `apply_ingress` rolls back a *successful* expose. Only the `/connect` L2 relay survives the splice (egress works); DM1/HVF is unaffected. **Fix:** `post_json`/`exchange` now use HTTP/1.1 keep-alive (no `Connection: close`) and frame the reply by `Content-Length` instead of read-to-EOF, so the server never closes first. **Verified live on DM3 (KVM): TC3/TC4/TC7/TC8 = 200/200/(401+200)/200**, startup proxy-publish `malformed` warnings gone; `cargo fmt`/`clippy -D warnings`/`test -p minimald` clean (regression test `exchange_frames_by_content_length_without_a_server_close`); DM2 forwarder path unregressed (TC3/4/7 green). | `crates/minimald/src/net/policy.rs` (`post_json`, `exchange`, `content_length`); pinned via the host forwarder-table probe + isolated ingress-vs-no-ingress repro |
| G-N9 | TC8 on the VM path (DM1); DM3/DM4 (verified 2026-07-08 once G-N8 was fixed, TC8=200) | **FIXED 2026-07-07; DM1 runtime 2026-07-08 = conditional.** Sandbox-owned lease routing: the in-VM `:7654`/`:7655` proxies and `direct-tcpip` dial the PTask's switch `lease:<internal>` instead of the host-loopback forwarder unreachable from inside the VM. Live lease published into the shared hostname registry at own-ip attach (Vsock/VM only), reverted at teardown, never persisted to the `Record`; DM2 keeps the loopback forwarder untouched. **DM1 runtime, HEAD `a686f703` (with `be711722`): the `:7654`/`:7655` proxy path is 200 unconditionally — 200 both churn-free and after own-ip egress (G-N11 closed by `be711722`). The G-N9 data path is fully verified: TC3/TC4/TC7 on DM1 and TC3/4/7/8 on DM3.** TC8's DM1 flakiness is **not** a G-N9 residual — it never reaches the lease-dial code; it is the session-liveness race G-N13. | `crates/minimald/src/net/{dns,proxy,gvproxy_network}.rs`; `crates/minimald/src/connection.rs`; [`gn9-forwarding-findings.md`](gn9-forwarding-findings.md) |
| G-N10 | TC1b, TC2 in-sandbox egress probes (all DMs) | **RESOLVED in-harness 2026-07-08 via `min add curl`.** In-sandbox `curl` disappeared after #650 made the session rootfs compose only *declared* packages (curl was incidental to the old base rootfs; not in `runtime_packages`, and declaring it does not compose it — a separate build/compose gap). TC1b/TC2 now provision curl per-session with `min add curl` (egress 200, peer YES). Residual: the underlying compose gap, and that the provisioning's own-ip egress triggers G-N11. | `.minimal/minimal.toml:8`; #650 (`crates/minimald/src/sessions/composables.rs:356`) |
| G-N11 | ~~TC3, TC7 on DM1 after own-ip egress~~ | **RESOLVED 2026-07-08 by `be711722`.** The 502 was not a distinct lease-routing defect: the `:7654`/`:7655` proxy-publish rides the **same forwarder control leg** as the G-N8 ingress attach, so the HTTP/1.0-`Connection: close` read-to-EOF framing that dropped over the vsock shuttle also dropped the proxy-publish. `be711722` (HTTP/1.1 + Content-Length) fixes both. Re-run on `a686f703` with the same `min add curl` churn: **TC3 = 200 (2/2)**, no longer 502. | fixed in `crates/minimald/src/net/policy.rs` (`be711722`); verified DM1 `a686f703` 2×200 |
| G-N12 | TC7 with-cert on DM1 (host side) — **not reproduced on `a686f703`** | `minimal login` issues a valid P-256 mTLS client cert/key (OpenSSL parses it; pubkeys match); on one earlier VM instance macOS `curl 8.7.1 / LibreSSL 3.3.6` rejected it at load (`asn1 … EVP lib`) with an `openssl s_client` CA-chain mismatch, but the `a686f703` re-run got **with-cert 200 (2/2)**. Host/PKI-instance dependent and intermittent; the proxy mTLS gate always works (no-cert → 401). Watch item, not a standing block. | 2026-07-08 DM1: `9443becb` instance failed, `a686f703` instance 2×200; `minimal login` cert issuance |
| G-N13 | TC8 ssh-forward on DM1 (flaky) | **TC8's `000` is a session-liveness race under full-plan load, not a `direct-tcpip`/lease defect.** The daemon logs `direct-tcpip rejected: session not found`: `ssh-forward` resolves `dev` → its UUID (passed as the SSH username), but `dev`'s session is reaped **~5 s after its held attach** — deterministically, and **only in the full-plan context** (in isolation the identical held attach + forward is 6/6 green). So the forward's channel validates a destroyed session and the client resets. `direct-tcpip` correctly fails closed and never reaches the lease-dial path (so this is unrelated to G-N9). Harness hardening did not fix it — an in-sandbox hold had no effect, and a settle+retry *worsened* it to **0/16** by pushing the curl past the ~5 s reap (which pinned the mechanism). TC3/4/7 pass because their curl lands inside the ~5 s window; TC8's extra `ssh-forward` step pushes it to the edge. **Needs daemon-side teardown-path tracing** to identify what reaps `dev` under prior-session churn (possibly a genuine product issue, akin to G-N11). | 2026-07-08 DM1: `direct-tcpip rejected: session not found`; `dev` register→deregister ≈5 s; isolation 6/6 vs in-plan ~50%/0%; `crates/minimald/src/connection.rs:521` |
