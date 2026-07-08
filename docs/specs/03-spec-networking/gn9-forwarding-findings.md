# G-N9 re-investigation — host→PTask forwarding on DM1

**Status:** fix **implemented** 2026-07-07 on branch
`networking-test-plan-all-dms` (sandbox-owned lease routing). Supersedes the
G-N9 characterization in `test-plan.md`. Verification: `cargo test -p minimald`
green (incl. new lease-lifecycle/lease-routing unit tests) + a clean **DM2**
regression, and — since **G-N8 was pinned and fixed (2026-07-08)** — a live
**DM3 (KVM)** run confirming the in-VM lease path end-to-end (TC3/TC4/TC7/TC8 =
200/200/(401+200)/200). DM1 (macOS/HVF) is off the Linux dev host, so its verdicts
predate the fix (HVF was never G-N8-affected). See
[Implementation](#implementation-2026-07-07) and
[G-N8 pinned + fixed](#g-n8-pinned--fixed-2026-07-08--vsock-forwarder-response-drop).

**Findings date:** 2026-07-07. **Host:** macOS/HVF (DM1), clean `minimal3` stack
(`just up`), libkrun VM, host gvproxy 0.8.8.

## TL;DR

The original G-N9 finding — *"host→PTask ingress forward never reaches the
in-session backend"* — is **substantially wrong**. Two separate causes were
conflated under one gap:

1. **A broken test backend (harness artifact).** The plan's in-session server,
   `socat … "SYSTEM:printf 'HTTP/1.0 200 OK\r\n\r\nWEB_OK'"`, emits a **non-HTTP**
   reply (socat's `SYSTEM:` quoting mangles the `printf`). `curl` reports
   `Received HTTP/0.9 when not allowed` and scores `http_code=000`. The bytes
   **do** traverse the forward; the reply is just malformed. This produced the
   `000`/`502` verdicts for **TC3/TC4/TC7/TC8** regardless of the data path.

2. **A real but narrow defect (sub-break ii).** Independent of the backend, the
   in-VM `:7654`/`:7655` proxies and the `direct-tcpip` handler dial
   `127.0.0.1:<external>` — the **in-VM** daemon's loopback — but gvproxy's
   forwarder listener lives on the **host** loopback, unreachable from inside the
   VM. So those consumers get a connect failure (`502` / "Connect failed").

The daemon itself **can** reach a PTask over the switch, so the fix is to route
in-VM consumers to the lease, not host loopback.

## Evidence (all live, valid HTTP backend served from a file)

| Probe | Result | Conclusion |
|---|---|---|
| in-sandbox `SELF` (`curl 127.0.0.1:8080`) | **200** | backend serves valid HTTP |
| **TC4** host → `127.0.0.1:18080` (gvproxy forwarder → lease) | **200** | **the forwarder path works** |
| **TC3** host → `:7654` proxy → `web…:18080` | **502** | in-VM proxy can't reach the forward (loopback split) |
| **TC7** host → `:7655` mTLS proxy | **502** | same |
| daemon (guest root netns, via `attach -c`) → `lease:8080` | **200** | **daemon reaches the lease over the switch** |
| exact test-plan backend, host → `:18080` | `HTTP/0.9 not allowed` → **000** | backend malformed; bytes still delivered |

Supporting facts:
- gvproxy forwarder table during an active ingress session (queried over
  `gvproxy-switch.sock` `GET /services/forwarder/all`):
  `{"local":"127.0.0.1:18080","remote":"100.64.0.9:8080"}` — the ingress `expose`
  is registered correctly, and removed on `destroy`. `apply_ingress`
  (`crates/minimald/src/net/policy.rs`) is **not** the problem.
- `lsof` shows the forwarder listener on the **host** (`gvproxy … 127.0.0.1:18080
  (LISTEN)`), confirming in-VM consumers cannot reach it via `127.0.0.1`.
- The `:7654`/`:7655` proxy publishes point at the daemon
  (`remote:100.64.255.253`), which is why those proxies are reachable while a
  per-session sandbox lease dialed on loopback is not.

## Why the original run saw uniform failure

The `test-plan.sh` server built the HTTP response *inside* socat's `SYSTEM:`
address. That path mangles the `printf` and serves HTTP/0.9. Every host-side
probe used a strict `curl -w %{http_code}` (no `--http0.9`), so a delivered-but-
malformed reply scored `000`, and the `:7654`/`:7655` proxies (which speak HTTP
to the upstream) returned `502`. TC8 additionally used the ingress external port
(`18080`) as the `ssh -L` local port, colliding with gvproxy's own `:18080`
listener, so the tunnel failed to bind and the curl silently hit the forwarder.
Both harness bugs are fixed in `test-plan.sh` (file-served response; TC8 uses a
distinct local port).

## Corrected DM1 picture

- **TC4 passes.** The published-loopback model (host `127.0.0.1:<external>` →
  gvproxy → `lease:<internal>`) works end-to-end for **direct host access**.
- **TC3/TC7 fail** for the loopback-namespace split (sub-break ii), not a
  forwarding-leg defect.
- **TC8 fails** for the original G-N9 reason (direct-tcpip dialed the raw target
  in the daemon netns) — and the interim Part 1 change (route to
  `127.0.0.1:<external>`) does **not** fix it on DM1 for the same sub-break (ii).

## The fix (implemented 2026-07-07)

Route in-VM host→PTask consumers to the **lease over the switch** instead of host
loopback. The daemon is on the switch (`100.64.255.253`) and can reach
`lease:<internal>` (verified: 200).

1. **Lease-on-sandbox, published — not persisted on the session.** The lease is
   *ephemeral runtime state of the live PTask*: allocated at own-ip attach
   (`gvproxy_network.rs:130`), valid only while the sandbox runs. Its
   authoritative home is `OwnIpGuard` — the per-PTask net guard whose
   `teardown()` already detaches the switch and removes ingress forwards — so add
   a `lease: Ipv4Addr` field there (it is already in scope at construction,
   `lease.ip`). **Do not** put it on the on-disk `Record`
   (`crates/sessions/src/lib.rs`): that is declarative config that outlives every
   attach/detach and survives daemon restarts, so a lease stored there goes stale.
   Instead **publish** the lease into the shared `HostnameRegistry` for the
   sandbox's lifetime:
   - at `finish_own_ip_attach`, set the session's hostname to resolve →
     `lease_ip` (replacing the `LOOPBACK` placeholder `register_own_ip` writes at
     `dns.rs:153`); thread the shared `Arc<RwLock<HostnameRegistry>>` (already
     cloned into `Router`, `server.rs:464`) into the attach path;
   - at `OwnIpGuard::teardown`, revert the entry (mark down / back to loopback),
     beside the existing `remove_ingress`.

   The registry becomes a live view keyed by session but owned by the sandbox —
   present exactly while the PTask runs.
2. **`direct-tcpip`** (`crates/minimald/src/connection.rs`): dial
   `lease:<internal_port>` (the client already supplies the internal port),
   reading the lease from the live routing state above. This revises the interim
   Part 1 change, which resolves to `127.0.0.1:<external>`.
3. **`:7654`/`:7655` proxies** (`crates/minimald/src/net/dns.rs`,
   `net/proxy.rs`): already read the registry — with the published lease they
   resolve `<name>…:<external>` → `lease:<internal>` (router maps external→internal
   via the session's `IngressPolicy`).
4. **Keep the gvproxy forwarder** for pure host-direct access (TC4). It is not
   removed — only the in-VM consumers stop depending on it.

### DM2 caveat — RESOLVED (verified on Linux 2026-07-07)

On DM2 (native, rootless hakoniwa/RustSlirp) gvproxy runs in the **daemon's**
netns, so `127.0.0.1:<external>` is correct there. A `DM=dm2` run with a valid
file-served backend confirmed the shared-netns forwarder works end-to-end
(**TC3/TC4/TC7-cert/TC8 = 200/200/200/200**, no-cert = 401), so the resolver is
**transport-aware** rather than unified:

- **VM DMs (DM1/DM3/DM4):** publish the lease; consumers dial `lease:<internal>`
  over the switch.
- **DM2 (native):** keep `127.0.0.1:<external>` (shared-netns forwarder) — the
  loopback placeholder is left untouched, so DM2's verified behaviour is
  unchanged.

The transport is discriminated by the switch control channel already in hand at
attach: `ControlChannel::Vsock` (VM) publishes the lease; `ControlChannel::Unix`
(DM2) does not.

## Interim Part 1 change — now completed by the lease routing

`crates/minimald/src/connection.rs` `channel_open_direct_tcpip` had earlier been
changed to stop connecting to the raw client target in the daemon netns and
instead resolve the session's ingress mapping (`published_external_port`) and dial
`127.0.0.1:<external>`. That removed the arbitrary-connect behavior and added
session-scoped validation (unit-tested), but it targeted host loopback — wrong for
the VM path. The 2026-07-07 change keeps the published-mapping validation and, on
the VM path, dials `lease:<internal>` instead (falling back to
`127.0.0.1:<external>` on DM2 / when no live lease is published) — completing
step 2.

## Implementation (2026-07-07)

Landed on branch `networking-test-plan-all-dms`. The lease is **ephemeral
runtime state of the live sandbox**, published into the shared routing table for
exactly the sandbox's lifetime and **never** persisted to the on-disk `Record`.

- **`net/dns.rs`** — the hostname registry entry is now a
  `Route { target, port_map }`. `set_own_ip_lease(session_id, lease, port_map)`
  publishes a live lease + its TCP external→internal ingress map;
  `clear_own_ip_lease(session_id)` reverts to the loopback placeholder;
  `route_for_session(session_id)` reads it (keyed by stable id, rename-safe).
- **`net/proxy.rs`** — `Router::route` remaps the authority's published external
  port to the PTask-internal port via `Route::dial_port`, so the `:7654`/`:7655`
  proxies dial `lease:<internal>`.
- **`net/gvproxy_network.rs`** — `OwnIpGuard` owns the ephemeral `lease`;
  `finish_own_ip_attach` publishes it **only on `ControlChannel::Vsock` (VM)**,
  and teardown reverts it **before** the switch detach. DM2 (`Unix`) is untouched.
- **`connection.rs`** — `direct-tcpip` dials the lease on the VM path (see above).
- Threading: the manager's `hostnames` registry is made unconditional and passed
  through `Session` → `SandboxLauncher` → the attach tail with the `session_id`.

**Verification.** `cargo test -p minimald --features networking-proxy,networking-wg`
→ 103 passed (incl. `own_ip_lease_is_published_only_between_attach_and_teardown`
and `own_ip_lease_routes_to_switch_lease_with_internal_port`); `fmt` + `clippy
-D warnings` clean; **DM2 regression re-run all-PASS** (TC3/4/7/8 = 200/200/200
+401/200), proving no native-path regression. The in-VM lease branch was
initially covered by unit tests only, because **DM3/DM4 were blocked by G-N8** —
now pinned and fixed (below), so the VM lease path is **runtime-verified**.

## G-N8 pinned + fixed (2026-07-08) — vsock forwarder response drop

The G-N8 "attach hang" that blocked DM3/DM4 verification of this lease path was
**not a hang**. On a live DM3 (KVM) run the own-ip + `--ingress` attach *failed
fast* (~8 s, client `network attach failed: malformed gvproxy status line: ""`);
the ">200 s" was only the suite's `hold_wait` ceiling (`session_hold` backgrounds
`attach` and greps for `SERVER_UP` only, never the exit code, so a fast failure
is indistinguishable from a hang).

**Root cause (confirmed by the host forwarder table).** gvproxy's forwarder HTTP
verbs — `POST /services/forwarder/expose` (ingress) and the `:7654`/`:7655`
proxy-publish — do **not** round-trip over the **KVM** libkrun
`add_vsock_port2(listen=false)` shuttle. The request reaches gvproxy and **is
applied** — during a failed attach, `GET /services/forwarder/all` on the host
`gvproxy-switch.sock` showed the expose (`127.0.0.1:18080 → 100.64.0.x:8080`) plus
both proxy publishes — but gvproxy's `Connection: close` response is dropped as
the splice propagates the peer close, so the guest's `read_to_end` returns 0
bytes. `apply_ingress` then reads a *successful* expose as a failure and rolls the
own-ip attach back, so the shell never starts. Only the `/connect` L2 relay
(an HTTP *upgrade*, not request/response) survives the splice — which is why
egress works but every forwarder verb fails. DM1/HVF is unaffected (HVF delivers
the response), and DM2 (native unix socket, no splice) was never affected.

**Fix** (`crates/minimald/src/net/policy.rs`): `post_json` sends HTTP/1.1
keep-alive (drops `Connection: close`) and `exchange` frames the reply by
`Content-Length` instead of read-to-EOF, so gvproxy never closes the socket first
and the response drains to the guest, which closes from its own side. This is a
superset fix — it also repairs the in-VM `:7654`/`:7655` proxy-publish (same leg).

**Verified live on DM3 (KVM), 2026-07-08:** own-ip + `--ingress` attach starts the
shell and publishes the lease; **TC3/TC4/TC7/TC8 = 200/200/(401+200)/200** (full
`DM=dm3` suite); startup proxy-publish `malformed` warnings gone. TC8=200 in
particular exercises `direct-tcpip → lease:8080`, so this run is also the
end-to-end runtime confirmation of the G-N9 lease routing on the VM path.
`fmt`/`clippy -D warnings`/`cargo test -p minimald` clean, with a regression test
(`exchange_frames_by_content_length_without_a_server_close`) that hangs if the
framing ever reverts to read-to-EOF.
