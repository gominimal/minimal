---
id: spec-networking-gaps
title: "networking test plan: gaps G-N1–G-N7 and host→PTask forward defect"
kind: spec
status: planned
tracking-issue: 626
supersedes:
---

# networking test plan: gaps G-N1–G-N7 and host→PTask forward defect

## Context

The networking epic (`docs/specs/03-spec-networking/03-spec-networking.md`, tracking-issue #478)
specified five deployment models (DM1–DM5) and seven use cases (UC1–UC7). The accompanying test
plan (`docs/specs/03-spec-networking/test-plan.md`) extended DM×TC coverage to all five models in
PR #625 and registered eight blockers — G-N1 through G-N7 plus one driver-independent defect —
that prevent full coverage. Sub-issues #627 onward enumerate each blocker with evidence and
acceptance criteria. This spec closes them.

Current codebase baselines (informed by #478, #553, #581, #625):

- **G-N1** (`crates/minimald/src/net/proxy.rs:31–39`): `EGRESS_PROXY_PORT = 7654` and
  `HTTPS_PROXY_PORT = 7655` are compile-time constants used as fixed bind addresses. A DM4 host
  runs two `minimald` instances (native + VM-re-published); whichever daemon loses the bind race
  silently loses its `*.min.internal` proxy surface. Blocks TC15 and TC3/TC7 on DM4.
- **G-N2**: `minimald` listens only on a Unix domain socket. No TCP listener or `--server` flag
  exists. DM5 (network-accessible, authenticated control plane) is entirely blocked: TC16 and all
  DM5 matrix cells cannot be executed.
- **G-N3**: `vm_egress` is defined in the networking spec (R2.5) but has no runtime config
  surface in `minvmd`. The VM-wide egress enforcement path (`crates/minimald/src/net/policy.rs`)
  exists, but `minvmd` carries no `vm_egress` field and makes no gvproxy ACL call at VM-start.
  Blocks TC12 (UC5/R2.5). Egress enforcement at the relay/frame layer is pending #553.
- **G-N4** (`crates/minimald/src/net/policy.rs`): Per-PTask egress (`sessions::EgressPolicy`) is
  defined and the `apply_egress` path exists, but the session-launch code unconditionally passes
  `None`. No CLI flag or spec field propagates a user-supplied egress section. Blocks TC13
  (UC3/R2.1–R2.2). Egress enforcement also pending #553.
- **G-N5**: The dynamic port-map RPC (spec R2.4) has no daemon handler. `policy::apply_ingress`
  covers static mappings at launch; a runtime call site wiring the RPC to `apply_ingress` is
  absent. Blocks TC14 (R2.4).
- **G-N6** (`crates/minimald/src/net/wg.rs`): The `boringtun` data plane is fully implemented and
  unit-tested, but `minimald` never calls `wg::start` at startup and `minimal mesh join` does not
  propagate enrolment to the running daemon. Blocks TC17 (UC7/R4.1–R4.3).
- **G-N7** (`crates/minvmd/src/state.rs`, `vmm_pid: Option<u32>`): `minvmd` tracks a single VM
  process. The spec says "one or more." Multi-VM DM1/DM3 scenarios cannot be exercised.
- **defect** (driver-independent): host→PTask published-port forwarding sends TCP RST when a live
  backend is present inside the PTask. The `apply_ingress` forwarder registration path exists;
  the defect is a sequencing issue between lease assignment and forwarder registration. Blocks
  TC3, TC4, TC7, TC8 green on DM1.

## Introduction/Overview

Eight blockers are closed in five demoable units:

1. **Unit 1** — Proxy port configurability and host→PTask forward defect (G-N1 + defect).
2. **Unit 2** — Network-accessible control plane, `minimald --server` (G-N2).
3. **Unit 3** — Egress/ingress policy completion and dynamic port-map handler (G-N3, G-N4, G-N5).
4. **Unit 4** — WireGuard mesh enrolment daemon-side wiring (G-N6).
5. **Unit 5** — Multi-VM supervision in `minvmd` (G-N7).

Units 1 and 2 are independent foundations; Unit 3 depends on Unit 1 (the defect fix must be in
place before policy round-trip tests are reliable). Units 4 and 5 are independent of each other
and of Units 1–3.

## Goals

1. All eight blocked test-plan cells pass: TC15, TC3/TC7 on DM4 (G-N1 + defect), TC16 (G-N2),
   TC12 (G-N3), TC13 (G-N4), TC14 (G-N5), TC17 (G-N6), multi-VM DM1/DM3 (G-N7).
2. Two `minimald` instances on the same DM4 host each serve a working `*.min.internal` proxy
   surface without port conflict.
3. `minimald` is reachable over a network-authenticated TCP connection (DM5).
4. `vm_egress`, per-PTask egress, and dynamic port-map RPCs are wired end-to-end.
5. `minimal mesh join` wires the WireGuard data plane into the running daemon.
6. `minvmd` manages a named fleet of VMs concurrently.

## User Stories

- As a Developer on DM4, I run two `minimald` instances; each resolves `*.min.internal` hostnames
  through its own proxy without conflict.
- As a SecOps/SRE on DM5, I connect `minimal` to a `minimald` daemon over an authenticated TCP
  connection from a remote host.
- As a Developer, I declare `egress: {allow_subnets: ["10.0.0.0/8"]}` in a PTask spec; traffic
  to other subnets is dropped at the switch (pending #553 for relay enforcement).
- As a Developer, I call the dynamic port-map RPC from inside a PTask and a new host-side port
  opens immediately.
- As a Developer, I run `minimal mesh join` and the running daemon immediately enrols as a
  WireGuard subnet-router peer.
- As an Operator, I provision a `minvmd` host with three VM configs; all three VMs run
  concurrently and are independently managed.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1; R2.1 for Unit 2; etc.).
> Do not renumber after approval.

---

### Unit 1: Proxy port configurability and host→PTask forward defect (G-N1 + defect)

**Purpose:** Eliminate the hardcoded `7654`/`7655` proxy ports so two `minimald` instances on the
same DM4 host each retain a working proxy surface (G-N1). Simultaneously fix the TCP RST defect
that blocks TC3, TC4, TC7, and TC8 even on a single-daemon host (defect).

**Depends on:** None (foundation for Unit 3)

**Affected areas:** `crates/minimald/src/net/proxy.rs` (port constants → configurable),
`crates/minimald/src/main.rs` / startup config (env/flag wiring), `crates/minimald/src/` session
launch sequence (lease-before-forwarder serialisation for the defect)

**Functional Requirements:**

- **R1.1**: `EGRESS_PROXY_PORT` and `HTTPS_PROXY_PORT` shall no longer be fixed bind addresses.
  `minimald` shall accept `--egress-proxy-port <port>` and `--https-proxy-port <port>` CLI flags
  (and equivalent env vars `MINIMALD_EGRESS_PROXY_PORT` / `MINIMALD_HTTPS_PROXY_PORT`). Default
  is `7654`/`7655` when no override is supplied, preserving backwards compatibility for single-daemon
  hosts.
- **R1.2**: When a port is already in use at startup, `minimald` shall log a `tracing::error!`
  with `component = "dns-proxy"` identifying the conflicting port and either select an OS-assigned
  alternative port (auto-select) or fail the proxy subsystem with a logged remedy. The silent
  warn-only best-effort bind of `proxy.rs:154–172` shall be replaced; a failed proxy bind is
  always observable.
- **R1.3**: `minimald` shall expose the actual bound egress-proxy and HTTPS-proxy ports in its
  status or info RPC so a second daemon on the same host can discover the effective port without
  guessing.
- **R1.4**: The host→PTask published-port forward shall complete a full TCP connection (no RST)
  when a live backend is present inside the PTask. The session launch sequence shall serialise the
  gvproxy DHCP lease assignment before the ingress-forwarder `expose` call, so the forwarder
  target address is a live, reachable lease from the moment the mapping is registered.

  *Baseline:* `policy::apply_ingress` already calls the gvproxy `expose` API; the defect is that
  the expose call is issued before the PTask's DHCP lease is confirmed, so the forwarder initially
  points at an address the switch does not yet know. Open Question 1 tracks the exact mechanism.

**Proof Artifacts:**

1. **Test:** Integration test starts an `OwnIp` PTask with a static ingress mapping, waits for the
   PTask's shell to be ready (confirming DHCP lease is assigned), starts a `socat` HTTP listener
   inside, detaches, then `curl`s the host-side published port from outside the PTask and asserts
   HTTP 200 — demonstrates the defect is fixed (R1.4) without a DM4 co-residency requirement.
2. **CLI:** `minimald --egress-proxy-port 17654 --https-proxy-port 17655` starts and a subsequent
   `minimal session info` (or status RPC query) reports `egress_proxy_port: 17654` —
   demonstrates R1.1 port override and R1.3 port reporting.

---

### Unit 2: Network-accessible control plane, `minimald --server` (G-N2)

**Purpose:** Give `minimald` a network-accessible, authenticated listener (DM5), unblocking TC16
and all DM5 matrix cells.

**Depends on:** None (independent)

**Affected areas:** `crates/minimald/src/server.rs` (new TCP listener path), startup flag parsing,
mTLS credential setup (reusing `proxy::CertAuthority`)

**Functional Requirements:**

- **R2.1**: `minimald` shall accept a `--server <addr:port>` CLI flag (or equivalent config key)
  that enables a TCP listener in addition to the default UDS. Without the flag, `minimald` is
  UDS-only (no behaviour change to existing deployments).
- **R2.2**: The TCP listener shall require mutual TLS (mTLS) using the same `CertAuthority`
  already managing the daemon's internal CA. A client presents the cert issued by `minimal login`;
  a connection without a valid CA-signed client certificate is rejected at the TLS layer, never
  reaching any RPC handler. No daemon state or session data is disclosed to an unauthenticated
  caller.
- **R2.3**: All existing RPC handlers (session management, mesh, policy, port-map, etc.) shall be
  available over the TCP listener identically to the UDS; no RPC is UDS-only.
- **R2.4**: `minimald` in `--server` mode shall report the bound network address in its status RPC
  so `minimal` can discover a network-accessible daemon.

**Proof Artifacts:**

1. **CLI:** `minimald --server 127.0.0.1:17900` starts; a second process runs
   `minimal --server 127.0.0.1:17900 session list` over TCP/mTLS and the session list is
   returned — demonstrates DM5 network RPC (TC16 scenario, loopback standing in for a remote host).
2. **Test:** Integration test connects to the `--server` listener without a client certificate and
   asserts the connection is rejected at the TLS layer (no RPC response received) —
   demonstrates R2.2 auth enforcement.

---

### Unit 3: Egress/ingress policy completion and dynamic port-map handler (G-N3, G-N4, G-N5)

**Purpose:** Wire the three missing policy paths so TC12, TC13, and TC14 activate:
`vm_egress` runtime config surface in `minvmd` (G-N3), per-PTask egress spec/CLI surface (G-N4),
and the dynamic port-map RPC daemon handler (G-N5).

**Depends on:** Unit 1 (R1.4 defect fix stabilises host→PTask forwarding, making policy
round-trip tests reliable with live backends)

**Affected areas:** `crates/minvmd/src/` (vm_egress config field), `crates/minimald/src/`
session-launch path (egress wiring), `crates/minimald/src/net/policy.rs` (dynamic handler call
site), `crates/minimald-rpc/` (dynamic port-map RPC definition if not already present),
`crates/sessions/` (EgressPolicy population)

**Functional Requirements:**

- **R3.1**: `minvmd` shall accept a `vm_egress` field in its VM configuration (config file or a
  `minvmd run --vm-egress` flag). When present, `minvmd` shall call the gvproxy ACL API at
  VM-start to apply VM-wide egress rules to all traffic from the VM's gvproxy switch port. Absent
  `vm_egress` leaves VM egress unrestricted. On DM2, specifying `vm_egress` shall produce a
  typed configuration error with a clear message (per R2.5 of spec-networking).

  *Note:* Actual enforcement at the relay/frame-inspection layer is pending #553. This requirement
  wires the config surface and the gvproxy ACL API call; the enforcement itself is a follow-up.

- **R3.2**: A PTask spec's `egress` section shall be propagated from the launch request through
  the session-launch path to the gvproxy ACL API call, not discarded as `None`. The
  `sessions::EgressPolicy` struct shall be populated from the request and passed to the existing
  (or new) `apply_egress` call site in `minimald`.

  *Baseline:* `sessions::IngressPolicy` is wired at launch; `EgressPolicy` is defined but the
  session launch path unconditionally passes `None`. R3.2 closes that skip.

  *Note:* Same enforcement caveat as R3.1 — relay-layer enforcement is pending #553.

- **R3.3**: The dynamic port-map RPC handler shall be added to `minimald`. The handler shall:
  (a) look up the session's `dynamic_allowed_ports` range; (b) reject a requested port outside
  that range with a typed `DynamicPortOutOfRange` error (never panic); (c) call the gvproxy
  expose API via `policy::apply_ingress` to register the new mapping; (d) emit a
  `tracing::info!` with structured fields `session_id`, `external_port`, `internal_port`, `proto`.

  *Baseline:* `policy::apply_ingress` for static mappings is implemented; R3.3 adds a runtime
  call site for the RPC path.

**Proof Artifacts:**

1. **Test:** Integration test launches a `minvmd`-managed VM with
   `vm_egress: {allow_subnets: ["10.0.0.0/8"]}`, starts an `OwnIp` PTask inside it, and asserts
   that the `session policy <id>` response contains `allow_subnets: ["10.0.0.0/8"]` for the VM
   egress — demonstrates G-N3 vm_egress config surface end-to-end (UC5/R2.5, TC12 policy
   round-trip). Marked `#[ignore]`; gated on `/dev/kvm`.
2. **CLI:** `minimal session policy <id>` on a PTask launched with an egress spec returns JSON with
   `allow_subnets` and `allow_protocols` fields non-empty — demonstrates G-N4 per-PTask egress
   surface wired end-to-end (TC13 policy round-trip).
3. **CLI:** The dynamic port-map RPC is called for a session whose `dynamic_allowed_ports`
   includes port 19000; `minimal session policy <id>` then lists port 19000 in the ingress
   mappings — demonstrates G-N5 dynamic port-map handler (TC14).

---

### Unit 4: WireGuard mesh enrolment daemon-side wiring (G-N6)

**Purpose:** Wire the `boringtun` data plane (fully implemented in
`crates/minimald/src/net/wg.rs`) into `minimald`'s startup and the `minimal mesh join` command,
so TC17 and UC7 pass end-to-end (informed by #478 R4.1–R4.3).

**Depends on:** None (independent)

**Affected areas:** `crates/minimald/src/main.rs` / startup (wg::start call site),
`crates/minimald/src/net/wg.rs` (tunnel_sink wiring), `crates/minimald-rpc/` (JoinMeshPeer RPC
if not present), `crates/minimal/src/` (mesh join command sends RPC)

**Functional Requirements:**

- **R4.1**: At startup, when a mesh config file exists at the configured path
  (`--mesh-config <path>` or equivalent), `minimald` shall call `wg::start` with the loaded
  `MeshConfig` and keep the resulting `MeshHandle` alive for the daemon lifetime. An absent or
  missing config leaves mesh unconfigured (no-op; existing behaviour).

  *Baseline:* `wg::start`, `MeshConfig`, and `MeshHandle` are fully implemented and unit-tested;
  the missing piece is a startup call site that reads the config and invokes `start`.

- **R4.2**: `minimald` shall wire the `MeshHandle`'s tunnel sink (decrypted inbound IP packets
  from WireGuard peers) into the gvproxy switch, completing the remote PTask → mesh tunnel →
  local switch path (UC7/R4.2 of spec-networking). The exact injection mechanism (raw IPv4 vs
  Ethernet framing) is governed by Open Question 2.

- **R4.3**: `minimal mesh join <address> [--peer-key <base64>]` shall send a `JoinMeshPeer` RPC
  to the running daemon that adds the new peer to the live `MeshHandle` and persists the updated
  config so the peer survives a restart. If the daemon is not yet in mesh mode, the RPC shall
  start it with a new `MeshConfig` derived from the request.

**Proof Artifacts:**

1. **Test:** Integration test starts two `minimald` instances, each with a mesh config pointing at
   the other's loopback UDP port (using `wg::start_with_socket` as in the existing
   `two_meshes_handshake_and_relay_a_packet` unit test for the WireGuard layer), asserts that a
   TCP connection from a PTask on instance A to a PTask on instance B via switch IPs succeeds —
   demonstrates UC7 end-to-end (TC17 scenario). Marked `#[ignore]`; gated on
   `MINIMALD_INTEGRATION_MESH` env var.
2. **CLI:** `minimal mesh status` on a daemon started with a mesh config reports
   `configured: true` and the peer list — demonstrates R4.1 startup enrolment.

---

### Unit 5: Multi-VM supervision in `minvmd` (G-N7)

**Purpose:** Extend `minvmd` to supervise a named fleet of VMs concurrently, matching the
spec-networking claim of "one or more" VMs per `minvmd` host (DM1, DM3).

**Depends on:** None (independent)

**Affected areas:** `crates/minvmd/src/state.rs` (fleet map replacing `vmm_pid: Option<u32>`),
`crates/minvmd/src/lifecycle.rs` (per-VM locks), `crates/minvmd/src/vm.rs`,
`crates/minvmd/src/cmd/` (run/stop/status accept `--name`)

**Functional Requirements:**

- **R5.1**: `minvmd`'s persistent state shall be refactored from a single `vmm_pid: Option<u32>`
  to a map `<vm-name> → VmState { lifecycle, vmm_pid, started_at }`. On startup, `minvmd` shall
  detect the legacy single-entry format and migrate it to a singleton `"default"` VM entry, logging
  the migration. The migration is idempotent.
- **R5.2**: The per-VM lifecycle state machine (`lifecycle::next_state`) is pure-functional and
  applies per VM without change. The daemon's lifecycle lock shall be widened to a per-VM lock
  keyed by name so concurrent `minvmd start`/`stop` commands on different VMs do not block each
  other.
- **R5.3**: `minvmd run <config> [--name <name>]`, `minvmd stop [--name <name>]`, and
  `minvmd status [--name <name>]` shall accept an optional VM name. Without `--name`, commands
  operate on `"default"` for backward compatibility. `minvmd status` with no name lists all
  supervised VMs with their individual lifecycle state.
- **R5.4**: When a `minimald` guest inside a VM issues a vsock control-socket call to `minvmd`,
  the dispatch shall route the call to the correct per-VM context (its gvproxy instance, its
  egress policy) identified by the calling vsock CID. Open Question 3 tracks CID stability.

**Proof Artifacts:**

1. **Test:** Integration test (`crates/minvmd/tests/`) starts two VMs under different names,
   asserts both appear in `minvmd status` with `lifecycle: Running`, stops one by name, asserts the
   other remains `Running`. Marked `#[ignore]`; gated on `/dev/kvm`.
2. **CLI:** `minvmd run first.toml --name vm-a && minvmd run second.toml --name vm-b &&
   minvmd status` lists both `vm-a` and `vm-b` with their lifecycle states — demonstrates R5.3
   named-fleet CLI.

---

## Non-Goals

- Full DM5 production deployment: hardened ACME certificate management for the `--server` listener
  is deferred (spec-networking Open Question 5).
- Automated WireGuard peer key distribution: v1 manual config is the floor per R4.1 of
  spec-networking; peer discovery is a follow-up.
- Relay-layer egress frame inspection: enforcement at the switch/relay level is pending #553;
  Units 3 wires the config surface and gvproxy ACL API calls only.
- IPv6 within the gvproxy switch (spec-networking non-goal).
- Multi-tenant `minimald` policy isolation (spec-networking non-goal).
- macOS native (no-VM) PTask networking (spec-networking non-goal).

## Design Considerations

### Proxy port configurability: explicit flags over auto-select (Unit 1)

R1.1 adds explicit `--egress-proxy-port` / `MINIMALD_EGRESS_PROXY_PORT` overrides. R1.2 adds
auto-select as a recovery path, not the operational default, because a stable predictable port is
required for `HTTP(S)_PROXY` environment variable configuration. Auto-select produces an OS-assigned
ephemeral port that changes each restart, breaking any client that hard-codes the address; the
status-RPC port reporting (R1.3) is necessary but not sufficient for all clients.

### DM5 auth reuses `CertAuthority` (Unit 2)

`CertAuthority` in `proxy.rs` already manages the daemon's internal CA. The `--server` TCP
listener (Unit 2) reuses the same CA so `minimal login` issues one cert covering both the HTTPS
proxy (port 7655) and the network control plane, avoiding a second credential management surface.

### Egress enforcement boundary (Units 3)

R3.1 and R3.2 wire the config surface and the gvproxy ACL API call path. Actual enforcement (frame
inspection that drops non-matching traffic) is in `#553`'s relay layer and is not in scope here.
Implementation PRs for Unit 3 must document this boundary so reviewers do not conflate "wired" with
"enforced."

### Multi-VM state migration (Unit 5)

The R5.1 migration from a single `vmm_pid` to a per-VM map is a one-time upgrade at `minvmd`
startup. The migrated singleton uses key `"default"` so existing `minvmd run` invocations without
`--name` continue to work. The migration must be idempotent and logged so operators observing log
output understand the upgrade.

## Repository Standards

- Workspace conventions from `CLAUDE.md`: workspace-pinned deps; `cargo fmt && cargo test --
  --include-ignored`; `cargo clippy --allow-dirty --fix --all-targets -- -D warnings`; no
  `println!`/`eprintln!` in library or daemon code; structured `tracing` fields.
- Commit messages: Conventional Commits per `docs/commit-conventions.md`; imperative mood, lower-case,
  no trailing period; scopes `fix(minimald):`, `feat(minimald):`, `feat(minvmd):`, `feat(minimal):`.
- Rust coding standards per `docs/rust-coding-standards.md`: typed errors via `thiserror` in
  library crates; `anyhow` at CLI/RPC boundaries; `#[non_exhaustive]` on public enums/structs;
  `#[must_use]` on Result-shaped returns; `#[ignore]` + env-var gate on hardware-requiring tests.
- New external dependencies must be workspace-pinned and vetted against `blessed.rs` or the
  existing workspace.

## Open Questions

1. **R1.4 RST defect root cause** (proxy.rs / switch.rs / session launch): Is the TCP RST caused
   by the forwarder registering before the PTask's DHCP lease is confirmed by gvproxy (sequencing
   bug in session launch), or by the forwarder target being the switch-IP before the switch assigns
   it (address-lookup bug)? The fix differs: sequencing → add a lease-wait after PTask network
   namespace setup; address-lookup → resolve the target lazily at first connection. Needs
   investigation before Unit 1 implementation begins.
2. **R4.2 switch injection framing** (wg.rs ↔ switch.rs / gvproxy): The `tunnel_sink` channel
   delivers raw decrypted IPv4 packets. Does gvproxy's L2 switch accept raw IPv4 injected via the
   existing `POST /connect` relay path, or does it require Ethernet framing (EtherType 0x0800
   header prepended)? The `switch.rs` relay already shuttles raw L2 frames; the exact framing
   gvproxy expects for an injected inbound packet must be confirmed against gvproxy v0.8.9's
   source before Unit 4 implementation.
3. **R5.4 vsock CID stability** (minvmd / libkrun): The vsock CID is assigned by the KVM
   hypervisor at VM creation time. Is the CID stable across VM lifecycle events (stop/start of the
   same VM), or is it ephemeral (new CID each boot)? If ephemeral, the `minvmd` dispatch cannot
   rely on CID alone and needs a secondary lookup (e.g. `vm-name → CID` table maintained at boot
   via a registration handshake from the VM guest). Needs investigation before Unit 5 R5.4 is
   implemented.

## Technical Considerations

- **R1.1 port propagation:** The effective egress-proxy port must be communicated to clients that
  auto-configure `HTTP_PROXY`. The status RPC (R1.3) is the right channel; the CLI should read it
  rather than assuming 7654, especially in DM4 where each instance picks a different port.
- **R3.1 gvproxy egress ACL API:** The gvproxy v0.8.9 spike
  (`docs/spikes/2026-06-21-gvproxy-attachment.md §5`) established that there is no per-client
  egress ACL in gvproxy's management API. R3.1 and R3.2 therefore call whatever partial ACL surface
  exists today; the enforcement is a #553 follow-up. Confirm the latest gvproxy API surface before
  Unit 3 implementation begins.
- **R5.1 state file:** The migration must be backward-compatible on any existing `minvmd`
  deployment. The state file path should remain at `$XDG_STATE_HOME/minimal/minvmd/state.toml`;
  a version field in the TOML is the standard migration discriminator.
- **Async safety:** All network operations use `tokio`; no blocking I/O in async contexts.

## Security Considerations

- **R2.2 mTLS rejection:** The TCP listener drops unauthenticated connections at the TLS layer
  before any RPC handler executes. An invalid or absent client certificate must not elicit any
  daemon state, session data, or topology information.
- **R1.2 auto-select port:** An OS-assigned port changes on restart. Any client that hard-codes
  7654 breaks in auto-select mode. The status RPC (R1.3) is the correct discovery channel.
- **R4.3 mesh config persistence:** The config file written by `minimal mesh join` must be
  mode 0600 (owner-only). Peer public keys and endpoint addresses in the config are sensitive.
- **R3.3 dynamic port-map validation:** The `DynamicPortOutOfRange` typed error must be returned
  for any port outside the configured range; the handler must never panic or return an untyped
  error that exposes a stack trace to the caller.

## Verification

| Check | Command |
|---|---|
| Lint | `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` |
| Build | `cargo build -p minimald -p minvmd -p minimal` |
| Unit + integration | `cargo test -p minimald -p minvmd -p minimal` |
| Full (hardware) | `cargo test -- --include-ignored` (requires `/dev/kvm`) |
