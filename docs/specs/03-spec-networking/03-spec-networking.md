---
id: spec-networking
title: "minimald networking — PTask network modes, DNS, egress/ingress, WireGuard mesh"
kind: spec
status: planned
tracking-issue: 478
supersedes:
---

# minimald networking — PTask network modes, DNS, egress/ingress, WireGuard mesh

## Context

`minimald` manages PTasks (isolated sandboxed environments) on Linux. The
underlying isolation uses Linux user namespaces and network namespaces
(`sandbox2` crate), but PTasks currently have no configurable network
connectivity: they inherit the host network namespace. Issue #404 explored
gvproxy outbound transport for VM sessions; this spec extends and supersedes
that scope to deliver the full networking stack across all five deployment
models (informed by #404).

The implementation analysis in
`docs/specs/03-spec-networking/networking-with-diagrams.md` selects the
building blocks: **one gvproxy per host** (gvisor-tap-vsock) serving all
PTasks as switch clients, **libkrun** VMs (Hypervisor.framework on macOS,
KVM on Linux), **wireguard-go** (Tailscale userspace netstack) for the
authenticated remote mesh, and an **HTTPS reverse proxy on minimald** for
UC2b option B remote browser access. No root privilege is required per-invocation
on any path covered by this spec.

The five deployment models (DM1–DM5) from the requirements document are:

- **DM1** — macOS + one or more libkrun Linux VMs, each with `minimald`
- **DM2** — native Linux, `minimald` on the host directly
- **DM3** — native Linux + one or more Linux VMs, each with `minimald`
- **DM4** — DM2 + DM3 combined
- **DM5** — any of the above with a network-accessible, authenticated `minimald`

## Introduction/Overview

The networking stack delivers seven use cases:

- **UC1** — PTask network isolation modes: no-net, host-net, or own-IP.
- **UC2** — DNS hostnames for PTasks and network-accessible `minimald`
  instances; local (UC2a) and remote (UC2b) browser access by hostname.
- **UC3** — Per-PTask egress policy: subnet/DNS allowlists for own-IP PTasks.
- **UC4** — Ingress port mapping for own-IP PTasks (static + dynamic); default
  deny-external.
- **UC5** — VM-wide egress controls (DM1, DM3, DM4); collapses to UC3 on DM2.
- **UC6** — Local PTask-to-PTask: TCP/UDP between PTasks on the same host.
- **UC7 + UC2b** — WireGuard mesh for authenticated remote PTask-to-PTask and
  laptop-to-PTask access; HTTPS reverse proxy for no-client remote browser.

The shared infrastructure is **one gvproxy process per host**. On native Linux
(DM2) it runs as a host process alongside `minimald`. On macOS (DM1, libkrun VM
path), it runs on the macOS side; PTasks inside the VM connect via vsock.
Each own-IP PTask attaches as a switch client: over a unix socket on native
Linux, over vsock through the libkrun VM on macOS.

## Goals

1. A PTask can be launched in no-net, host-net, or own-IP mode as declared in
   its specification; the mode is enforced at session launch on all five DMs.
2. Own-IP PTasks on the same host reach each other by TCP/UDP via the shared
   gvproxy switch without transiting the host network stack (UC6).
3. Per-PTask egress policy (subnet/DNS allowlists, protocol filter) is enforced
   for own-IP PTasks; VM-wide egress is enforced for DM1/DM3/DM4.
4. Static and dynamic ingress port mappings are configurable per PTask spec;
   the default for own-IP PTasks is deny-all-external.
5. DNS hostnames resolve for own-IP and host-net PTask services, and
   network-accessible `minimald` instances; a browser can reach a PTask
   webserver by hostname without memorizing an IP (UC2a).
6. A wireguard-go mesh enables authenticated remote PTask-to-PTask and
   laptop-to-PTask access (UC7 + UC2b option A).
7. An HTTPS reverse proxy on `minimald` (mTLS/OIDC) enables ad-hoc remote
   browser access without a mesh client (UC2b option B).
8. All of the above require no root privilege per-invocation.
9. SSH port-forwarding over `minimald`'s existing SSH transport provides a
   fallback remote-access path for restricted networks where WireGuard is
   blocked.

## User Stories

- As a Developer, I declare `network: none`, `network: host`, or
  `network: own-ip` in a PTask spec and the mode is enforced at launch.
- As a Developer, I open `http://my-service.ptask.local` in a browser on the
  same host and reach a webserver running inside an own-IP PTask (UC2a).
- As a Developer, I configure an egress allowlist for an own-IP PTask and
  connections to disallowed subnets are blocked at the switch level (UC3).
- As a Developer, I declare a static ingress port mapping in a PTask spec and
  a process on the host can connect to that port (UC4 static mapping).
- As a SecOps/SRE, I configure VM-wide egress rules that apply to all PTasks
  in a VM, including host-net PTasks (UC5, DM1/DM3/DM4).
- As a Developer, I run `minimal mesh join` on my laptop and can then reach
  PTasks on a remote server by hostname via the WireGuard mesh (UC2b option A).
- As a Developer, I share a URL with a teammate who opens it in a browser;
  `minimald`'s HTTPS reverse proxy authenticates and routes the request without
  any client install on the teammate's machine (UC2b option B).
- As a Developer, I open `http://my-service.ptask.local` in a browser on the
  same host and reach a webserver running inside a `HostNet` PTask (the hostname
  resolves to the host's loopback address).
- As a Developer on a network where WireGuard is blocked, I run
  `minimal ssh-forward <session> 8080:127.0.0.1:80` and a local port tunnels
  over SSH to a service inside a remote PTask (SSH fallback for UC2b).

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2, etc.). Do not renumber after approval.

---

### Unit 1: gvproxy switch and PTask network modes (UC1, UC6)

**Purpose:** Establish the gvproxy-per-host infrastructure and implement the
three PTask network isolation modes. Own-IP PTasks attach to the shared switch;
UC6 (same-host PTask-to-PTask) is automatic once both PTasks are on the switch.

**Depends on:** None (foundation)

**Affected areas:** `crates/minvmd/` (gvproxy child lifecycle, vsock switch
wiring), `crates/minimald/` (session launch: network mode selection, netns/tap
setup), `crates/sandbox2/` (netns/tap provisioning for own-IP mode), new or
extended network-mode types in `crates/minimald-rpc/`

**Functional Requirements:**

- **R1.1**: The PTask specification type shall carry a `network` field whose
  value is one of `NoNet`, `HostNet`, or `OwnIp`. The field defaults to
  `HostNet` for backwards compatibility with existing sessions.
- **R1.2**: For `NoNet` PTasks, `minimald` shall configure the sandbox with an
  empty network namespace (no interfaces, no default route). The PTask is still
  reachable via the SSH/UDS path of its `minimald` (re-attach works regardless
  of network mode).
- **R1.3**: For `HostNet` PTasks, `minimald` shall configure the sandbox to share
  the host's (or VM's) network namespace, preserving the current behaviour.
- **R1.4**: `minimald` (on DM2) and `minvmd` (on DM1/DM3/DM4) shall spawn and
  supervise exactly one gvproxy process per host. gvproxy starts before the first
  own-IP PTask is requested and stops when the last own-IP PTask exits; the
  lifecycle follows the same SIGTERM → timeout → SIGKILL pattern used for the
  vmm child. If gvproxy exits unexpectedly, all own-IP PTasks on that host are
  torn down and a `tracing::error!` is emitted.
- **R1.5**: For `OwnIp` PTasks, `minimald` / `sandbox2` shall create a network
  namespace, provision a virtual tap interface inside it, and pass the tap file
  descriptor to the running gvproxy as a new switch client. On DM2 the fd-pass
  is over a unix socket or SCM_RIGHTS; on DM1 (macOS/libkrun VM) it is over
  vsock via the per-PTask shuttle process already used for boot signalling.
- **R1.6**: Each `OwnIp` PTask shall be assigned a unique IP from the gvproxy
  switch subnet (configurable; default `100.64.0.0/16` or similar RFC-6598
  range). The assigned IP shall not be reused by another PTask during the
  lifetime of the `minimald` process.
- **R1.7**: Two `OwnIp` PTasks on the same host shall reach each other by TCP
  and UDP directly on the gvproxy switch without leaving the switch process
  (UC6). Traffic is subject to each PTask's ingress policy (Unit 2).
- **R1.8**: `minimald` shall emit structured `tracing` events for: gvproxy
  process spawn and stop, PTask switch attachment (with assigned IP), and switch
  detachment. No `println!`/`eprintln!` in library or daemon code.

**Proof Artifacts:**

1. **Test:** Integration test (`crates/minimald/tests/` or `crates/minvmd/tests/`)
   starts two `OwnIp` PTasks and asserts a TCP connect from PTask A to PTask B's
   switch IP succeeds — demonstrates UC6 same-host PTask-to-PTask.
2. **Test:** Integration test starts a `NoNet` PTask and asserts that a TCP
   connect attempt from within it to `8.8.8.8:80` fails with connection
   refused or ENETUNREACH — demonstrates UC1 no-net isolation.

---

### Unit 2: Egress, ingress policy, and VM-wide controls (UC3, UC4, UC5)

**Purpose:** Policy enforcement on the gvproxy switch: per-PTask egress
allowlists (UC3), static and dynamic ingress port mappings (UC4), and VM-wide
egress for DM1/DM3/DM4 (UC5).

**Depends on:** Unit 1

**Affected areas:** `crates/minimald/` (policy wiring at session launch, new
policy RPC), `crates/minvmd/` (VM-level egress configuration), network policy
types, gvproxy filter/portfwd API integration

**Functional Requirements:**

- **R2.1**: A PTask spec shall carry an optional `egress` section (valid only for
  `OwnIp` mode). It shall have three optional fields: `allow_subnets` (list of
  CIDR strings), `allow_dns_hosts` (list of FQDNs), and `allow_protocols` (list
  of `tcp`, `udp`, `icmp`). Absent fields default to allow-all. Specifying `egress`
  on a `NoNet` or `HostNet` PTask is a parse-time error with a clear message.
- **R2.2**: `minimald` shall translate the egress rules from R2.1 into gvproxy's
  filter or policy API at PTask launch. Traffic not matching any allow rule shall
  be dropped. A `tracing::warn!` is emitted on the first drop per PTask per rule
  per minute (rate-limited); subsequent drops in the window increment a counter
  and are summarised at window close.
- **R2.3**: A PTask spec shall carry an optional `ingress` section (valid only
  for `OwnIp` mode). It shall have a `port_mappings` list of
  `{external_port: u16, internal_port: u16, proto: tcp|udp}` entries. The
  default (absent section) is deny-all-external. A `dynamic_allowed_ports`
  range may be specified to permit runtime port-mapping requests from inside
  the PTask.
- **R2.4**: `minimald` shall apply static port mappings at PTask launch via
  gvproxy's port-forward API. Dynamic port mapping requests shall arrive via a
  new RPC on the session; `minimald` shall validate the requested port against
  `dynamic_allowed_ports` and reject out-of-range requests with a typed error.
- **R2.5**: For DM1/DM3/DM4 (libkrun VMs managed by `minvmd`), the VM
  specification shall support a `vm_egress` field with the same structure as
  R2.1's `egress`. `minvmd` shall configure gvproxy to apply VM-wide egress
  rules to all traffic from the VM, regardless of per-PTask mode. On DM2,
  `vm_egress` is not applicable and shall be rejected as a configuration error.
- **R2.6**: `minimald` shall expose a read-only RPC returning the effective
  egress and ingress policy for a named session (useful for debugging and
  tooling). The response is a structured type, not a string.
- **R2.7**: All policy violations shall emit a `tracing::warn!` with structured
  fields: `session_id`, `direction` (`egress`/`ingress`), `remote_addr`, `proto`,
  `rule_matched`. Structured events, not interpolated strings.

**Proof Artifacts:**

1. **Test:** Integration test starts an `OwnIp` PTask with an egress allowlist
   permitting only `tcp` to a specific test IP. Asserts that a TCP connect to the
   allowed IP succeeds and a connect to a different IP fails — demonstrates UC3
   egress enforcement.
2. **Test:** Integration test configures a static ingress mapping on an `OwnIp`
   PTask, starts a listener inside it, and asserts that `connect("127.0.0.1",
   external_port)` from the host reaches the in-PTask listener — demonstrates
   UC4 ingress port mapping.
3. **CLI:** `minimal session policy <id>` returns the effective egress/ingress
   policy JSON for a running session — demonstrates the R2.6 read-only RPC.

---

### Unit 3: DNS hostname management (UC2a, UC2c)

**Purpose:** DNS-resolvable hostnames for own-IP and host-net PTask services,
and network-accessible `minimald` instances, so users reach services by name,
not by rotating IPs.

**Depends on:** Unit 1

**Affected areas:** `crates/minimald/` (hostname registration/deregistration,
DNS integration), new hostname manager module, host-side DNS configuration path

**Functional Requirements:**

- **R3.1**: `minimald` shall register a DNS hostname for each `OwnIp` PTask on
  launch. The hostname format shall be `<session-name>.<host-id>.localhost`
  (where `<host-id>` is a stable short name for the `minimald` instance,
  configurable). The hostname shall resolve to the PTask's gvproxy switch IP
  from processes on the same host. The hostname shall be deregistered when the
  session exits.
- **R3.2**: Network-accessible `minimald` instances (DM5) shall be reachable by
  a configured DNS hostname. The `minimal` CLI shall accept a hostname in addition
  to an IP address when connecting to a `minimald` (UC2c).
- **R3.3**: A browser on the same host shall reach a webserver inside an `OwnIp`
  PTask by its hostname (R3.1) without memorizing an IP (UC2a). The request
  routes through the gvproxy published port on `127.0.0.1`. The DNS resolution
  mechanism is `*.localhost` + a host-side proxy (Open Question 1, resolved by
  spike #485): the system resolver synthesizes every `*.localhost` name to
  loopback statically, and the host-side proxy routes each request to the right
  PTask by its `Host:` header.
- **R3.4**: DNS hostname registration shall require no root privilege per-invocation.
  If the mechanism requires a one-time install step (e.g. a system resolver
  configuration), `minimald` shall detect whether the step has been performed and
  emit a `tracing::warn!` with a human-readable remediation instruction when the
  setup is incomplete.
- **R3.5**: All hostname registration and deregistration events shall emit a
  structured `tracing` event with fields: `session_name`, `hostname`, `ip`,
  `action` (`registered` / `deregistered`). The hostname registry is keyed by
  the session name (per the hostname-manager architecture), so the identifying
  field carried by the event is `session_name`.
- **R3.6**: `minimald` shall register a DNS hostname for each `HostNet` PTask
  on launch, in the same format as R3.1 (`<session-name>.<host-id>.localhost`).
  The hostname shall resolve to `127.0.0.1` for local-only `minimald`
  configurations, or to the host's configured network interface address for DM5
  (network-accessible) configurations. The hostname shall be deregistered when
  the session exits. This enables hostname-driven access to `HostNet` PTask
  services without memorizing the host's IP address.

**Proof Artifacts:**

1. **Test:** Integration test starts an `OwnIp` PTask, resolves its hostname
   via the system resolver (`getaddrinfo`), asserts it resolves to the expected
   gvproxy switch IP, then confirms the hostname no longer resolves after the
   PTask exits — demonstrates R3.1 registration lifecycle.
2. **CLI:** `curl http://<session-name>.<host-id>.localhost/` from the local host
   returns HTTP 200 from a webserver running inside an own-IP PTask — demonstrates
   UC2a local browser access.
3. **CLI:** `curl http://<session-name>.<host-id>.localhost:<port>/` from the
   local host returns HTTP 200 from a webserver running inside a `HostNet` PTask
   (hostname resolves to `127.0.0.1`) — demonstrates UC2 hostname-driven access
   for host-net PTask services (R3.6).

---

### Unit 4: WireGuard mesh and remote browser access (UC7, UC2b)

**Purpose:** Authenticated remote connectivity: remote PTask-to-PTask across
hosts (UC7), laptop joining the mesh to reach PTasks by hostname (UC2b option A),
HTTPS reverse proxy on `minimald` for no-client remote browser access
(UC2b option B), and SSH port-forwarding as a fallback transport for networks
where WireGuard is blocked.

**Depends on:** Unit 1, Unit 3

**Affected areas:** `crates/minimald/` (new `wg` module: wireguard-go/boringtun
peer lifecycle, subnet-router advertisement; new `proxy` module: HTTPS TLS
termination, mTLS/OIDC auth, reverse-proxy to gvproxy switch),
`crates/minimal2/` (new `mesh` subcommand: CLI peer join/leave, peer-key
management)

**Functional Requirements:**

- **R4.1**: `minimald` shall embed a WireGuard peer using either wireguard-go
  (compiled to a shared library via cgo) or a pure-Rust WireGuard implementation
  (`boringtun` or equivalent). When a mesh configuration is present, `minimald`
  joins the mesh as a subnet-router peer advertising its gvproxy switch subnet
  (Tailscale-style subnet-router model). Peer public keys are exchanged via manual
  configuration in v1; automatic discovery is deferred.
- **R4.2**: PTasks on remote hosts shall be reachable by TCP/UDP from another
  PTask via the mesh, subject to each endpoint's egress/ingress policies. The
  traffic path is: source PTask → gvproxy switch → `minimald` peer → WireGuard
  tunnel → remote `minimald` → remote gvproxy switch → target PTask (UC7).
- **R4.3**: `minimal mesh join <minimald-address>` shall enrol the local `minimal`
  CLI (running on a laptop) as a WireGuard peer, with wireguard-go bundled so no
  system WireGuard package is required. Once joined, the laptop routes traffic to
  all PTask switch IPs through the mesh tunnel (UC2b option A). DNS resolution of
  PTask hostnames on the laptop follows from Unit 3's mechanism, scoped to mesh
  members.
- **R4.4**: `minimald` shall expose an HTTPS reverse proxy on a configurable
  port. The proxy terminates TLS (self-signed CA or ACME cert per Open Questions
  item 5), authenticates with mTLS (client cert from `minimal login`) or OIDC
  redirect, and reverse-proxies to the target PTask via the gvproxy switch.
  Only HTTP and WebSocket traffic is proxied; raw TCP/UDP is not available via
  this path (UC2b option B).
- **R4.5**: Authentication failures (invalid cert, failed OIDC, unrecognised peer)
  shall be logged via `tracing::warn!` with structured fields and shall not reveal
  internal topology (switch IPs, PTask names) to the caller.
- **R4.6**: `minimald` shall expose a `minimal mesh status` RPC returning the
  current mesh state: own public key, connected peer list (name + last-handshake),
  advertised subnets.
- **R4.7**: WireGuard and HTTPS proxy code shall be conditionally compiled behind
  a feature flag and shall not affect binary size or startup time when unconfigured.
- **R4.8**: `minimal mesh join`, `minimal mesh leave`, and `minimal mesh status`
  shall be documented with examples in the CLI help text.
- **R4.9**: `minimald` shall expose SSH port-forwarding (using the `russh` SSH
  server already embedded for PTask re-attach) as a fallback remote-access
  transport for networks where WireGuard is blocked. `minimal ssh-forward
  <session> <local-port>:<remote-addr>:<remote-port>` shall set up a
  `LocalForward`-style TCP tunnel to a service reachable from within the named
  `OwnIp` PTask, authenticated by the same credentials used for re-attach. This
  path requires no WireGuard configuration and carries TCP only.

**Proof Artifacts:**

1. **Test:** Integration test with two `minimald` instances in separate test
   network namespaces, WireGuard mesh configured, asserts that a TCP connect from
   a PTask on instance A to a PTask on instance B (via their switch IPs across the
   mesh tunnel) succeeds — demonstrates UC7 remote PTask-to-PTask.
2. **CLI:** From a laptop in the mesh, `curl http://<session-name>.<host-id>.localhost/`
   returns HTTP 200 from a webserver in an own-IP PTask on a remote host, routed
   over the WireGuard tunnel — demonstrates UC2b option A remote mesh access.
3. **CLI:** `minimal ssh-forward <session> 8080:127.0.0.1:80` with the WireGuard
   feature flag disabled establishes a TCP tunnel; `curl http://localhost:8080/`
   returns HTTP 200 from a webserver inside the PTask — demonstrates the SSH
   fallback for restricted networks (R4.9).

---

## Non-Goals

- **macOS native (no-VM) PTask networking** — on macOS, PTasks run inside a
  libkrun VM; the gvproxy switch architecture applies but the VM boundary is
  managed by `minvmd`. No native-macOS no-VM PTask path is added by this spec.
- **Root privilege networking** — any mechanism requiring ongoing root per-invocation
  is out of scope.
- **IPv6 within the gvproxy switch** — the initial implementation uses IPv4.
  IPv6 is a follow-up.
- **Commercial WireGuard coordination** — the mesh substrate is self-hosted;
  Tailscale cloud or other coordination services are out of scope.
- **QUIC / HTTP/3 in the reverse proxy** — initial proxy supports HTTP/1.1 and
  WebSockets; HTTP/2 and HTTP/3 are follow-ups.
- **Port mapping for HostNet or NoNet PTasks** — ingress port mapping (UC4) is
  only defined for `OwnIp` PTasks.
- **Multi-user `minimald` tenancy** — this spec handles a single-user `minimald`
  per host; multi-tenant policy isolation is a follow-up.

## Design Considerations

### One gvproxy per host, not per PTask

A single gvproxy instance per host gives one TCP/IP stack to reason about on
all five deployment models. The alternative (one pasta/gvproxy per PTask) would
require a second TCP/IP implementation on macOS and offers no UC6 (same-host
PTask-to-PTask) path without additional bridging. The CPU overhead of a shared
gvproxy is acceptable for a developer-workstation workload
(informed by `docs/specs/03-spec-networking/networking-with-diagrams.md`).

### DNS resolution: `*.localhost` + host-side proxy (decided)

R3.3 required a hostname-resolution mechanism. Spike #485 settled it in favour
of **`*.localhost` + a host-side proxy** over the one-time
`/etc/resolver`/resolver-config alternative, because it needs no privileged
write per session and no documented install step beyond an active system
resolver:

- The system resolver synthesizes every `*.localhost` name to a loopback
  address statically (guaranteed on macOS; provided by systemd-resolved or
  NetworkManager on Linux). `minimald` writes nothing to the resolver per
  session; it only probes at startup that the synthesis is available and warns
  with a remediation if it is not (R3.4).
- Because that synthesis is static and identical for every name, the DNS layer
  cannot distinguish PTasks. A host-side proxy is the discriminator: it routes
  each incoming request to the right PTask by its `Host:` header, consulting an
  in-memory hostname registry `minimald` maintains.

The rejected alternative — a one-time `/etc/resolver` (macOS) or resolver
config (Linux) — has a simpler per-session path but requires a documented
privileged setup step, which conflicts with the rootless goal.

### WireGuard implementation: wireguard-go vs boringtun

R4.1 leaves the choice open. `boringtun` (Rust) avoids a Go toolchain dependency
and produces a smaller binary. wireguard-go is more battle-tested and is the
reference implementation used in Tailscale's production stack. The decision is
made during Unit 4 design, informed by build-chain and maintenance considerations.

### UC5 collapses to UC3 on DM2

Native Linux (DM2) has no VM boundary to defend. VM-wide egress (UC5) therefore
collapses to per-PTask egress (UC3). The spec reflects this by marking `vm_egress`
as a configuration error on DM2 (R2.5).

### SSH port-forwarding as a restricted-network fallback

`minimald` embeds `russh` for PTask re-attach (SSH over UDS/TCP). SSH
`LocalForward`-style port-forwarding reuses that authenticated transport — no
credential setup beyond `minimal login` is required. The WireGuard mesh
(R4.1–R4.3) is the primary remote-access path for UC2b and UC7; SSH
port-forwarding (R4.9) is the fallback for networks where WireGuard's UDP cannot
get out. The fallback supports TCP only and does not deliver the hostname-driven
browser access of the mesh path, but it preserves authenticated remote service
access in restricted environments.

## Repository Standards

- Workspace conventions from `CLAUDE.md`: workspace-pinned deps; `cargo fmt &&
  cargo test -- --include-ignored`; `cargo clippy --allow-dirty --fix
  --all-targets -- -D warnings`; no `println!`/`eprintln!` in library or daemon
  code; structured `tracing` fields, not interpolated strings.
- Commit messages: Conventional Commits (`docs/commit-conventions.md`); imperative
  mood, lower-case, no trailing period; `feat(minimald):`, `feat(minvmd):`,
  `feat(minimal2):` scopes.
- Rust coding standards (`docs/rust-coding-standards.md`): functional over
  imperative; cheapest reference (`&str`, `&Path`); make illegal states
  unrepresentable; typed errors (`thiserror`) in library crates, `anyhow` at
  CLI/RPC boundaries; `#[must_use]` on Result-shaped returns; `#[non_exhaustive]`
  on public enums/structs that may grow.
- New external dependencies must be workspace-pinned and vetted against
  `blessed.rs` or the existing workspace before introduction.
- Each demoable unit adds integration tests under the affected crate's `tests/`
  directory; libkrun- or hardware-requiring tests are `#[ignore]` by default and
  gated on an env var.

## Open Questions

1. **DNS resolution mechanism** (R3.3, Unit 3): **Resolved (spike #485):**
   `*.localhost` + host-side proxy, over one-time
   `/etc/resolver`/resolver-config registration. The `*.localhost` path is fully
   rootless; it requires only that the system resolver synthesize wildcard
   localhost patterns, which `minimald` probes at startup and warns about if
   absent (R3.4). See the "DNS resolution" design consideration above.
2. **Egress default policy** (R2.1): The spec defaults absent `egress` to
   allow-all. Confirm with SecOps whether a deny-all default is required for
   compliance; changing the default is a breaking change to existing PTask
   behaviour.
3. **Dynamic port-mapping API shape** (R2.4): How does a process inside a PTask
   request a dynamic port mapping? Options: a Unix socket endpoint inside the
   PTask, a vsock port exposed by the switch, or an HTTP endpoint on the gvproxy
   gateway IP. Shape must be decided before Unit 2.
4. **WireGuard peer key exchange in v1** (R4.1): Manual key exchange (copy-paste
   public keys into config) is the v1 floor. Is there a planned lightweight
   coordination RPC on `minimald` itself, or does v1 remain fully manual?
5. **HTTPS proxy TLS certificate management** (R4.4): Self-signed CA managed by
   `minimald` (client installs trust anchor via `minimal login`) or ACME with a
   real DNS name? The self-signed path works for private teams; ACME requires a
   public-facing `minimald` with a DNS name.

## Technical Considerations

- **gvproxy binary**: `containers/gvisor-tap-vsock` is a Go project. Options:
  build from source as a workspace step (vendored Go module, version-pinned),
  or ship a pre-built binary with SHA-256 verification. Building from source is
  preferred for reproducibility and eliminates supply-chain risk from a
  pre-built download.
- **WireGuard in Rust**: `boringtun` (pure Rust WireGuard) avoids the Go
  toolchain dependency. If wireguard-go is chosen instead, it requires a cgo
  bridge and a Go toolchain in CI; this must be evaluated against the build-chain
  cost.
- **Platform gates**: `#[cfg(target_os = "linux")]` and
  `#[cfg(target_os = "macos")]` guards where the gvproxy client-attachment
  mechanism differs (unix socket vs vsock). The gvproxy process itself is
  cross-platform.
- **Async**: all networking operations use `tokio`; no blocking I/O in an async
  context (`tokio::fs`, `tokio::net`, `tokio::time::sleep`).
- **HTTPS proxy**: `hyper` or `axum` (already in the workspace ecosystem) for
  TLS termination and WebSocket upgrade; `rustls` for TLS with no OpenSSL
  dependency.

## Security Considerations

- **gvproxy process isolation**: gvproxy runs as the same user as `minimald`;
  no additional privilege. The unix socket used for switch attachment is mode
  0600, owner-only; gvproxy rejects connections from other uids.
- **Egress default**: absent `egress` config defaults to allow-all; environments
  requiring containment must configure explicit allowlists (see Open Questions
  item 2).
- **WireGuard peer revocation**: revocation in v1 is manual (remove peer key from
  config, restart). Automatic revocation is a follow-up.
- **HTTPS proxy auth boundary**: authentication (mTLS / OIDC) is enforced before
  any traffic reaches the gvproxy switch; rejected requests receive a plain 401
  with no topology information.
- **Port numbers < 1024**: `minimald` shall refuse to configure gvproxy to
  publish host ports below 1024 and emit a clear error with a remediation
  suggestion.
- **No external exposure by default**: `minimald` listens on localhost or a
  configured UDS; the HTTPS proxy and WireGuard endpoints are opt-in via
  explicit configuration.

## Verification

| Check | Command |
|---|---|
| Lint | `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` |
| Build | `cargo build -p minimald -p minvmd -p minimal2` |
| Unit + integration | `cargo test -p minimald -p minvmd -p minimal2` |
| Full (hardware) | `cargo test -- --include-ignored` (requires `/dev/kvm`) |
