---
id: arch-networking
title: "minimald networking — PTask network modes, DNS, egress/ingress, WireGuard mesh — architecture"
kind: architecture
status: planned
tracking-issue: 478
---

# minimald networking — architecture

## Chosen approach

The networking stack is built on a **shared gvproxy switch per host**. One
`gvproxy` (gvisor-tap-vsock) process per host acts as a userspace network
switch for all `OwnIp` PTasks. PTask isolation is implemented as a trimodal
`NetworkMode` enum replacing the current binary `disable_networking` flag in
`sandbox2::Config`. Each `OwnIp` PTask attaches to the switch as an
independent client; `HostNet` PTasks continue to share the host namespace;
`NoNet` PTasks run in an empty network namespace with no interfaces.

The gvproxy switch is owned by `minimald` on DM2 (native Linux) and by
`minvmd` on DM1/DM3/DM4 (libkrun VM deployments). `minvmd` already managed
a per-VM gvproxy in the prior `spec-minvmd-networking-gvproxy` specification
(#404); this architecture extends that pattern to DM2 and adds the full
per-PTask policy, DNS, and remote-access layers on top.

### Unit 1 — gvproxy switch and PTask network modes

**`sandbox2::Config`** gains a `network_mode: NetworkMode` field replacing
`disable_networking: bool`. The `NetworkMode` enum has three variants:

```rust
pub enum NetworkMode {
    /// No network namespace; all network syscalls fail or see no interfaces.
    NoNet,
    /// Share the host (or VM) network namespace. Current default.
    HostNet,
    /// Own IP via the gvproxy switch: new netns + tap + switch attachment.
    OwnIp,
}
```

`NoNet` maps directly to the former `disable_networking = true` path. `HostNet`
preserves current behaviour. `OwnIp` is new: `sandbox2` creates a network
namespace, provisions a virtual tap interface inside it, and returns the tap
file descriptor so the caller can pass it to the gvproxy switch. The IP address
is allocated from the switch subnet and written into the netns via a veth
setup.

**Attachment to the switch:**
- DM2 (native Linux): `minimald` passes the tap fd to gvproxy via a unix
  socket (SCM_RIGHTS fd-pass). A per-PTask unix socket controls the attachment.
- DM1/DM3/DM4 (libkrun VM): the tap fd is forwarded out of the VM over vsock
  by a per-PTask shuttle process (already used for boot signalling); gvproxy
  on the macOS/Linux host side accepts it.

**IP allocation:** `minimald` (or `minvmd`, for the VM path) maintains an
in-memory allocation table for the switch subnet (default `100.64.0.0/16`, RFC
6598 Carrier-Grade NAT range). IPs are allocated sequentially and released on
PTask exit. The table is not persisted across `minimald` restarts (surviving
PTasks across restarts are outside this spec's scope).

**gvproxy lifecycle:** `minimald` spawns gvproxy before the first `OwnIp`
PTask is created and supervises it via the same SIGTERM → timeout → SIGKILL
pattern used by `minvmd` for the VMM child. `minvmd` extends its existing
per-VM gvproxy lifecycle (from `spec-minvmd-networking-gvproxy`) to also serve
the full switch role for per-PTask attachment.

**gvproxy binary:** Built from vendored source (spec § "Technical
Considerations"), not downloaded at runtime. A Go build step is added to CI.
The binary is verified by SHA-256 before use.

**UC6 (same-host PTask-to-PTask):** Two `OwnIp` PTasks on the same switch
reach each other directly — the traffic stays within the gvproxy process,
never touching the kernel's IP routing. Subject to each PTask's ingress policy
(Unit 2).

### Unit 2 — egress, ingress policy, and VM-wide controls

Policy types live in `crates/minimald-rpc` (shared between the server and
clients) as `#[non_exhaustive]` enums:

```rust
pub struct EgressPolicy {
    pub allow_subnets: Option<Vec<String>>,      // CIDR strings
    pub allow_dns_hosts: Option<Vec<String>>,    // FQDNs
    pub allow_protocols: Option<Vec<IpProto>>,   // tcp | udp | icmp
}

pub struct IngressPolicy {
    pub port_mappings: Vec<PortMapping>,
    pub dynamic_allowed_range: Option<RangeInclusive<u16>>,
}
```

`minimald` translates these into gvproxy's filter/port-forward API at PTask
launch via gvproxy's HTTP management endpoint (default `192.168.127.254:8080`,
the well-known gvproxy gateway IP). This is gvproxy's native API surface and
requires no custom protocol — the dynamic port-mapping API is resolved as the
HTTP-on-gateway approach (see assumption ledger, `dynamic-portmap-api-http`).

**VM-wide egress (UC5):** `minvmd`'s VM specification gains a `vm_egress`
field with the same `EgressPolicy` structure. On DM2, `vm_egress` is rejected
as a configuration error (UC5 collapses to UC3 on DM2, which has no VM
boundary).

**Read-only policy RPC:** A new `GetSessionPolicy` RPC in `minimald-rpc`
returns the effective `EgressPolicy` and `IngressPolicy` for a named session.
The response is a structured type; it is consumed by `minimal session policy`.

### Unit 3 — DNS hostname management

`minimald` maintains a hostname registry keyed by session name. Registration
format: `<session-name>.<host-id>.min.local`, where `<host-id>` is a stable
configurable short name for the `minimald` instance.

The **DNS resolution mechanism** is the one genuine open design decision this
architecture cannot settle from the repository working tree — it depends on
target-OS behaviour (see assumption `dns-hostname-mechanism`, needs-spike
below). Both candidate paths are architecturally uniform from `minimald`'s
perspective: `minimald` writes hostnames to either a local resolver
configuration or the system resolver stub at launch, and removes them on exit.
Unit 3 begins after the spike resolves this question.

`HostNet` PTask hostnames (R3.6) use the same format; the resolved IP is
`127.0.0.1` for local-only instances or the host's configured network
interface address for DM5.

### Unit 4 — WireGuard mesh and remote browser access

`minimald` embeds a WireGuard peer via a feature-flagged `wg` module. When
the mesh configuration is present, `minimald` joins the mesh as a
subnet-router peer advertising its gvproxy switch subnet. **boringtun**
(pure Rust WireGuard) is the chosen WireGuard implementation for v1, settled
by spike #486 and confirmed by the maintainer. The wireguard-go subprocess
path is the v2 escalation if peer coordination is needed or boringtun stalls.

The HTTPS reverse proxy (`proxy` module) uses `hyper`/`axum` for HTTP/1.1 +
WebSocket, `rustls` for TLS (no OpenSSL dependency). Both `wg` and `proxy`
are behind a Cargo feature flag and do not affect binary size or startup time
when unconfigured.

SSH port-forwarding (R4.9) reuses `russh`, which `minimald` already embeds
for PTask re-attach. No new dependency is needed for the fallback transport.

## Data and interface changes

### `crates/sandbox2/src/config.rs`

- `disable_networking: bool` removed; replaced by `network_mode: NetworkMode`.
- `setup_dns_config: bool` retained (controls `/etc/resolv.conf` synthesis,
  orthogonal to UC2's per-PTask hostname registration).
- Builder method renamed: `with_disable_networking(bool)` → `with_network_mode(NetworkMode)`.
- All existing callers using `disable_networking: true` switch to
  `NetworkMode::NoNet`; callers using `false` (default) switch to
  `NetworkMode::HostNet`.

ALREADY EXISTS: `disable_networking: bool` in `crates/sandbox2/src/config.rs`
handles NoNet and HostNet cases in boolean form. The OwnIp case and the
trimodal enum are fully new work.

### `crates/sessions/src/lib.rs`

`Record` gains a `network: NetworkMode` field (defaulting to `HostNet` via
`#[serde(default)]`). The `NetworkMode` type is re-exported from
`crates/minimald-rpc` to avoid a circular dependency.

ALREADY EXISTS: `sessions::Record::attrs: BTreeMap<String, String>` as a
free-form escape hatch; the typed `network` field supersedes any ad-hoc
attrs-based approach.

### `crates/minimald-rpc/src/lib.rs`

New types: `NetworkMode`, `EgressPolicy`, `IngressPolicy`, `PortMapping`,
`IpProto`. New RPCs: `GetSessionPolicy`, `DynamicPortMapRequest`.

### `crates/minimald/src/`

New `net/` module tree:
- `net/mod.rs`: gvproxy lifecycle, IP allocator, switch attachment helpers.
- `net/policy.rs`: policy application via gvproxy HTTP API.
- `net/dns.rs`: hostname register / deregister (implementation depends on
  DNS spike outcome).
- `net/wg.rs`: WireGuard peer lifecycle (feature `networking-wg`).
- `net/proxy.rs`: HTTPS reverse proxy (feature `networking-proxy`).

`session.rs`: `SessionMessage` gains variants for the new policy and
dynamic-portmap RPCs.

### `crates/minvmd/src/`

`vm.rs`: Remove "no network device in v0.1" comment; add `vm_egress:
Option<EgressPolicy>` to `VmConfig`. The existing gvproxy child from
`spec-minvmd-networking-gvproxy` (#404) is extended to serve as the shared
switch for all PTask attachments inside that VM.

New `net.rs`: `NetworkMode`, `spawn_gvproxy`, `VmEgressPolicy` — aligned with
the stub design from spec #404 but extended for the full switch role.

### `crates/minimal2/src/`

New subcommand group `mesh`: `join`, `leave`, `status` (Unit 4).
New subcommand `ssh-forward` (Unit 4).
New subcommand `session policy` (Unit 2).

## Alternatives considered

### Per-PTask gvproxy (one gvproxy per PTask)

Rejected. The spec considered and rejected this: a shared switch gives one
TCP/IP implementation to debug on all five deployment models; per-PTask would
require a second userspace stack (pasta or another gvproxy) on macOS, since
the macOS VM path already needs gvproxy. UC6 (same-host PTask-to-PTask) is
free when both PTasks are on the same switch and requires additional bridging
with per-PTask stacks. (Informed by spec § "One gvproxy per host, not per
PTask".)

### pasta for the per-PTask Linux path

Rejected. Pasta does TCP splicing rather than a full TCP/IP stack; it cannot
run on macOS; it cannot provide UC6 without bridging. A shared gvproxy gives
platform uniformity and direct PTask-to-PTask routing at no extra cost.
(Informed by spec § rootless implementation analysis.)

### Retaining `disable_networking: bool` and adding `OwnIp` as a separate flag

Rejected. The trimodal enum encodes the three mutually exclusive states as
exactly that — a three-variant enum, not two booleans that can be
independently set into an illegal combination. The Rust coding standards
require making illegal states unrepresentable.

## Knowledge gaps

Distillery search (project: minimal) against concepts from this spec returned:

- **`arch-minvmd-host-daemon`** (score ≈ 0.82): directly constrains Unit 4's
  socket and process model. The architecture is fully aligned: `minimald`'s SSH
  transport, gvproxy child lifecycle pattern, and `StartingGuard` RAII pattern
  are all re-used. No contradiction.
- **`spec-minvmd-networking-gvproxy`** (#404, score ≈ 0.56): the prior
  gvproxy-for-VM spec, whose implementation has not landed yet (issue #404 is
  in `sdd:triage`). Its `NetworkMode` enum, `spawn_gvproxy`, and
  `check_network_policy` stub are all re-usable as foundation for Unit 1 and
  Unit 2. This architecture depends on #404's implementation landing first (or
  being subsumed by this work — see note in Unit 1).
- **`sandbox2/config.rs` pr#110** (cgroups without systemd): surfaced a prior
  constraint that `sandbox2` must degrade gracefully when cgroups/systemd are
  absent. The same resilience principle applies to netns creation: `minimald`
  must detect whether `CLONE_NEWNET` is available and emit a clear error when
  it is not.

Contradictions found: none.

Referenced-but-missing artifact: The "capability envelope" tracking issue
(referenced in spec #404 as the declaration surface for the `network`
allowlist) is not indexed in Distillery. The `sessions::Record::network` field
proposed here is the typed replacement for that placeholder.

## Assumption ledger

| slug | statement | bucket | evidence / citation |
|---|---|---|---|
| `shared-gvproxy-per-host` | One gvproxy process per host (DM2: alongside minimald; DM1/3/4: alongside the libkrun VM) serves all OwnIp PTasks as switch clients | settled | spec § "One gvproxy per host, not per PTask"; prior spec-minvmd-networking-gvproxy (#404) established the per-VM pattern (informed by #404) |
| `sandbox2-netmode-enum` | `sandbox2::Config::disable_networking: bool` must be replaced with a trimodal `NetworkMode` enum to express NoNet, HostNet, and OwnIp | settled | `crates/sandbox2/src/config.rs`: `disable_networking: bool` exists; boolean cannot represent OwnIp; coding standards require making illegal states unrepresentable |
| `ownip-ptask-fd-pass` | OwnIp PTasks attach to gvproxy via unix socket SCM_RIGHTS fd-pass on DM2; via vsock shuttle on DM1/3/4 | settled | spec R1.5; consistent with the vsock shuttle already described in arch-minvmd-host-daemon; DM2 has direct host access so SCM_RIGHTS is the simplest mechanism |
| `minvmd-owns-vm-gvproxy` | On DM1/3/4, minvmd owns the gvproxy process that serves the libkrun VM; minimald owns the gvproxy that serves DM2 PTasks | settled | spec R1.4; prior arch-minvmd-host-daemon delegates network lifecycle to the VM supervisor; minimald is the process that creates and destroys DM2 PTasks |
| `dynamic-portmap-api-http` | Dynamic port-mapping requests from within a PTask (R2.4) use HTTP to gvproxy's management endpoint at the gateway IP | settled | spec § "Technical Considerations" references gvproxy's port-forward API; gvproxy's management HTTP endpoint is its standard API surface for port mapping; accessible from any OwnIp PTask without additional infrastructure |
| `dm2-uc5-collapse` | VM-wide egress (UC5) is a configuration error on DM2 (native Linux, no VM boundary); UC5 collapses to UC3 on DM2 | settled | spec R2.5 explicitly states this; DM2 has no VM boundary — `vm_egress` applies only when minvmd owns the VM |
| `gvproxy-source-build` | gvproxy ships as a pinned **pre-built** release binary (gvisor-tap-vsock v0.8.9), fetched and verified against checked-in SHA-256 digests in `vendor/gvproxy/gvproxy.lock` via `scripts/fetch-gvproxy.sh` — not built from source | settled (maintainer decision; supersedes the spec's source-build preference) | spec § "Technical Considerations" lists a SHA-256-verified pre-built binary as the accepted alternative; chosen to avoid a Go toolchain + module-proxy egress in the build sandbox; supply-chain risk mitigated by pinned upstream digests (#495) |
| `https-proxy-hyper-rustls` | The Unit 4 HTTPS reverse proxy uses hyper/axum for HTTP and rustls for TLS, matching the workspace's existing ecosystem | settled | spec § "Technical Considerations"; `rustls` is listed as a no-OpenSSL-dependency choice; `hyper`/`axum` are named as consistent with workspace deps |
| `dns-hostname-mechanism` | The system resolver supports PTask hostname registration without root privilege per-invocation via either `*.localhost` wildcard (rootless on macOS; requires systemd-resolved or NetworkManager on Linux) or a one-time `/etc/resolver`-equivalent setup | needs-spike | spec Open Questions item 1: "Decision needed before Unit 3 implementation begins"; whether `*.localhost` wildcard resolution is reliably available on common Linux distributions (Ubuntu, Fedora, Arch, Debian) is not settleable from the repo working tree; R3.4 requires rootless per-invocation operation |
| `wireguard-implementation` | Unit 4 WireGuard implementation is **boringtun** (pure Rust); wireguard-go subprocess is the v2 escalation path if peer coordination is needed or boringtun stalls | settled | spike #486 concluded boringtun for v1: clean Cargo feature-flag support for R4.7, zero additional build-chain dependencies, sufficient production maturity (Cloudflare WARP, Mullvad VPN) for the AllowedIPs-based subnet-router model; cgo path substantially more complex than hypothesised; maintainer confirmed on #478 (informed by #486) |

ALREADY EXISTS: `sandbox2::Config::disable_networking: bool` — covers R1.2 (NoNet) and R1.3 (HostNet) in boolean form. The trimodal enum refactor replaces this field, preserving its semantics for the two existing modes.

ALREADY EXISTS: `sandbox2::Config::setup_dns_config: bool` — synthesises `/etc/resolv.conf` inside sandboxes. Retained unchanged; orthogonal to UC2 per-PTask hostname registration.

ALREADY EXISTS: `minimald` embeds `russh` for PTask re-attach over SSH/UDS. R4.9 (SSH port-forwarding fallback) reuses this transport with no new dependency.

ALREADY EXISTS: `minvmd::lifecycle` pure state machine, `StartingGuard` RAII pattern, VMM child supervision — all re-usable as-is for the gvproxy lifecycle extension in DM1/3/4 (informed by arch-minvmd-host-daemon).
