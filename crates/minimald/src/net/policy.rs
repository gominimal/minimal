//! Static ingress port-mapping via gvproxy's forwarder API (R2.3, R2.4-static)
//! and rate-limited policy-violation warning plumbing (R2.7).
//!
//! The gvproxy v0.8.9 spike (`docs/spikes/2026-06-21-gvproxy-attachment.md` §5)
//! pinned two load-bearing facts this module is built on:
//!
//! * The forwarder / management API is reachable **only** on the host-side
//!   control socket (the same unix socket [`switch`](super::switch) connects to
//!   for `POST /connect`), **not** the in-PTask gateway IP. So minimald drives
//!   ingress from the daemon side, where it already holds the control socket.
//! * gvproxy exposes `POST /services/forwarder/expose` and
//!   `POST /services/forwarder/unexpose` there to add and remove static port
//!   forwards.
//!
//! The same spike established that gvproxy v0.8.9 has **no per-client egress
//! ACL API**, so egress *enforcement* (R2.2, NET-062) lives in the relay
//! layer ([`switch`](super::switch)) — it inspects each frame against the
//! pure verdict in `boxes::core::egress` and drops what the box did not
//! declare. What this module carries for that enforcement is the warning
//! plumbing: [`PolicyWarnLimiter`], whose rate limit is keyed by box and
//! rule, and [`Proto`], the transport a dropped frame is logged under.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_vsock::{VsockAddr, VsockStream};

use boxes::core::egress::{DynamicPortVerdict, IngressRules};
use boxes::{IngressPolicy, IpProto, PortMapping};

/// The forwarder-expose request body gvproxy's `POST /services/forwarder/expose`
/// expects: a host-side `local` listen address and the PTask-side `remote` it
/// forwards to, plus the transport `protocol`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExposeRequest {
    /// Host-side listen address, `host:port` (e.g. `127.0.0.1:8080`).
    pub local: String,
    /// PTask-side destination, `ip:port`.
    pub remote: String,
    /// Transport protocol (`tcp` / `udp`).
    pub protocol: String,
}

/// The `POST /services/forwarder/unexpose` body: the `local` address (and its
/// `protocol`) a prior [`ExposeRequest`] bound, identifying the forward to drop.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnexposeRequest {
    /// The host-side listen address the forward was exposed on.
    pub local: String,
    /// The transport protocol the forward was exposed with.
    pub protocol: String,
}

/// How minimald reaches gvproxy's control socket to drive the forwarder API.
///
/// On DM2 the gvproxy `minimald` spawned is local, so the control socket is a
/// unix path. On DM1/3/4 gvproxy runs on the host (`minvmd` owns it); the guest
/// reaches the same `-listen` control socket over the per-host vsock shuttle
/// (`minvmd` maps the shuttle port to it via `krun_add_vsock_port2`), so the
/// forwarder verbs ride the same channel as the L2 `POST /connect` relay.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ControlChannel {
    /// Local unix control socket (DM2).
    Unix(std::path::PathBuf),
    /// Host gvproxy reached over vsock (DM1/3/4): `cid` = host (2), `port` = the
    /// shuttle port `minvmd` bridged to the gvproxy control socket.
    Vsock { cid: u32, port: u32 },
}

impl ControlChannel {
    /// Whether the host, not this daemon, unbinds a declared port's forward.
    /// On a VM-backed host (the vsock channel) every control request passes
    /// the host's egress gate first. The gate refuses any withdrawal of a
    /// declared port (NET-081's withdrawal rule) and unbinds the declared
    /// forwards itself when the box's row is withdrawn (design §7.1:
    /// host-side ingress revocation). On a native host the daemon drives the
    /// switch directly, and the unbind is its own job.
    #[must_use]
    pub fn host_unbinds_declared_forwards(&self) -> bool {
        matches!(self, Self::Vsock { .. })
    }
}

/// gvproxy's wire spelling of an [`IpProto`] in a forwarder request.
fn protocol_str(proto: IpProto) -> &'static str {
    match proto {
        IpProto::Tcp => "tcp",
        IpProto::Udp => "udp",
        // gvproxy's forwarder only exposes TCP/UDP, and `Record::validate_policy`
        // rejects any other protocol before it reaches here. `IpProto` is also
        // `#[non_exhaustive]`, so the `_` arm cannot be eliminated; a
        // `debug_assert!` surfaces any future caller that bypasses validation in
        // test runs, while TCP — the forwarder's default transport — stays the
        // production fallback rather than a silently misrouted request.
        _ => {
            debug_assert!(
                false,
                "protocol_str reached its fallback with {proto:?}; validate_policy \
                 must reject every non-TCP/UDP ingress protocol before apply_ingress"
            );
            "tcp"
        }
    }
}

/// Builds the [`ExposeRequest`] that forwards `mapping`'s host-side
/// `external_port` — published at `published`, the host loopback address the
/// box's declaration is published on (NET-010) — to `ptask_ip:internal_port`
/// on the switch.
///
/// The `local` host is a loopback address so the forward binds host loopback
/// only: a process *on the host* reaches the port (R2.3), while the spec's "no
/// external exposure by default" keeps it off the LAN. It is the box's **own**
/// address, not `127.0.0.1`, wherever the reserved local range gave it one, so
/// two boxes naming the same port both publish — on their own addresses, at
/// their own port numbers (NET-010). A box that shares an address with another
/// and names a port it names too collides there; the collision is intrinsic to
/// the mode, so it is *reported* by the registry's publish — never translated
/// away here: neither port number is remapped (NET-129).
///
/// The `remote` targets the PTask's allocated switch address.
#[must_use]
pub fn expose_request(
    mapping: &PortMapping,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
) -> ExposeRequest {
    ExposeRequest {
        local: format!("{published}:{}", mapping.external_port),
        remote: format!("{ptask_ip}:{}", mapping.internal_port),
        protocol: protocol_str(mapping.proto).to_string(),
    }
}

/// A forward currently exposed on the switch, retained so it can be torn down
/// on PTask exit ([`remove_ingress`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposedMapping {
    local: String,
    protocol: String,
}

impl ExposedMapping {
    /// The `host:port` the forward is bound on — the address the switch is
    /// actually holding, spelled exactly as its expose request named it. A
    /// caller reporting a publish (the per-mapping info line in
    /// `finish_own_ip_attach`) reads this instead of re-deriving the address
    /// from the request, so the report cannot claim a host a forward is not
    /// published on.
    #[must_use]
    pub fn local(&self) -> &str {
        &self.local
    }

    /// [`Self::local`] split into the host address and port to report. `None`
    /// when `local` is not a `host:port` pair with a numeric port — a shape
    /// [`expose_request`], its only builder, never produces.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        let (host, port) = self.local.rsplit_once(':')?;
        Some((host, port.parse().ok()?))
    }
}

/// A declared port's forwarder, owned by the daemon (NET-121): the mapping the
/// switch bound for it, the internal port it forwards to, and — when the box
/// carries a session gate — that gate, which the forwarder's own
/// [`revoke`](Self::revoke) drives. `revoke` refuses the port at the relay's
/// ingress legs, terminates the connections the gate holds, and only then
/// unexposes. The patched switch's unexpose closes the forward's listener and
/// then the connections that forward accepted, so the host-side ends of a
/// revoked port's connections close with it, while a sibling forward to the
/// same internal port keeps its own (NET-017).
#[derive(Clone)]
pub struct PortForwarder {
    mapping: ExposedMapping,
    internal_port: u16,
    gate: Option<Arc<super::switch::BoxGate>>,
    /// Whether this forwarder's ingress was revoked already — set by
    /// [`Self::revoke`] once its unbind has *succeeded*, so a revocation that
    /// failed at the switch stays unrevoked and both a retry and the
    /// teardown's unexpose still have work to do. `Arc`-shared because the
    /// forwarder is cloned onto the guard's list and every clone must agree
    /// on whether the forward stands.
    revoked: Arc<AtomicBool>,
}

impl PortForwarder {
    /// The `host:port` the forward is bound on, as [`ExposedMapping`] reads
    /// it.
    #[must_use]
    pub fn local(&self) -> &str {
        self.mapping.local()
    }

    /// [`Self::local`] split into the host address and port.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        self.mapping.host_port()
    }

    /// Whether this is the forward `mapping` declares at `published`: the
    /// same listener and the same protocol. TCP and UDP on one port are two
    /// forwards.
    #[must_use]
    pub fn is_forward_of(&self, published: Ipv4Addr, mapping: &PortMapping) -> bool {
        self.mapping.protocol == protocol_str(mapping.proto)
            && self.mapping.local == format!("{published}:{}", mapping.external_port)
    }

    /// The internal port the forward delivers to — the port a revocation
    /// refuses at the box's ingress gate.
    #[must_use]
    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }

    /// Whether this forwarder's ingress was revoked already: its unbind ran
    /// and succeeded, so no forward stands at its `local` any more, and
    /// neither a second revocation nor the teardown's unexpose has anything
    /// left to ask of the switch.
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// Unbinds the forwarder (NET-121): the gate refuses its port from here
    /// on — terminating the connections it holds — and the switch unexposes
    /// the forward. The gate first, so no new connection can cross the gap
    /// between a port the gate still admits and a listener already gone: a
    /// refused port is answered by the box, not left hanging at a listener
    /// that no longer exists.
    ///
    /// `keep_admitted` names the internal ports that must stay admitted
    /// because another *live* forwarder still forwards to them — the shape
    /// two mappings make when both publish the same in-box port. The gate
    /// refuses by internal port alone (a box's inbound frames carry no trace
    /// of which external forward they arrived through), so a revocation whose
    /// internal port is in the set *withholds* the gate's termination rather
    /// than end a sibling forwarder's connections with it. The unbind still
    /// ends this forward's own connections: the switch tracks what each
    /// forward accepted, so its unexpose closes this forward's connections
    /// and leaves the sibling's open (NET-017).
    ///
    /// # Errors
    ///
    /// The unexpose error, after the termination has run: the caller decides
    /// whether a failed unbind stops its path.
    pub async fn revoke(
        &self,
        control: &ControlChannel,
        keep_admitted: &HashSet<u16>,
    ) -> io::Result<()> {
        let (host, external_port) = self.host_port().unwrap_or(("", 0));
        if let Some(gate) = &self.gate {
            if keep_admitted.contains(&self.internal_port) {
                // A live sibling forwarder still maps another external port
                // to this internal port: terminating here would end its
                // connections with this port's, and the gate cannot tell the
                // two apart. Withheld, and said so — the log tail names each
                // revocation with its port and its reason (NET-121).
                tracing::info!(
                    host,
                    port = external_port,
                    internal_port = self.internal_port(),
                    reason = "internal port still served by another forwarder",
                    "unbinding ingress forwarder"
                );
            } else {
                let terminated = gate.revoke_port(self.internal_port());
                tracing::info!(
                    host,
                    port = external_port,
                    internal_port = self.internal_port(),
                    terminated,
                    reason = "ingress revoked",
                    "unbinding ingress forwarder"
                );
            }
        }
        let req = UnexposeRequest {
            local: self.mapping.local.clone(),
            protocol: self.mapping.protocol.clone(),
        };
        match unexpose_closing(control, &req).await {
            Ok(closed) => {
                tracing::info!(
                    host,
                    port = external_port,
                    closed_connections = %closed,
                    reason = "ingress revoked",
                    "unbound ingress forwarder"
                );
                // Marked only now, when the switch has really dropped the
                // forward: an unbind that failed leaves the forward standing,
                // so a retry — and the teardown's unexpose — still have work.
                self.revoked.store(true, Ordering::Release);
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    host,
                    port = external_port,
                    error = %e,
                    reason = "ingress revoked",
                    "unbinding ingress forwarder failed"
                );
                Err(e)
            }
        }
    }

    /// Unbinds the forward a move of the box's publish left at the old
    /// address (#2748). The gate keeps admitting the port, since the forward
    /// bound at the new address serves it now. The forwarder is marked
    /// revoked once the unbind stands, so the attach's teardown, which holds
    /// a clone, asks nothing more of it.
    ///
    /// # Errors
    ///
    /// Returns the I/O error from the failing `unexpose` call.
    pub async fn unbind_moved(&self, control: &ControlChannel) -> io::Result<()> {
        if self.is_revoked() {
            return Ok(());
        }
        let closed = unexpose_mapping(control, &self.mapping).await?;
        self.revoked.store(true, Ordering::Release);
        let (host, port) = self.mapping.host_port().unwrap_or(("", 0));
        tracing::info!(
            host,
            port,
            protocol = %self.mapping.protocol,
            closed_connections = %closed,
            "unbound the forward a move of the box's publish left at the old address"
        );
        Ok(())
    }
}

/// Exposes every static port mapping in `ingress` on the switch's `control_sock`
/// at `published` — the box's own host loopback address (NET-010) — forwarding
/// to `ptask_ip`, returning one daemon-owned [`PortForwarder`] per bound
/// forward (R2.3, R2.4-static, NET-121). The dynamic range, if any, is not
/// applied here — dynamic port-mapping is split to #553.
///
/// `gate` is the box's session gate, carried into every forwarder so a later
/// revocation can end its connections (NET-121); `None` for a caller whose
/// box has no relay — the netns proofs — where a forwarder simply has no
/// gate to revoke through.
///
/// `yielded` is the ports the box yields at a shared address (NET-129,
/// first-come): another box holds each one, so its forward is known state,
/// not a failure. It is skipped, with one warn line naming the port and the
/// box that holds it, and the box's other forwards bind as usual.
///
/// A host port another process already holds is a failure like any other
/// refused bind (NET-121): the rollback below runs and the caller withdraws
/// the name. Only the returned error differs. It carries a
/// [`minimald_rpc::PortInUseRefusal`] in place of the forwarder's raw
/// refusal, and its kind is [`io::ErrorKind::AddrInUse`]. The refusal names
/// the port and its holder (NET-144). Here the holder is always the host.
/// [`apply_ingress_naming_holders`] reads it from the hostname registry.
///
/// On the first failure the already-bound forwards are rolled back so a
/// partial apply does not leak forwards onto the switch, and the original
/// error is returned. The failure says its own line first (NET-121's sub 2):
/// one warn per failed bind, naming the declared port and the reason, so the
/// daemon log's tail shows which port of which address could not bind.
///
/// # Errors
///
/// Returns the I/O error from the first failing `expose` call (after rollback).
pub async fn apply_ingress(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
    gate: Option<&Arc<super::switch::BoxGate>>,
    yielded: &[super::dns::SharedPortCollision],
) -> io::Result<Vec<PortForwarder>> {
    apply_ingress_naming_holders(
        control,
        published,
        ptask_ip,
        ingress,
        gate,
        yielded,
        &|_| minimald_rpc::PortHolder::Host,
    )
    .await
}

/// [`apply_ingress`], with `holder_of` to name what holds a taken port
/// (NET-144). The attach path passes [`port_holder`] over the hostname
/// registry, so the refusal names the box whose publish stands at that
/// address and port, or the host when none does.
///
/// # Errors
///
/// As [`apply_ingress`].
pub async fn apply_ingress_naming_holders(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
    gate: Option<&Arc<super::switch::BoxGate>>,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    apply_declared(
        control,
        control.host_unbinds_declared_forwards(),
        published,
        ptask_ip,
        ingress,
        gate,
        yielded,
        holder_of,
    )
    .await
}

/// Binds the declared forwards of a box on a VM-backed host when finalize
/// publishes it, before the record goes `Active` (NET-121, NET-144, design
/// §7.1: the bind succeeds before the name is published). On a VM-backed
/// host the forwarder binds on the host OS, so the daemon cannot probe the
/// ports itself ([`host_ports_in_use`]). It binds them, toward the
/// `switch_address` the VM host handed the box, and a held port fails with
/// the same typed refusal the native probe gives. A failure rolls back as
/// [`apply_ingress`] does.
///
/// The bound forwards stay on the host. The box's first attach posts the
/// same exposes again, and the host's switch answers each one that the
/// listener is already bound, which the attach takes as bound. The host
/// unbinds the forwards when it withdraws the box's row, as it does for
/// every declared forward ([`release_declared_ingress`]).
///
/// # Errors
///
/// As [`apply_ingress`].
pub async fn bind_declared_at_publish(
    control: &ControlChannel,
    published: Ipv4Addr,
    switch_address: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    apply_declared(
        control,
        control.host_unbinds_declared_forwards(),
        published,
        switch_address,
        ingress,
        None,
        yielded,
        holder_of,
    )
    .await
}

/// [`apply_ingress_naming_holders`], with `host_holds_listeners` read off the
/// control channel ([`ControlChannel::host_unbinds_declared_forwards`]) by
/// the caller, so a test can drive the VM-backed answers over a unix socket.
/// Behind a VM host's gate a listener the switch already holds is the
/// box's own forward, bound at publish ([`bind_declared_at_publish`]), or
/// a publish the host keeps for the box until the holder's row is withdrawn
/// ([`HandedBind::HeldByHost`]). Either way the forward is tracked as bound.
#[expect(
    clippy::too_many_arguments,
    reason = "the public wrappers above fix the flag; a struct would be single-use ceremony"
)]
async fn apply_declared(
    control: &ControlChannel,
    host_holds_listeners: bool,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    ingress: &IngressPolicy,
    gate: Option<&Arc<super::switch::BoxGate>>,
    yielded: &[super::dns::SharedPortCollision],
    holder_of: &(dyn Fn(u16) -> minimald_rpc::PortHolder + Sync),
) -> io::Result<Vec<PortForwarder>> {
    let mut bound: Vec<PortForwarder> = Vec::with_capacity(ingress.port_mappings.len());
    for mapping in &ingress.port_mappings {
        if let Some(collision) = yielded
            .iter()
            .find(|collision| collision.port == mapping.external_port)
        {
            tracing::warn!(
                port = mapping.external_port,
                address = %published,
                other = %collision.other,
                action = "shared-address-port-collision",
                "declared ingress port not bound: another box at the shared \
                 address holds it"
            );
            continue;
        }
        let req = expose_request(mapping, published, ptask_ip);
        let answer = match post_json(control, "/services/forwarder/expose", &req).await {
            Err(e) if host_holds_listeners && is_already_running(&e) => {
                tracing::debug!(
                    port = mapping.external_port,
                    local = %req.local,
                    "the host already holds this declared forward for the box"
                );
                Ok(())
            }
            answer => answer,
        };
        match answer {
            Ok(()) => bound.push(PortForwarder {
                mapping: ExposedMapping {
                    local: req.local,
                    protocol: req.protocol,
                },
                internal_port: mapping.internal_port,
                gate: gate.cloned(),
                revoked: Arc::new(AtomicBool::new(false)),
            }),
            Err(e) => {
                // The failed bind is the failure's own fact, said where it
                // happened: the declared port, the address it tried to bind
                // on, and the reason the switch gave. What follows — the
                // rollback and the caller's refusal to publish — reads it in
                // the log beside the name that was never registered.
                tracing::warn!(
                    port = mapping.external_port,
                    local = %req.local,
                    error = %e,
                    "binding declared ingress port failed"
                );
                // Roll back what we managed to expose so a half-applied policy
                // does not leave dangling forwards on the shared switch.
                release_declared(control, host_holds_listeners, &bound).await;
                // A taken host port fails the apply like any other refusal:
                // NET-121 (docs/specs/18-spec-box-networking, design §7.1)
                // makes a failed bind a surfaced error, never a silent
                // fallback, so the box never publishes a name while one of
                // its declared ports is missing. Only the error's words
                // differ: they name the port and the way out.
                if is_address_in_use(&e) {
                    return Err(address_in_use_error(minimald_rpc::PortInUseRefusal {
                        port: mapping.external_port,
                        box_port: mapping.internal_port,
                        holder: holder_of(mapping.external_port),
                    }));
                }
                return Err(e);
            }
        }
    }
    Ok(bound)
}

/// The OS's own text for a bind onto a port another process already holds,
/// as it reaches [`apply_ingress`] inside the forwarder's refusal.
const ADDRESS_IN_USE_BODY: &str = "address already in use";

/// Whether `error` is the forwarder refusing an `expose` because the host
/// port it binds is already in use — the OS's `EADDRINUSE` text, matched on
/// the message's own words rather than the forwarder's surrounding wording,
/// so a differently-phrased listener on the same bind is still read as the
/// same fact.
fn is_address_in_use(error: &io::Error) -> bool {
    let said = error.to_string();
    said.contains("returned HTTP 500") && said.contains(ADDRESS_IN_USE_BODY)
}

/// The declared TCP host ports of `ingress` that another process already
/// holds at `published`, found by a short-lived bind of each one in this
/// daemon's network namespace — the same bind the forwarder makes at the
/// box's first spawn when `control` reaches a switch this daemon spawned.
/// When the host unbinds the declared forwards
/// ([`ControlChannel::host_unbinds_declared_forwards`]), the forwarder
/// binds on the host OS, not where this daemon runs, so a bind here would
/// test the wrong ports: the probe reports nothing and the spawn's own
/// apply says a taken port. A port in `yielded` is skipped, because another
/// box at the shared address holds it and the collision report already
/// names it. A bind that fails for any reason other than `EADDRINUSE`
/// reports nothing: the spawn's own apply says that failure. Call this only
/// when the box's forwards are not bound, or it finds the box's own
/// forwards.
#[must_use]
pub fn host_ports_in_use(
    control: &ControlChannel,
    published: Ipv4Addr,
    ingress: &IngressPolicy,
    yielded: &[u16],
) -> Vec<u16> {
    if control.host_unbinds_declared_forwards() {
        return Vec::new();
    }
    ingress
        .port_mappings
        .iter()
        .filter(|mapping| mapping.proto == boxes::IpProto::Tcp)
        .map(|mapping| mapping.external_port)
        .filter(|port| !yielded.contains(port))
        .filter(|&port| port_held_at(published, port))
        .collect()
}

/// How many times [`port_held_at`] binds a port before it reports the port
/// held.
const PORT_HELD_BINDS: u32 = 3;
const _: () = assert!(PORT_HELD_BINDS > 1, "one failed bind is not enough");

/// The pause between two binds of [`port_held_at`].
const PORT_HELD_RETRY: Duration = Duration::from_millis(20);

/// Whether another process holds `port` at `address`: every one of
/// [`PORT_HELD_BINDS`] binds, [`PORT_HELD_RETRY`] apart, fails with
/// `EADDRINUSE`. A single failed bind is not enough, because a parallel
/// probe of the same port holds it for the moment of its own bind. A real
/// holder fails every bind. The first bind that succeeds, or fails for any
/// other reason, ends the probe at once, so a free port costs no pause.
fn port_held_at(address: Ipv4Addr, port: u16) -> bool {
    port_held_by(|| std::net::TcpListener::bind((address, port)).map(drop))
}

/// [`port_held_at`]'s rule over any `bind`, so a test can fail chosen
/// binds in turn without racing a listener's release.
fn port_held_by(mut bind: impl FnMut() -> io::Result<()>) -> bool {
    for attempt in 1..=PORT_HELD_BINDS {
        match bind() {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                if attempt < PORT_HELD_BINDS {
                    std::thread::sleep(PORT_HELD_RETRY);
                }
            }
            _ => return false,
        }
    }
    true
}

/// The error [`apply_ingress`] returns for a declared port that something
/// else already holds on the host, and the error a finalize returns when it
/// finds one before the box is active. A person reads it at the failed
/// activation or command, so it names the port, its holder and the next step
/// (NET-144). The forwarder's own refusal is in the warn line
/// [`apply_ingress`] logs, not here. The kind is
/// [`io::ErrorKind::AddrInUse`], and the payload is the typed refusal, which
/// [`port_in_use_refusal`] reads back.
pub fn address_in_use_error(refusal: minimald_rpc::PortInUseRefusal) -> io::Error {
    io::Error::new(io::ErrorKind::AddrInUse, refusal)
}

/// The typed refusal inside `error`, when it is one [`address_in_use_error`]
/// built or when its text carries one, as an error wrapped on its way up
/// does.
#[must_use]
pub fn port_in_use_refusal(error: &io::Error) -> Option<minimald_rpc::PortInUseRefusal> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<minimald_rpc::PortInUseRefusal>())
        .cloned()
        .or_else(|| minimald_rpc::PortInUseRefusal::find_in(&error.to_string()))
}

/// What holds `port` at `address` (NET-144): the box whose publish stands
/// there in the hostname registry, or the host when no box does. A holder
/// named `own_name` is the box that asks, so it does not count: then the
/// host holds the port.
#[must_use]
pub fn port_holder(
    registry: &std::sync::RwLock<super::dns::HostnameRegistry>,
    own_name: &str,
    address: Ipv4Addr,
    port: u16,
) -> minimald_rpc::PortHolder {
    registry
        .read()
        .expect("hostname registry lock poisoned")
        .own_port_holder(address, port)
        .map(|(_, name)| name)
        .filter(|name| name != own_name)
        .map_or(
            minimald_rpc::PortHolder::Host,
            minimald_rpc::PortHolder::Box,
        )
}

/// The body the forwarder answers an expose with when a forward is already
/// bound at the listener, as an HTTP 500. On a VM-backed host the egress
/// gate gives the same answer to a publish whose listener another box's row
/// still holds, and keeps the publish to bind when that row is withdrawn.
const ALREADY_RUNNING_BODY: &str = "proxy already running";

/// Whether `error` is the forwarder's answer to an expose of a listener
/// that is already bound, as [`post_json`] reports a refused request.
fn is_already_running(error: &io::Error) -> bool {
    let said = error.to_string();
    said.contains("returned HTTP 500") && said.contains(ALREADY_RUNNING_BODY)
}

/// What binding a shared-address port's forward at its hand-over came to
/// ([`bind_handed_port`]). Both carry the forwarder to track for the box.
pub enum HandedBind {
    /// The switch bound the forward.
    Bound(PortForwarder),
    /// On a VM-backed host, the listener is still held by the row of the
    /// box that gave the port up. The host keeps this publish and binds it
    /// when that row is withdrawn.
    HeldByHost(PortForwarder),
}

/// Binds one declared mapping's forward for a box that took its port over
/// while running (NET-129): the expose the box's own attach posts for the
/// mapping ([`apply_ingress`]), at `published` toward `ptask_ip`. Nothing
/// else of the box's ingress is touched, so a failure rolls nothing back.
///
/// On a VM-backed host an answer that the listener is already bound is the
/// host's egress gate holding the publish behind the old holder's row,
/// which it binds itself when that row is withdrawn: [`HandedBind::HeldByHost`].
/// On a native host the same answer is a forward still bound at the
/// listener, and is the error it reads as.
///
/// # Errors
///
/// Returns the I/O error from the failing `expose` call.
pub async fn bind_handed_port(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    mapping: &PortMapping,
    gate: Option<&Arc<super::switch::BoxGate>>,
) -> io::Result<HandedBind> {
    let req = expose_request(mapping, published, ptask_ip);
    let answer = post_json(control, "/services/forwarder/expose", &req).await;
    let forwarder = PortForwarder {
        mapping: ExposedMapping {
            local: req.local,
            protocol: req.protocol,
        },
        internal_port: mapping.internal_port,
        gate: gate.cloned(),
        revoked: Arc::new(AtomicBool::new(false)),
    };
    handed_bind(control.host_unbinds_declared_forwards(), answer, forwarder)
}

/// Reads the forwarder's answer to a hand-over's expose
/// ([`bind_handed_port`]). `host_holds_listeners` is whether a host-side
/// gate sits in front of the switch
/// ([`ControlChannel::host_unbinds_declared_forwards`]).
fn handed_bind(
    host_holds_listeners: bool,
    answer: io::Result<()>,
    forwarder: PortForwarder,
) -> io::Result<HandedBind> {
    match answer {
        Ok(()) => Ok(HandedBind::Bound(forwarder)),
        Err(error) if host_holds_listeners && is_already_running(&error) => {
            Ok(HandedBind::HeldByHost(forwarder))
        }
        Err(error) => Err(error),
    }
}

/// Removes every forward in `bound` from the switch's `control_sock` (R2.3
/// teardown on PTask exit). Best-effort: a failed unexpose is logged and the
/// rest still attempted, since teardown runs on the session-end path where there
/// is no caller left to propagate to. A bound forward that comes down says one
/// info line (NET-121), naming the port it unbound — the unbind half of the
/// per-forwarder bind/unbind pair the daemon log carries. A forward a
/// revocation already unbound is skipped: the switch holds no forward at its
/// `local` any more, and asking again would read as a teardown failure that
/// is none.
pub async fn remove_ingress(control: &ControlChannel, bound: &[PortForwarder]) {
    for forwarder in bound {
        if forwarder.is_revoked() {
            continue;
        }
        let (host, external_port) = forwarder.host_port().unwrap_or(("", 0));
        let req = UnexposeRequest {
            local: forwarder.mapping.local.clone(),
            protocol: forwarder.mapping.protocol.clone(),
        };
        match unexpose_closing(control, &req).await {
            Ok(closed) => {
                tracing::info!(
                    host,
                    port = external_port,
                    closed_connections = %closed,
                    reason = "box stopped",
                    "unbound ingress forwarder"
                );
            }
            Err(e) => {
                tracing::warn!(
                    local = %forwarder.local(),
                    error = %e,
                    "removing ingress port mapping from switch on PTask exit"
                );
            }
        }
    }
}

/// Unbinds one forward and says whether the switch let it go: the fallible
/// twin of [`remove_ingress`], for a caller that keeps tracking a forward the
/// switch still holds so a later teardown can retry it. A forward already
/// revoked is already down.
pub async fn unexpose_forwarder(
    control: &ControlChannel,
    forwarder: &PortForwarder,
) -> io::Result<()> {
    if forwarder.is_revoked() {
        return Ok(());
    }
    let closed = unexpose_mapping(control, &forwarder.mapping).await?;
    // The callers withdraw an unaudited publish or unbind the forward a move
    // left behind, and each says why in its own line. This line carries the
    // switch's count, and claims no withdrawal.
    let (host, port) = forwarder.mapping.host_port().unwrap_or(("", 0));
    tracing::info!(
        host,
        port,
        protocol = %forwarder.mapping.protocol,
        closed_connections = %closed,
        "unbound a port's forward on the switch"
    );
    Ok(())
}

/// Ends the declared ports' forwards in `bound` when their box stops (NET-121)
/// or when a partial apply rolls back. Who unbinds them depends on the host
/// ([`ControlChannel::host_unbinds_declared_forwards`]):
///
/// - On a native host the daemon asks the switch itself, through
///   [`remove_ingress`].
/// - On a VM-backed host the daemon asks nothing. The host's egress gate
///   refuses any withdrawal of a declared port, by dropping the request
///   unanswered. Asking anyway only produced a misleading "malformed status
///   line" warning per port. The host unbinds the forwards and terminates
///   their connections when it withdraws the box's row. Each forward still
///   gets one info line, so the log keeps NET-121's bind/unbind pair.
pub async fn release_declared_ingress(control: &ControlChannel, bound: &[PortForwarder]) {
    release_declared(control, control.host_unbinds_declared_forwards(), bound).await;
}

/// [`release_declared_ingress`], with `host_unbinds` read off the control
/// channel by the caller.
async fn release_declared(control: &ControlChannel, host_unbinds: bool, bound: &[PortForwarder]) {
    if !host_unbinds {
        remove_ingress(control, bound).await;
        return;
    }
    for forwarder in bound.iter().filter(|forwarder| !forwarder.is_revoked()) {
        let (host, external_port) = forwarder.host_port().unwrap_or(("", 0));
        tracing::info!(
            host,
            port = external_port,
            reason = "box stopped",
            "left the declared ingress forwarder for the host to unbind"
        );
    }
}

/// NET-016's publish: exposes **one** mapping on the switch's forwarder —
/// a port a process in the box is listening on, published at `published`
/// (the box's own address, NET-010) at the port the process listens on,
/// both sides the same number, exactly as a declaration's mapping publishes
/// its external port. Returns the [`ExposedMapping`] that identifies the
/// forward, for [`unexpose_mapping`] when the listener closes.
///
/// The single mapping of the listener watcher, not [`apply_ingress`]: a
/// declaration's forwards are bound once at publish and held until the box
/// stops (NET-121), while these come and go with the processes inside the
/// box (NET-016, NET-017), one at a time, and only after the shared verdict
/// permitted the port. The forward is bound *before* the caller admits the
/// port at the box's gate — the same order the declaration's apply holds —
/// so there is no window in which the gate admits a port nothing answers.
///
/// # Errors
///
/// The expose error, for the caller to say and decide about: the caller
/// keeps the port unadmitted, says the failure once per streak, and retries
/// on the per-port backoff its refusals have earned.
pub async fn expose_mapping(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    port: u16,
) -> io::Result<ExposedMapping> {
    let mapping = PortMapping {
        external_port: port,
        internal_port: port,
        proto: IpProto::Tcp,
    };
    let req = expose_request(&mapping, published, ptask_ip);
    post_json(control, "/services/forwarder/expose", &req)
        .await
        .map(|()| ExposedMapping {
            local: req.local,
            protocol: req.protocol,
        })
}

/// How many accepted connections the switch closed when it unexposed a
/// forward: the `closed` field of the patched switch's `/unexpose` reply
/// (`vendor/gvproxy/patches/`). `None` when the reply carries no count — an
/// unpatched switch, or a channel that relays no body — so the log says
/// unknown rather than zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedConnections(pub Option<u64>);

impl ClosedConnections {
    /// The count in an `/unexpose` reply body, `{"closed":<n>}`.
    fn from_reply(body: &[u8]) -> Self {
        #[derive(serde::Deserialize)]
        struct Reply {
            closed: Option<u64>,
        }
        let text = String::from_utf8_lossy(body);
        let text = text.trim();
        if text.is_empty() {
            return Self(None);
        }
        Self(
            serde_json_lenient::from_str::<Reply>(text)
                .ok()
                .and_then(|reply| reply.closed),
        )
    }
}

impl fmt::Display for ClosedConnections {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(n) => write!(f, "{n}"),
            None => f.write_str("unknown"),
        }
    }
}

/// Asks the switch to unexpose the forward at `req.local`. The switch closes
/// the forward's listener and then every connection that forward accepted
/// and still holds. A forward at another `local` to the same in-box port is
/// a separate forward on the switch, so it keeps its own connections.
async fn unexpose_closing(
    control: &ControlChannel,
    req: &UnexposeRequest,
) -> io::Result<ClosedConnections> {
    post_json_reply_within(
        control,
        "/services/forwarder/unexpose",
        req,
        GVPROXY_CONTROL_TIMEOUT,
    )
    .await
    .map(|body| ClosedConnections::from_reply(&body))
}

/// Unexposes one mapping [`expose_mapping`] bound, and returns the count of
/// accepted connections the switch reports it closed. NET-017's withdraw of
/// a listener that has since closed comes here, so the box's address stops
/// answering at the port. A move, a revoke and a teardown come here too, so
/// this logs nothing: each caller logs its own line, with the count, and
/// only the withdrawal's line ([`log_withdrawal`]) says a port was withdrawn.
///
/// The caller refuses the port at the box's gate *first* — the
/// order [`PortForwarder::revoke`] holds for a declared forward — so no new
/// connection crosses the gap between a listener already gone and a gate
/// that still admits the port. A declared port's forward never comes down
/// this path: it is not the watcher's (NET-081's sub-requirement — a
/// withdrawal applies only to the runtime-published set), and nothing a
/// process closing a listener does can withdraw what the declaration holds.
///
/// # Errors
///
/// The unexpose error, for the caller to say and decide about: a forward
/// that fails to come down still stands at its `local`, so the caller keeps
/// it in its published set — retrying the unexpose on every poll the box
/// still runs and through the passes the stop that ends the watcher makes,
/// and re-admitting the port if its listener returns before they run —
/// never leaving it standing unowned for the switch's lifetime.
pub async fn unexpose_mapping(
    control: &ControlChannel,
    mapping: &ExposedMapping,
) -> io::Result<ClosedConnections> {
    let req = UnexposeRequest {
        local: mapping.local.clone(),
        protocol: mapping.protocol.clone(),
    };
    unexpose_closing(control, &req).await
}

/// NET-017's one line per withdrawal: a published port's listener closed and
/// its forward came down. The box is the caller's span: the listen watcher
/// runs inside one that names it. The line claims closed connections only
/// when the switch reported a count. An unpatched switch reports none, so
/// the line then says the count is not known.
pub fn log_withdrawal(mapping: &ExposedMapping, closed: ClosedConnections) {
    let (host, port) = mapping.host_port().unwrap_or(("", 0));
    if closed.0.is_some() {
        tracing::info!(
            host,
            port,
            protocol = %mapping.protocol,
            closed_connections = %closed,
            "withdrew a published port, and the switch closed the connections it accepted"
        );
    } else {
        tracing::info!(
            host,
            port,
            protocol = %mapping.protocol,
            closed_connections = %closed,
            "withdrew a published port, and the switch did not report how many \
             accepted connections it closed"
        );
    }
}

/// Why a runtime port-publish request was refused **before** the switch was
/// asked anything: the typed error NET-044's deny arm answers with, rather
/// than a bare message, so a caller can tell "this box denies dynamic
/// ingress" from "that port is out of range" without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeRefusal {
    /// The box's `dynamic_ingress` is unset or `deny` — the deny-all default
    /// an absent declaration means.
    DeniedByPolicy,
    /// `dynamic_ingress` is `ask`: the attached human decides (NET-045), and
    /// with nobody attached — or until that prompt path exists — the request
    /// fails closed rather than publishing unasked.
    AskNeedsAnswer,
    /// `dynamic_ingress` is `ask` and the attached human answered no — or
    /// keyed a cancel, which means the same (NET-045): the box's own deny
    /// answer, now in the human's hand. The log and the audit record say it
    /// with the deny's words; the caller's line says who declined.
    DeniedByHuman,
    /// `dynamic_ingress` is `ask` and the VM host's attached client could
    /// not show the dialog — no terminal to draw it on — so the ask ended
    /// in the deny an unanswerable dialog defaults to.
    AskNoTerminal,
    /// `dynamic_ingress` allows, but the box declares no
    /// `dynamic_allowed_range`: no port was opted in.
    NoDynamicRange,
    /// The requested port lies outside the declared `dynamic_allowed_range`.
    OutOfRange { requested: u16, range: (u16, u16) },
    /// The box holds no address the hostname registry published for it, so
    /// there is nowhere to bind. A capability gap: waiting does not fix it.
    NoPublishedAddress,
    /// The box has a published address but no running PTask attached to the
    /// switch — no lease reported yet, or the spawn that held one has ended —
    /// so there is nothing to forward to until the box is started.
    NotAttached,
    /// No box is running behind the session: it was stopped, and its record
    /// still reads `active` — but the publish has nothing to deliver to, and a
    /// forward bound for the lease it would name would answer for nothing.
    /// Starting the box again is what fixes it.
    NotRunning,
    /// The port is held already by this box's other runtime surface — the
    /// reservation or publication that holds it, whichever surface that
    /// is, named by the owner the loser is refused with. While `pending`
    /// is true the hold is a reservation whose publish has not landed
    /// yet: the port is on its way to being published, not there yet.
    AlreadyPublished {
        port: u16,
        owner: super::listeners::PublicationOwner,
        pending: bool,
    },
    /// The port is published already for this box by its own listening
    /// process (NET-016): the publication stands, its gate admits the port,
    /// and it is listed at `local`. The request's goal is met, not refused,
    /// so the in-box caller hears this as a plain message and exits 0. The
    /// request publishes nothing of its own: the publication stays the
    /// listener's, and it is withdrawn when the listener closes (NET-017).
    ListenPublished { port: u16, local: SocketAddr },
    /// The box shares the host's network (`host_ip`), so the port already
    /// answers on the host and there is nothing to publish. The request's
    /// goal is met, not refused, so the in-box caller hears this as a plain
    /// message and exits 0. `host_loopback` says whether the host's own
    /// loopback is one of the places it answers: true on a native host, and
    /// false on a VM-backed one, where the loopback the box shares is the
    /// guest's and the name is the only host-reachable answer (NET-129).
    NeedsNoExposing { port: u16, host_loopback: bool },
}

impl ExposeRefusal {
    /// The line the in-box `min net expose` prints for this refusal: the
    /// verdict and, where a way forward exists, the way forward, named with
    /// the box's current host-side name and the port the request asked for,
    /// so a detached agent reading it has its next command. `network` is the
    /// box's mode: a `--network none` box carries no dynamic ingress at all,
    /// so re-activating with it is no way forward there, and the host-side
    /// forward — which dials inside the box's own namespace — is the one
    /// offered. The verdict alone (`Display`) is what the log line and the
    /// audit record carry.
    #[must_use]
    pub fn for_caller(&self, box_name: &str, network: boxes::NetworkMode, port: u16) -> String {
        let forward = format!("min net forward {box_name} <local>:{port}");
        match self {
            Self::DeniedByPolicy => match network {
                boxes::NetworkMode::NoNet => format!(
                    "{self}: a --network none box has no address to publish at. Forward it \
                     from the host instead: {forward}"
                ),
                // `NetworkMode` is non-exhaustive; every other mode gets the
                // own-address advice.
                _ => format!(
                    "{self}. Re-activate with --network own_ip and --dynamic-ingress allow \
                     --dynamic-range <lo>-<hi> (or --dynamic-ingress ask) to allow it, or \
                     forward it from the host now: {forward}"
                ),
            },
            Self::DeniedByHuman => format!(
                "{self}: the person attached to this session answered no. Ask again, or \
                 forward it from the host: {forward}"
            ),
            Self::AskNoTerminal => format!(
                "{self}: no terminal was attached to answer. Attach one and retry, or \
                 forward it from the host: {forward}"
            ),
            Self::AskNeedsAnswer => format!(
                "{self}: attach a terminal (min session attach {box_name}) and retry, or \
                 have the host forward it ({forward})"
            ),
            Self::NeedsNoExposing {
                host_loopback: true,
                ..
            } => format!(
                "{self}, so it already answers at {box_name}.min.internal:{port} \
                 (and localhost:{port})"
            ),
            Self::NeedsNoExposing {
                host_loopback: false,
                ..
            } => format!("{self}, so it already answers at {box_name}.min.internal:{port}"),
            // The same words for an allow-stance and an ask-stance box: the
            // range refused the port before any prompt (NET-047).
            Self::OutOfRange { .. } => format!("{self}. Nothing was published."),
            // The listener's publication is the one standing, so the
            // caller hears how long it lasts: it is not the request's own.
            Self::ListenPublished { .. } => {
                format!("{self}. It is unpublished when that process stops listening on it.")
            }
            _ => self.to_string(),
        }
    }
}

impl fmt::Display for ExposeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // One verdict for the three denies: the policy's, the human's
            // and the one an unshowable dialog defaults to. The log and the
            // audit record pin these words; the caller's line tells them
            // apart.
            Self::DeniedByPolicy | Self::DeniedByHuman | Self::AskNoTerminal => {
                write!(f, "dynamic ingress is denied for this box")
            }
            Self::AskNeedsAnswer => write!(
                f,
                "dynamic ingress is set to ask and nobody is attached to answer"
            ),
            Self::NoDynamicRange => write!(
                f,
                "this box has no --dynamic-range, so no port can be opened at runtime"
            ),
            Self::OutOfRange { requested, range } => write!(
                f,
                "port {requested} is outside this box's --dynamic-range {}-{}",
                range.0, range.1
            ),
            Self::NoPublishedAddress => write!(
                f,
                "this box was given no address on the host to open a port at"
            ),
            Self::NotAttached => write!(
                f,
                "this box's network is not connected, so no port can be opened on it; \
                 start the box and try again"
            ),
            Self::NotRunning => {
                write!(
                    f,
                    "this box is not running, so there is nothing to open a port on; \
                     start the box and try again"
                )
            }
            Self::AlreadyPublished {
                port,
                owner,
                pending,
            } => {
                let state = if *pending {
                    "is being published"
                } else {
                    "is published already"
                };
                write!(f, "port {port} {state} by this box ({})", owner.as_str())
            }
            Self::ListenPublished { port, local } => write!(
                f,
                "port {port} is published already at {local}, because a process in this box \
                 is listening on it"
            ),
            Self::NeedsNoExposing { port, .. } => write!(
                f,
                "port {port} needs no exposing: this box shares the host's network"
            ),
        }
    }
}

/// Why one runtime port-publish request ended without a publish — the answer
/// the session actor hands its caller, which is what the box's own
/// `min net expose` prints.
#[derive(Debug)]
pub enum ExposeFailure {
    /// The box's `dynamic_ingress` decision refused the port: the switch was
    /// asked nothing, so nothing partial is left behind (NET-047).
    Refused(ExposeRefusal),
    /// The publish could not be made — the switch refused the bind or never
    /// answered. One mapping is one request, so a bind that failed bound
    /// nothing and asked nothing further (NET-047).
    Publish { port: u16, source: io::Error },
    /// The box's own record could not be read to decide the request, so its
    /// name, its policy and its addresses are all unknown. Refused rather
    /// than guessed at: the switch was asked nothing, and nothing was bound
    /// (NET-047). Its own arm — not `Publish` — because a caller that knows
    /// the box's name without the record (the env channel, from the
    /// environment's own name) is the one that can still say whose request
    /// this was in the one line the request owes the log.
    RecordUnreadable { port: u16, source: io::Error },
    /// The session actor dropped the request's reply channel before
    /// answering — the box is stopping or stopped, so nobody is home to
    /// decide it. The switch was asked nothing and nothing was bound. Its
    /// own arm — not `Publish` — because the actor never reached the bind:
    /// a real `ENOTCONN` out of a bind the actor *did* attempt stays a
    /// `Publish`, and conflating the two would log one request twice.
    ActorGone { port: u16 },
}

impl fmt::Display for ExposeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::Publish { port, source } => {
                write!(f, "publishing port {port} failed: {source}")
            }
            Self::RecordUnreadable { port, source } => {
                write!(
                    f,
                    "port {port} was not opened: the session's saved state could \
                     not be read: {source}"
                )
            }
            Self::ActorGone { port } => {
                write!(
                    f,
                    "port {port} was not opened: the box is stopping or stopped"
                )
            }
        }
    }
}

/// Decides one runtime port-publish request against the box's
/// `dynamic_ingress` setting (NET-043): `ingress` is the box's declared
/// ingress half, `None` the deny-all default an absent declaration means.
/// `Ok(DynamicIngress::Allow)` when the box allows the port; the typed
/// refusal saying why not otherwise.
///
/// The stance and the range are [`IngressRules::dynamic_verdict`]'s to
/// derive — the one derivation this decision and the listen watcher's
/// verdict share, so the two runtime ingress surfaces cannot part ways on a
/// port — and this is the half that renders each fact as the refusal the
/// box's `min net expose` prints. An `ask` box's range is checked here too,
/// so a port outside it is refused without a prompt.
pub fn dynamic_ingress_decision(
    ingress: Option<&IngressPolicy>,
    port: u16,
) -> Result<boxes::DynamicIngress, ExposeRefusal> {
    match IngressRules::from_policy(ingress).dynamic_verdict(port) {
        DynamicPortVerdict::Allow => Ok(boxes::DynamicIngress::Allow),
        DynamicPortVerdict::Deny => Err(ExposeRefusal::DeniedByPolicy),
        // An `ask` box with a range refuses a port outside it here, before
        // any prompt is routed: no answer could publish it (NET-047).
        DynamicPortVerdict::Ask => match ingress.and_then(|i| i.dynamic_allowed_range) {
            Some(range) if port < range.0 || port > range.1 => Err(ExposeRefusal::OutOfRange {
                requested: port,
                range,
            }),
            _ => Err(ExposeRefusal::AskNeedsAnswer),
        },
        DynamicPortVerdict::NoRange => Err(ExposeRefusal::NoDynamicRange),
        DynamicPortVerdict::OutOfRange { range } => Err(ExposeRefusal::OutOfRange {
            requested: port,
            range,
        }),
    }
}

/// Publishes one port a process inside the box asked for at runtime
/// (NET-043/NET-044): the box's own port number, at the address its
/// registration handed it, forwarded to its own switch address — the same
/// request shape a declared mapping takes ([`expose_request`]). The caller
/// decides the request with [`dynamic_ingress_decision`] first; this is the
/// publish half only.
///
/// One mapping is one expose request, so the guarantee [`apply_ingress`]
/// buys with a rollback is structural here: a request that fails binds
/// nothing, and there is no earlier forward to roll back — the rejected
/// request leaves no partial mapping (NET-047). The bind's failure says its
/// own line, naming the port and the `local` it tried, the way the declared
/// binds' failures do.
///
/// # Errors
///
/// Returns the I/O error from the failing `expose` call.
pub async fn expose_dynamic(
    control: &ControlChannel,
    published: Ipv4Addr,
    ptask_ip: Ipv4Addr,
    port: u16,
    proto: IpProto,
    gate: Option<&Arc<super::switch::BoxGate>>,
) -> io::Result<PortForwarder> {
    let req = ExposeRequest {
        local: format!("{published}:{port}"),
        remote: format!("{ptask_ip}:{port}"),
        protocol: protocol_str(proto).to_string(),
    };
    match post_json(control, "/services/forwarder/expose", &req).await {
        Ok(()) => Ok(PortForwarder {
            mapping: ExposedMapping {
                local: req.local,
                protocol: req.protocol,
            },
            internal_port: port,
            gate: gate.cloned(),
            revoked: Arc::new(AtomicBool::new(false)),
        }),
        Err(e) => {
            tracing::warn!(
                port,
                local = %req.local,
                error = %e,
                "binding dynamic ingress port failed"
            );
            Err(e)
        }
    }
}

/// NET-123's bind probe, conducted through the forwarder that will publish:
/// the same whole-range walk as the local bind probe in `switch::loopback`,
/// one [`ExposeRequest`] per address of the reserved local range, each
/// released by its unexpose the moment it answers, classified exactly as the
/// local probe classifies its binds — every address bound reads the range
/// present; the first refusal names the first missing alias; anything that
/// is not a bind — a refused request, a stall, an unreachable control
/// channel — reads absent, never present. The first failure's kind tells
/// the two apart: `AddrNotAvailable` is a refusal the forwarder answered,
/// and any other kind is a fault of the channel. The session-start walk
/// keeps a present verdict over a fault (`RangeWalk` in `box_manager`).
///
/// Why a second probe beside the local one: an own-address box's declared
/// ports are bound by the **forwarder**, not by the daemon. On a native host
/// the daemon spawns that forwarder itself, so its own loopback is the
/// publish surface and the local probe is the honest one. On a microVM host
/// the forwarder is the host gvproxy `minvmd` owns, so the publish surface is
/// the *host's* loopback — a machine the daemon inside the guest cannot see,
/// and whose verdict its own `lo` would lie about, since a Linux guest
/// carries the whole `127/8` regardless of what the host carries. The only
/// thing that can measure a bind there is the bind itself, so the probe rides
/// the same control channel the publishes ride and asks the forwarder to do
/// the binding.
///
/// Side-effect-free in the same sense the local probe is: every round ends
/// with the unexpose that releases it, and the probe accepts no connection,
/// so its `remote` — never dialed — is a placeholder. Only the host's
/// loopback is asked anything, and only whether an address binds.
pub(crate) async fn probe_publish_surface(
    control: &ControlChannel,
) -> ::switch::loopback::RangeProbe {
    probe_publish_surface_within(control, RANGE_PROBE_BUDGET, RANGE_PROBE_REQUEST_BUDGET).await
}

/// [`probe_publish_surface`] with the walk's two budgets injected, so the
/// overrun arm and the stalled-round arm are testable at numbers a test can
/// afford: `budget` bounds the whole walk, `request` one request/response
/// round of it.
async fn probe_publish_surface_within(
    control: &ControlChannel,
    budget: Duration,
    request: Duration,
) -> ::switch::loopback::RangeProbe {
    // One walk at a time in this process. The daemon-start walk and each
    // session-start walk ask the same forwarder to bind the same probe port,
    // so a second walk that overlapped the first would read the first's
    // bind as a refusal. The wait is outside the budget: a session-start
    // walk queued behind the daemon-start one still gets its whole walk.
    let mut turn = RANGE_WALK_TURN.lock().await;
    // The addresses at which an earlier walk on this channel may have left
    // its own probe forward bound: an unexpose that failed, or a budget that
    // expired between a round's expose and its unexpose. The forwarder
    // answers `already running` from its own forward table, so a leftover
    // probe forward would read as a held address, and so as bound, on every
    // later walk, even after the host lost the address.
    let held = turn.entry(format!("{control:?}")).or_default();
    let mut probe = ::switch::loopback::RangeProbe::failed_to_run();
    let hosts: Vec<Ipv4Addr> = ::switch::loopback::range_hosts().collect();
    let walk = tokio::time::timeout(budget, async {
        for address in &hosts {
            probe.probed += 1;
            let expose = ExposeRequest {
                local: format!("{address}:{RANGE_PROBE_PORT}"),
                remote: ::switch::loopback::RANGE_PROBE_REMOTE.to_string(),
                protocol: "tcp".to_string(),
            };
            // Marked before the expose, so a budget cut inside this round
            // leaves the address marked for the next walk to release.
            let leftover = !held.insert(*address);
            let mut answer =
                post_json_within(control, "/services/forwarder/expose", &expose, request).await;
            // The VM host's egress gate admits one probe round at a time, and
            // another one is still bound there (#2748): a contention, not an
            // answer about this address. The round waits it out and asks
            // again. Contention that outlasts the walk's budget ends the walk
            // inconclusive, never absent, so it cannot replace a present
            // verdict.
            while answer
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::ResourceBusy)
            {
                tokio::time::sleep(RANGE_PROBE_CONTENTION_WAIT).await;
                answer =
                    post_json_within(control, "/services/forwarder/expose", &expose, request)
                        .await;
            }
            if leftover
                && answer
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::AddrInUse)
            {
                // The holder can be this walk's own earlier probe forward.
                // Release it and ask again, so the round reads the host and
                // not the leftover. Only a probe round binds this port at a
                // marked address, so the release takes no box's forward.
                match release_range_probe(control, &expose.local, request).await {
                    Ok(()) => {
                        tracing::info!(
                            local = %expose.local,
                            "released a loopback range probe forward that an earlier walk left bound",
                        );
                        answer = post_json_within(
                            control,
                            "/services/forwarder/expose",
                            &expose,
                            request,
                        )
                        .await;
                    }
                    Err(error) => {
                        // The leftover stays, so this round cannot vouch for
                        // the address. Read it as the release's own failure.
                        probe.first_failure.get_or_insert((*address, error.kind()));
                        tracing::warn!(
                            local = %expose.local,
                            error = %error,
                            "releasing a leftover loopback range probe forward failed, so the address does not count as bound",
                        );
                        continue;
                    }
                }
            }
            match answer {
                Ok(()) => {
                    probe.bound += 1;
                    match release_range_probe(control, &expose.local, request).await {
                        Ok(()) => {
                            held.remove(address);
                        }
                        Err(error) => {
                            // Best-effort, like teardown's: a probe round left
                            // bound holds one obscure port at one address, while
                            // a walk that stopped here would leave the range
                            // unread — the worse leak by far. The address stays
                            // marked, so the next walk releases it first.
                            tracing::warn!(
                                local = %expose.local,
                                error = %error,
                                "releasing the loopback range probe's forwarder bind failed",
                            );
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    // Something else already holds the probe port at this
                    // address: a box's forward or a host_ip mirror on the same
                    // port. The bind reached the address, so the address
                    // exists and counts as bound (NET-123). Nothing of the
                    // probe's is bound, so no unexpose runs: one would tear
                    // down the holder's forward.
                    held.remove(address);
                    probe.bound += 1;
                    tracing::debug!(
                        local = %expose.local,
                        error = %error,
                        "the loopback range probe port is held at this address, so it counts as bound",
                    );
                }
                Err(error) => {
                    // A refusal the forwarder answered is recorded as the
                    // bind refusal the local probe records, `AddrNotAvailable`:
                    // the host said this address does not bind. Every other
                    // error keeps its own kind (a timeout, a missing socket,
                    // a malformed reply), so a session-start walk can tell a
                    // fault of the channel from an answer about the range.
                    let refused = is_forwarder_refusal(&error);
                    if refused {
                        // A refused bind holds nothing at the address.
                        held.remove(address);
                    }
                    let kind = if refused {
                        io::ErrorKind::AddrNotAvailable
                    } else {
                        error.kind()
                    };
                    probe.first_failure.get_or_insert((*address, kind));
                    if error.kind() == io::ErrorKind::TimedOut {
                        // A control channel that does not answer is not a
                        // fact about the host's loopback at all, so the walk
                        // stops rather than spend the rest of its budget
                        // re-asking a dead one. The verdict is fixed either
                        // way: this round never bound, and one missing
                        // address is the whole range's answer.
                        break;
                    }
                }
            }
        }
    })
    .await;
    if walk.is_err() && probe.probed < hosts.len() {
        // The walk outran its budget mid-range: read it as the local probe
        // reads a partial alias set, never as present. Widening the probed
        // count to the whole range makes `present` demand every address it
        // never reached, and the address whose round the budget expired
        // inside is named as the record's first failure — where the vouching
        // stopped.
        let stuck = hosts
            .get(probe.probed.saturating_sub(1))
            .copied()
            .or_else(|| hosts.first().copied())
            .expect("the reserved range's usable-host list is never empty");
        probe.probed = hosts.len();
        probe
            .first_failure
            .get_or_insert((stuck, io::ErrorKind::TimedOut));
    } else if walk.is_err()
        && let Some(last) = hosts.last()
    {
        // The budget expired inside the last round: the same overrun.
        probe
            .first_failure
            .get_or_insert((*last, io::ErrorKind::TimedOut));
    }
    probe
}

/// Releases the range probe's forward at `local` (`POST
/// /services/forwarder/unexpose`), within the walk's round bound.
async fn release_range_probe(
    control: &ControlChannel,
    local: &str,
    request: Duration,
) -> io::Result<()> {
    let unexpose = UnexposeRequest {
        local: local.to_string(),
        protocol: "tcp".to_string(),
    };
    post_json_within(control, "/services/forwarder/unexpose", &unexpose, request).await
}

/// A gvproxy DNS zone-add request body for `POST /services/dns/add`
/// (gvproxy's `types.Zone`): registers `records` under the DNS zone `name`.
///
/// gvproxy merges on re-add with newest-first precedence and resolves to the
/// first matching record, so re-registering a name with a new IP makes the
/// newest win — how a rotated lease is picked up with no remove verb.
#[derive(Debug, Serialize)]
struct DnsZone {
    name: String,
    records: Vec<DnsRecord>,
}

/// A single `name → ip` answer within a [`DnsZone`].
#[derive(Debug, Serialize)]
struct DnsRecord {
    name: String,
    ip: String,
}

/// Registers the PTask's box name `<session_name>` — with the deprecated
/// three-label form `<session_name>.<host_id>` beside it (NET-002) — in
/// gvproxy's `min.internal.` DNS zone, pointing at its current switch lease
/// (finding #3 / UC6).
///
/// gvproxy's resolver is the switch gateway (`100.64.0.1`) that every own-IP
/// sandbox's `resolv.conf` already targets, so this makes a PTask's
/// `*.min.internal` hostname resolvable *from a peer session* — with no new
/// resolver process and no `resolv.conf` change. The zone `Name` carries the
/// trailing dot gvproxy matches DNS queries against; the record labels are
/// lowercased (gvproxy matches labels case-sensitively).
///
/// # Errors
///
/// Returns the I/O error from the gvproxy control request (non-2xx or transport).
pub async fn register_dns_name(
    control: &ControlChannel,
    host_id: &str,
    session_name: &str,
    lease_ip: Ipv4Addr,
) -> io::Result<()> {
    post_json(
        control,
        "/services/dns/add",
        &dns_add_body(host_id, session_name, lease_ip),
    )
    .await
}

/// Builds the `/services/dns/add` zone body for a PTask. Split out so the exact
/// wire shape (trailing-dot zone, lowercased label, dotted-quad IP) is unit-testable
/// without a live gvproxy. It carries both names the zone answers for: the
/// two-label box name `<session>` (NET-001), and the deprecated three-label
/// form `<session>.<host-id>` beside it (NET-002, answered for one release) —
/// both pointing at the same lease.
fn dns_add_body(host_id: &str, session_name: &str, lease_ip: Ipv4Addr) -> DnsZone {
    DnsZone {
        name: format!("{}.", crate::net::dns::HOSTNAME_SUFFIX),
        records: vec![
            DnsRecord {
                name: session_name.to_ascii_lowercase(),
                ip: lease_ip.to_string(),
            },
            DnsRecord {
                name: format!("{session_name}.{host_id}").to_ascii_lowercase(),
                ip: lease_ip.to_string(),
            },
        ],
    }
}

/// `POST`s `body` as JSON to `path` on gvproxy's control socket over a fresh
/// HTTP/1.1 keep-alive connection, succeeding on a 2xx status.
///
/// gvproxy's control socket speaks HTTP; the relay's `POST /connect` upgrade in
/// [`switch`](super::switch) is the data-plane verb, while the forwarder verbs
/// here are ordinary request/response. The exchange is framed by `Content-Length`
/// (not read-to-EOF) with **no** `Connection: close`, so the server never closes
/// the socket first — required for the response to survive the KVM vsock shuttle
/// (see [`exchange`] and the request-builder comment below for the G-N8 detail).
pub(crate) async fn post_json<T: Serialize>(
    control: &ControlChannel,
    path: &str,
    body: &T,
) -> io::Result<()> {
    post_json_within(control, path, body, GVPROXY_CONTROL_TIMEOUT).await
}

/// [`post_json`] with the exchange's bound injected: the publish verbs run at
/// [`GVPROXY_CONTROL_TIMEOUT`], while the range probe's walk runs at its own
/// tighter [`RANGE_PROBE_REQUEST_BUDGET`] — one round per address of the range
/// is not a launch-path request to a live box, and a channel that cannot answer
/// one round in that bound is not a fact about the host's loopback either way.
pub(crate) async fn post_json_within<T: Serialize>(
    control: &ControlChannel,
    path: &str,
    body: &T,
    timeout: Duration,
) -> io::Result<()> {
    post_json_reply_within(control, path, body, timeout)
        .await
        .map(drop)
}

/// [`post_json_within`] that hands back the body of a 2xx reply, for a verb
/// whose answer carries data: the patched switch's `/unexpose` says how many
/// accepted connections it closed.
async fn post_json_reply_within<T: Serialize>(
    control: &ControlChannel,
    path: &str,
    body: &T,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let body = serde_json_lenient::to_vec(body).map_err(io::Error::other)?;
    let mut request = Vec::with_capacity(128 + body.len());
    // HTTP/1.1 keep-alive (no `Connection: close`): gvproxy must respond *without*
    // closing the connection. On the KVM libkrun `add_vsock_port2(listen=false)`
    // shuttle, a server-initiated close drops the still-buffered response bytes as
    // it propagates to the guest (the guest reads an immediate EOF → 0 bytes →
    // `malformed gvproxy status line: ""`, even though the forward *was* applied —
    // G-N8). Keeping the connection open lets the response drain to the guest,
    // which then reads exactly `Content-Length` bytes and closes from its side.
    request.extend_from_slice(format!("POST {path} HTTP/1.1\r\n").as_bytes());
    request.extend_from_slice(b"Host: localhost\r\n");
    request.extend_from_slice(b"Content-Type: application/json\r\n");
    request.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    request.extend_from_slice(b"\r\n");
    request.extend_from_slice(&body);

    // Bound the whole exchange: a gvproxy that accepts the socket and then
    // stalls must not hang the launch or teardown path indefinitely. The control
    // socket is local (DM2) or the host gvproxy over vsock (DM1/3/4); both speak
    // the same HTTP/1.0 request/response on a fresh connection.
    let response = tokio::time::timeout(timeout, async {
        match control {
            ControlChannel::Unix(sock) => {
                exchange(UnixStream::connect(sock).await?, &request).await
            }
            ControlChannel::Vsock { cid, port } => {
                let stream = VsockStream::connect(VsockAddr::new(*cid, *port)).await?;
                exchange(stream, &request).await
            }
        }
    })
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("gvproxy {path} control request timed out after {timeout:?}"),
        )
    })??;

    let status = parse_status_code(&response)?;
    if (200..300).contains(&status) {
        Ok(body_after_headers(&response).to_vec())
    } else {
        let said = String::from_utf8_lossy(body_after_headers(&response));
        // A refusal that says the listener is already held, by another host
        // process (the OS's bind text) or by a forward this forwarder already
        // runs, carries `AddrInUse`: the address exists, and a caller that
        // reads the kind (the range walk) can tell it from a missing one.
        let kind = if status == 500
            && (said.contains(ADDRESS_IN_USE_BODY) || said.contains(ALREADY_RUNNING_BODY))
        {
            io::ErrorKind::AddrInUse
        } else if status == RANGE_PROBE_CONTENTION_STATUS {
            // The VM host's egress gate holds another range probe round and
            // admits one at a time (#2748). gvproxy itself never answers 409,
            // so this says nothing about the host's loopback: the walk waits
            // it out.
            io::ErrorKind::ResourceBusy
        } else {
            io::ErrorKind::Other
        };
        Err(io::Error::new(
            kind,
            ForwarderRefusal(format!("gvproxy {path} returned HTTP {status}: {said}")),
        ))
    }
}

/// The error a control request carries when the forwarder answered with a
/// non-2xx status: the forwarder was reached and said no. The range walk
/// reads it apart from a fault of the channel itself (a timeout, a missing
/// socket, a malformed reply), because only an answer is a fact about the
/// host's loopback (NET-123).
#[derive(Debug)]
struct ForwarderRefusal(String);

impl std::fmt::Display for ForwarderRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ForwarderRefusal {}

/// Whether `error` is a [`ForwarderRefusal`]: the forwarder answered the
/// request and refused it.
fn is_forwarder_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<ForwarderRefusal>())
}

/// Writes `request` to a freshly-connected control stream and reads the response
/// framed by its `Content-Length`. Transport-agnostic so the unix (DM2) and vsock
/// (DM1/3/4) control channels share one exchange.
///
/// We must **not** read to EOF: the request is HTTP/1.1 keep-alive (see
/// [`post_json`]), so gvproxy holds the connection open after responding and an
/// EOF-terminated read would block until the [`GVPROXY_CONTROL_TIMEOUT`]. Instead
/// we read the status line + headers, take `Content-Length` body bytes, and let
/// the caller drop the stream (closing from the *guest* side). This avoids the
/// server-initiated close that the KVM libkrun vsock splice mishandles by dropping
/// the buffered response (G-N8). We deliberately do not `shutdown()` the write
/// side for the same reason.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    stream.write_all(request).await?;

    // Read incrementally until the header terminator is in hand, capping total
    // buffered bytes: gvproxy's forwarder replies are tiny, so a stream that never
    // completes its headers within the bound is misbehaving.
    let mut response = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    let header_end = loop {
        if let Some(i) = find_header_end(&response) {
            break i;
        }
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            return Err(io::Error::other(
                "gvproxy control response exceeded the size cap before its headers ended",
            ));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // EOF before headers completed — the empty-reply symptom the
            // keep-alive framing is meant to avoid; surface it as-is.
            return Ok(response);
        }
        response.extend_from_slice(&buf[..n]);
    };

    // Body length from `Content-Length` (0 if absent). Read until the body is
    // fully buffered, so we never depend on a server close to signal completion.
    let want = content_length(&response[..header_end]).unwrap_or(0);
    let body_have = response.len() - header_end;
    let mut remaining = want.saturating_sub(body_have);
    while remaining > 0 {
        if response.len() as u64 >= MAX_CONTROL_RESPONSE {
            break;
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&buf[..n]);
        remaining = remaining.saturating_sub(n);
    }
    Ok(response)
}

/// Parses the numeric status code from an HTTP response's status line
/// (`HTTP/1.x <code> <reason>`).
fn parse_status_code(response: &[u8]) -> io::Result<u16> {
    let line_end = response
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(response.len());
    let line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| io::Error::other("gvproxy response status line was not UTF-8"))?;
    line.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::other(format!("malformed gvproxy status line: {line:?}")))
}

/// Index just past the `\r\n\r\n` header terminator, or `None` if the headers are
/// not yet fully buffered.
fn find_header_end(response: &[u8]) -> Option<usize> {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// The `Content-Length` header value parsed from a response's header block, or
/// `None` if the header is absent or unparseable (treated as a zero-length body).
fn content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers).ok()?.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })
}

/// Returns the body bytes following the blank line that ends the headers, or the
/// whole buffer if no header terminator is found (best-effort, for diagnostics).
fn body_after_headers(response: &[u8]) -> &[u8] {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(response, |i| &response[i + 4..])
}

/// Upper bound on a single gvproxy control request (expose/unexpose). The
/// control socket can accept the connection and then stall or never close;
/// without a bound, teardown's `remove_ingress` would block forever before the
/// switch `detach`, leaving the PTask attached and its forwards present.
const GVPROXY_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on bytes buffered from a single gvproxy control response. The
/// forwarder's replies are a status line plus a tiny body, so 64 KiB is far
/// above any legitimate response while capping memory if a misbehaving socket
/// streams without closing inside the [`GVPROXY_CONTROL_TIMEOUT`] window.
const MAX_CONTROL_RESPONSE: u64 = 64 * 1024;

/// The port the forwarder-conducted range probe binds each address of the
/// reserved local range at while asking the host whether the range is
/// publishable (NET-123): fixed and deliberately obscure, so no box's
/// declaration is likely to name it, and released by the unexpose that ends
/// each probe round before the next address takes it. Exactly one daemon
/// probes a given forwarder — the one that publishes through it, and a host
/// gvproxy has one of those (the second-daemon-on-a-host shape is native,
/// where the local bind probe runs instead) — so no concurrent walk can
/// collide on it. That daemon walks at its start and again at each session
/// start, and [`RANGE_WALK_TURN`] runs those walks one at a time. A round
/// that finds the port already held at an address (a box's forward or a
/// host_ip mirror) counts that address as bound. The host-side egress gate
/// of a VM-backed host admits each round by this port and
/// [`::switch::loopback::RANGE_PROBE_REMOTE`].
const RANGE_PROBE_PORT: u16 = ::switch::loopback::RANGE_PROBE_PORT;

/// The turn every forwarder-conducted range walk in this process takes
/// before its first round, so the daemon-start walk and the session-start
/// walks never bind [`RANGE_PROBE_PORT`] at the same time. It also keeps,
/// per control channel, the addresses at which a walk may have left its own
/// probe forward bound, so the next walk releases that forward before it
/// reads the address.
static RANGE_WALK_TURN: tokio::sync::Mutex<BTreeMap<String, BTreeSet<Ipv4Addr>>> =
    tokio::sync::Mutex::const_new(BTreeMap::new());

/// Upper bound on the whole forwarder-conducted range walk — the backstop for
/// the one pathology the per-request [`GVPROXY_CONTROL_TIMEOUT`] cannot
/// price: a forwarder that keeps answering, but slowly, once per address
/// across the range. A walk that outruns it is read exactly as it stopped:
/// the addresses it never reached are the ones it cannot vouch for, so the
/// range reads absent, the interim.
const RANGE_PROBE_BUDGET: Duration = Duration::from_secs(20);

/// The status the VM host's egress gate answers a range probe round with
/// while another round is still bound there (#2748). gvproxy itself never
/// answers it.
const RANGE_PROBE_CONTENTION_STATUS: u16 = 409;

/// How long a contended range probe round waits before it asks again. The
/// gate releases a round left bound within seconds, and the walk's whole
/// budget bounds the waiting.
const RANGE_PROBE_CONTENTION_WAIT: Duration = Duration::from_millis(250);

/// Upper bound on **one** request/response round of the forwarder-conducted
/// range walk — tighter than the [`GVPROXY_CONTROL_TIMEOUT`] the publish verbs
/// run under, because the probe is a walk, two rounds per address of the range
/// on one channel, and a round that does not answer inside this bound is a
/// channel with no fact to give about the host's loopback: the walk stops there
/// and the range reads absent, the interim. A forwarder that answers at all
/// answers in milliseconds — a bind and its release — so the bound costs a live
/// host nothing, while a stalled one is read for what it is a second rather
/// than after the publish verbs' five.
const RANGE_PROBE_REQUEST_BUDGET: Duration = Duration::from_secs(1);

/// Minimum gap between emitted policy-violation warnings: one minute, matching
/// R2.2's "first drop per PTask per rule per minute" rate-limit window, so a
/// flood of dropped frames cannot spam the log.
const WARN_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// Which direction a policy violation occurred in, for R2.7's `direction`
/// structured field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outbound traffic from the PTask (an egress-policy violation).
    Egress,
    /// Inbound traffic to the PTask (an ingress-policy violation).
    Ingress,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
        })
    }
}

/// The transport a policy-violating frame is logged under, for R2.7's `proto`
/// structured field.
///
/// Wider than [`IpProto`] because a dropped frame is not always an IP packet
/// whose protocol number is one of the three a policy can name: IPv6 is
/// dropped as a whole family (NET-082) with no single L4 protocol to name, a
/// truncated or non-IP frame has no header to read one from, and a policy can
/// be violated by a protocol Minimal does not model (any other IPv4 number).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// `IpProto::Tcp` — IPv4 protocol 6.
    Tcp,
    /// `IpProto::Udp` — IPv4 protocol 17.
    Udp,
    /// `IpProto::Icmp` — IPv4 protocol 1.
    Icmp,
    /// Any other IPv4 protocol number, logged as `ip-<number>`.
    Other(u8),
    /// An IPv6 frame, dropped as a family (NET-082) before any L4 protocol is
    /// read.
    Ipv6,
    /// Nothing to name: a frame with no IPv4 header to read a protocol from
    /// (a truncated or non-IP frame), or a protocol Minimal does not model
    /// under a name.
    None,
}

impl Proto {
    /// The transport Minimal's policies name, for a frame whose protocol is
    /// one of the three declared ones. `IpProto` is `#[non_exhaustive]`, so a
    /// variant a later sessions adds has no rendering here yet and logs as
    /// `none` — the drop still names its rule.
    #[must_use]
    pub fn from_ipproto(proto: IpProto) -> Self {
        match proto {
            IpProto::Tcp => Self::Tcp,
            IpProto::Udp => Self::Udp,
            IpProto::Icmp => Self::Icmp,
            _ => Self::None,
        }
    }

    /// The transport of an IPv4 frame carrying protocol number `number`: the
    /// three declared protocols by name, any other number by number.
    #[must_use]
    pub fn from_ipv4_number(number: u8) -> Self {
        match number {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 => Self::Icmp,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Other(n) => write!(f, "ip-{n}"),
            Self::Ipv6 => f.write_str("ipv6"),
            Self::None => f.write_str("none"),
        }
    }
}

/// Rate-limited emitter plumbing for policy-violation warnings (R2.7).
///
/// The rate limit is keyed by **box and rule** (NET-062: "first drop per
/// PTask per rule per minute"): one box's flood never silences another box's
/// single drop, and a box hitting several rules in the same minute is still
/// heard once per rule. The relay's egress enforcement
/// ([`switch`](super::switch)) and its ingress counterpart share one limiter
/// per session gate, each under its own rule key — with the one exception
/// that a DNS refusal adds the refused name to its key
/// ([`warn_dns_refusal`](Self::warn_dns_refusal)), because its requirement
/// is the name and the answer per refusal.
#[derive(Debug, Default)]
pub struct PolicyWarnLimiter {
    last: Mutex<HashMap<String, HashMap<String, Instant>>>,
}

impl PolicyWarnLimiter {
    /// A fresh limiter that has never emitted for any box or rule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether enough time has elapsed since the last emission for `session_id`
    /// under `rule` to warn again at `now`, recording `now` as that pair's last
    /// emission when it returns `true`.
    ///
    /// Split from [`warn`](Self::warn) so the rate-limit decision is testable
    /// without a real clock or a `tracing` subscriber.
    #[must_use]
    pub fn should_warn_at(&self, session_id: &str, rule: &str, now: Instant) -> bool {
        let mut last = self.last.lock().expect("PolicyWarnLimiter mutex poisoned");
        let Some(emit) = last.get_mut(session_id) else {
            last.entry(session_id.to_string())
                .or_default()
                .insert(rule.to_string(), now);
            return true;
        };
        match emit.get(rule) {
            Some(prev) if now.duration_since(*prev) < WARN_MIN_INTERVAL => false,
            _ => {
                emit.insert(rule.to_string(), now);
                true
            }
        }
    }

    /// Emits a rate-limited `tracing::warn!` for a policy violation, carrying
    /// R2.7's required structured fields: the `session_id`, the `direction` of
    /// the offending traffic, the `remote_addr` it was to/from (rendered as
    /// `none` when the frame had no IP destination to read, as for an IPv6 or
    /// truncated drop), its `proto`, the `dst_port` the traffic targeted
    /// (`None` when the drop is not about a port), and the `rule_matched`.
    /// The port is a structured field only, never part of `rule_matched`: it
    /// must not fragment the per-rule rate-limit key. Returns whether a warning
    /// was emitted (vs. suppressed by the rate limit).
    pub fn warn(
        &self,
        session_id: &str,
        direction: Direction,
        remote_addr: Option<SocketAddr>,
        proto: Proto,
        dst_port: Option<u16>,
        rule_matched: &str,
    ) -> bool {
        if self.should_warn_at(session_id, rule_matched, Instant::now()) {
            let remote_addr = remote_addr.map_or_else(|| "none".to_string(), |a| a.to_string());
            tracing::warn!(
                session_id,
                %direction,
                %remote_addr,
                %proto,
                dst_port,
                rule_matched,
                "network policy violation"
            );
            true
        } else {
            false
        }
    }

    /// Emits a rate-limited `tracing::warn!` for a DNS answer the rebinding
    /// intersection refused (NET-067): an address a name the box's policy
    /// allowed resolved into the box's `deny_subnets` or the infrastructure
    /// deny set, and so is never admitted — the name and the answer, the two
    /// things the spec requires the refusal to carry.
    ///
    /// Rate-limited per **box, name and rule**, not per box and rule like
    /// [`warn`](Self::warn): the requirement is the name and the answer per
    /// refusal, so a second refused name inside the interval is its own line
    /// rather than silenced by the first's, while a burst of the *same*
    /// name's refusals stays one line per rule. The limiter's key is built
    /// from both, and the `rule_matched` field it logs is the rule alone.
    pub fn warn_dns_refusal(
        &self,
        session_id: &str,
        name: &str,
        answer: Ipv4Addr,
        rule_matched: &str,
    ) -> bool {
        let key = format!("{rule_matched}:{name}");
        if self.should_warn_at(session_id, &key, Instant::now()) {
            tracing::warn!(
                session_id,
                name,
                %answer,
                rule_matched,
                "an allowed name resolved into a refused range"
            );
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_add_body_matches_gvproxy_zone_shape() {
        // The zone Name carries a trailing dot (gvproxy matches DNS queries, which
        // are trailing-dotted, against it); the record labels are lowercased
        // (gvproxy matches labels case-sensitively); the IP is dotted-quad. Both
        // the two-label box name and the deprecated three-label form are
        // registered, pointing at the same lease.
        let body = dns_add_body("Local", "Web", Ipv4Addr::new(100, 64, 0, 5));
        let json = serde_json_lenient::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"name":"min.internal.","records":[{"name":"web","ip":"100.64.0.5"},{"name":"web.local","ip":"100.64.0.5"}]}"#
        );
    }

    #[test]
    fn expose_request_maps_host_port_to_ptask_ip() {
        // R2.3/R2.4-static: external_port forwards to the PTask's switch IP on
        // internal_port; the local host is the box's own loopback address
        // (NET-010) so only the host can connect.
        let mapping = PortMapping {
            external_port: 18080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let published = Ipv4Addr::new(127, 0, 64, 9);
        let req = expose_request(&mapping, published, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(req.local, "127.0.64.9:18080");
        assert_eq!(req.remote, "100.64.0.2:80");
        assert_eq!(req.protocol, "tcp");
    }

    #[test]
    fn expose_request_serializes_to_gvproxy_fields() {
        let mapping = PortMapping {
            external_port: 5353,
            internal_port: 53,
            proto: IpProto::Udp,
        };
        // A box with no address of its own publishes on the node's shared
        // one, still at its own port numbers (NET-123's interim, NET-129).
        let req = expose_request(&mapping, Ipv4Addr::LOCALHOST, Ipv4Addr::new(100, 64, 0, 7));
        let json = serde_json_lenient::to_string(&req).unwrap();
        assert!(json.contains("\"local\":\"127.0.0.1:5353\""), "got: {json}");
        assert!(json.contains("\"remote\":\"100.64.0.7:53\""), "got: {json}");
        assert!(json.contains("\"protocol\":\"udp\""), "got: {json}");
    }

    #[test]
    fn refusals_name_the_way_forward_for_the_caller() {
        use boxes::NetworkMode;

        // The in-box line carries the verdict and the next command, named
        // with the host-side box name and the port asked for; the verdict
        // alone is what the log and the audit record keep.
        assert_eq!(
            ExposeRefusal::DeniedByPolicy.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box. Re-activate with --network own_ip and \
             --dynamic-ingress allow --dynamic-range <lo>-<hi> (or --dynamic-ingress ask) \
             to allow it, or forward it from the host now: min net forward web <local>:3001"
        );
        // A `--network none` box cannot carry dynamic ingress, so the only
        // way forward is the host's forward, which dials inside the box.
        assert_eq!(
            ExposeRefusal::DeniedByPolicy.for_caller("web", NetworkMode::NoNet, 3001),
            "dynamic ingress is denied for this box: a --network none box has no address \
             to publish at. Forward it from the host instead: min net forward web \
             <local>:3001"
        );
        // The three denies share the verdict and differ in the way forward.
        assert_eq!(
            ExposeRefusal::DeniedByHuman.to_string(),
            ExposeRefusal::DeniedByPolicy.to_string()
        );
        assert_eq!(
            ExposeRefusal::AskNoTerminal.to_string(),
            ExposeRefusal::DeniedByPolicy.to_string()
        );
        assert_eq!(
            ExposeRefusal::DeniedByHuman.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box: the person attached to this session \
             answered no. Ask again, or forward it from the host: min net forward web \
             <local>:3001"
        );
        assert_eq!(
            ExposeRefusal::AskNoTerminal.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is denied for this box: no terminal was attached to answer. \
             Attach one and retry, or forward it from the host: min net forward web \
             <local>:3001"
        );
        assert_eq!(
            ExposeRefusal::AskNeedsAnswer.for_caller("web", NetworkMode::OwnIp, 3001),
            "dynamic ingress is set to ask and nobody is attached to answer: attach a \
             terminal (min session attach web) and retry, or have the host forward it \
             (min net forward web <local>:3001)"
        );
        // Natively the host's loopback answers too; on a VM-backed host the
        // loopback the box shares is the guest's, so only the name is named.
        assert_eq!(
            ExposeRefusal::NeedsNoExposing {
                port: 3001,
                host_loopback: true
            }
            .for_caller("web", NetworkMode::HostNet, 3001),
            "port 3001 needs no exposing: this box shares the host's network, so it \
             already answers at web.min.internal:3001 (and localhost:3001)"
        );
        assert_eq!(
            ExposeRefusal::NeedsNoExposing {
                port: 3001,
                host_loopback: false
            }
            .for_caller("web", NetworkMode::HostNet, 3001),
            "port 3001 needs no exposing: this box shares the host's network, so it \
             already answers at web.min.internal:3001"
        );
        // The hold a port loses to is one watch in either of its two
        // states: the publication it stands on, or the reservation still
        // on its way there. Each state is its own verdict, and the in-box
        // line names it the same way the log does.
        assert_eq!(
            ExposeRefusal::AlreadyPublished {
                port: 3001,
                owner: crate::net::listeners::PublicationOwner::Listen,
                pending: false
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is published already by this box (listen)"
        );
        assert_eq!(
            ExposeRefusal::AlreadyPublished {
                port: 3001,
                owner: crate::net::listeners::PublicationOwner::Listen,
                pending: true
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is being published by this box (listen)"
        );
        // A port the box's own listener published is the goal met: the
        // line says where it answers, and that the publication is the
        // listener's, which goes when the listener does.
        assert_eq!(
            ExposeRefusal::ListenPublished {
                port: 3001,
                local: SocketAddr::from(([127, 0, 64, 9], 3001)),
            }
            .for_caller("web", NetworkMode::OwnIp, 3001),
            "port 3001 is published already at 127.0.64.9:3001, because a process in this \
             box is listening on it. It is unpublished when that process stops listening on it."
        );
        // A refusal with no way forward beyond its own words is its verdict.
        assert_eq!(
            ExposeRefusal::NoDynamicRange.for_caller("web", NetworkMode::OwnIp, 3001),
            ExposeRefusal::NoDynamicRange.to_string()
        );
    }

    #[test]
    fn dynamic_ingress_decision_denies_the_absent_and_explicit_deny() {
        // NET-043: the setting decides, and an absent declaration is the
        // deny-all default — the two shapes a request from inside a bare box
        // meets.
        let allow = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(None, 3000),
            Err(ExposeRefusal::DeniedByPolicy),
            "a box that declared no ingress denies every runtime publish"
        );
        let deny = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Deny),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&deny), 3000),
            Err(ExposeRefusal::DeniedByPolicy),
        );
        assert_eq!(
            dynamic_ingress_decision(Some(&allow), 3000),
            Ok(boxes::DynamicIngress::Allow),
        );
    }

    #[test]
    fn absent_dynamic_ingress_is_deny() {
        // NET-043: an absent stance is not a permission waiting to be read.
        // A declaration can carry a range — or even a mode-allow's range
        // with the mode itself never spelled — and still deny every runtime
        // publish, exactly as an explicit deny does: the stance is the fact
        // the decision turns on, and only a spelled `allow` is an allow.
        let absent = IngressPolicy {
            dynamic_ingress: None,
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        let explicit = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Deny),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        for port in [2999, 3000, 3500, 3999, 4000] {
            assert_eq!(
                dynamic_ingress_decision(Some(&absent), port),
                dynamic_ingress_decision(Some(&explicit), port),
                "an absent stance must decide exactly as the explicit deny at port {port}"
            );
            assert_eq!(
                dynamic_ingress_decision(Some(&absent), port),
                Err(ExposeRefusal::DeniedByPolicy),
                "an absent stance denies the runtime publish at port {port}"
            );
        }
        // The whole-declaration absence — the bare box's shape — denies the
        // same way, so the deny is a property of the stance, not of the
        // declaration around it.
        assert_eq!(
            dynamic_ingress_decision(None, 3000),
            Err(ExposeRefusal::DeniedByPolicy),
            "a box with no ingress declaration denies the runtime publish"
        );
    }

    #[test]
    fn dynamic_ingress_decision_gates_on_the_declared_range() {
        // NET-047: an allowed request still has to be in the range the box
        // opted in — the bounds are inclusive, unset means nothing was opted
        // in, and `ask` fails closed with nobody to answer it.
        let allow = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        for port in [2999, 4000] {
            assert_eq!(
                dynamic_ingress_decision(Some(&allow), port),
                Err(ExposeRefusal::OutOfRange {
                    requested: port,
                    range: (3000, 3999),
                }),
                "port {port} is outside the range and must be refused by name"
            );
        }
        for port in [3000, 3999] {
            assert_eq!(
                dynamic_ingress_decision(Some(&allow), port),
                Ok(boxes::DynamicIngress::Allow),
                "the range's own bounds are inside it"
            );
        }
        let no_range = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Allow),
            dynamic_allowed_range: None,
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&no_range), 3000),
            Err(ExposeRefusal::NoDynamicRange),
        );
        let ask = IngressPolicy {
            dynamic_ingress: Some(boxes::DynamicIngress::Ask),
            dynamic_allowed_range: Some((3000, 3999)),
            ..Default::default()
        };
        assert_eq!(
            dynamic_ingress_decision(Some(&ask), 3000),
            Err(ExposeRefusal::AskNeedsAnswer),
        );
    }

    #[test]
    fn expose_and_listen_share_one_verdict() {
        // `min net expose` and the listen watcher are two runtime ingress
        // surfaces over one box, so the stance and the range they read are
        // one derivation ([`IngressRules::dynamic_verdict`]), and this pins
        // the two surfaces to it over every shape the box's declaration can
        // take: absent stance, deny, ask, allow; absent range and one opted
        // in; in-range at both bounds and out-of-range at either edge.
        //
        // The declaration is the listen verdict's own half (NET-121), so
        // every policy below declares nothing: on these rows the verdict is
        // `Publish` or `Deny`, and `Publish` holds exactly where the expose
        // decision allows.
        use boxes::DynamicIngress;
        use boxes::core::egress::ListenVerdict;

        const LOW: u16 = 3000;
        const HIGH: u16 = 3010;
        let stances = [
            (None, "absent"),
            (Some(DynamicIngress::Deny), "deny"),
            (Some(DynamicIngress::Ask), "ask"),
            (Some(DynamicIngress::Allow), "allow"),
        ];
        let ranges = [(None, "no range"), (Some((LOW, HIGH)), "3000-3010")];
        for port in [LOW - 1, LOW, HIGH, HIGH + 1] {
            for (stance, stance_name) in stances {
                for (range, range_name) in ranges {
                    let ingress = IngressPolicy {
                        dynamic_ingress: stance,
                        dynamic_allowed_range: range,
                        ..Default::default()
                    };
                    let decision = dynamic_ingress_decision(Some(&ingress), port);
                    let listen = IngressRules::from_policy(Some(&ingress))
                        .listen_verdict(IpProto::Tcp, port);
                    // The agreement the shared derivation buys: the watcher
                    // publishes exactly the ports the expose decision allows.
                    let allowed = decision == Ok(DynamicIngress::Allow);
                    let expected_listen = if allowed {
                        ListenVerdict::Publish
                    } else {
                        ListenVerdict::Deny
                    };
                    assert_eq!(
                        listen, expected_listen,
                        "stance {stance_name}, range {range_name}, port {port}"
                    );
                    // And the refusal names its own fact, stance before
                    // range, in the words `min net expose` prints.
                    let expected_decision = match stance {
                        None | Some(DynamicIngress::Deny) => Err(ExposeRefusal::DeniedByPolicy),
                        Some(DynamicIngress::Ask) => match range {
                            Some((low, high)) if port < low || port > high => {
                                Err(ExposeRefusal::OutOfRange {
                                    requested: port,
                                    range: (low, high),
                                })
                            }
                            _ => Err(ExposeRefusal::AskNeedsAnswer),
                        },
                        Some(DynamicIngress::Allow) => match range {
                            None => Err(ExposeRefusal::NoDynamicRange),
                            Some((low, high)) if low <= port && port <= high => {
                                Ok(DynamicIngress::Allow)
                            }
                            Some(range) => Err(ExposeRefusal::OutOfRange {
                                requested: port,
                                range,
                            }),
                        },
                    };
                    assert_eq!(
                        decision, expected_decision,
                        "stance {stance_name}, range {range_name}, port {port}"
                    );
                }
            }
        }
    }

    #[test]
    fn expose_refusals_render_their_own_reasons() {
        // The typed refusal is what the box's `min net expose` prints, so
        // each message must name the fact that decided it — not a generic
        // "refused".
        let refusal = ExposeRefusal::OutOfRange {
            requested: 80,
            range: (3000, 3999),
        };
        let rendered = refusal.to_string();
        assert!(rendered.contains("80"), "{rendered}");
        assert!(rendered.contains("3000-3999"), "{rendered}");
        assert!(
            ExposeRefusal::DeniedByPolicy
                .to_string()
                .contains("denied for this box")
        );
        // The two missing-address halves say which half is missing: no
        // published address is a capability gap, no switch address is a box
        // that is not attached yet — and neither reads as a policy deny.
        let unpublished = ExposeRefusal::NoPublishedAddress.to_string();
        let unattached = ExposeRefusal::NotAttached.to_string();
        assert!(
            unpublished.contains("no address on the host to open a port at"),
            "{unpublished}"
        );
        assert!(
            unattached.contains("not connected") && unattached.contains("start the box"),
            "{unattached}"
        );
        assert_ne!(unpublished, unattached);
        assert!(!unattached.contains("denied") && !unpublished.contains("denied"));
        assert!(
            ExposeFailure::Refused(refusal)
                .to_string()
                .starts_with(&rendered),
            "the failure wraps the refusal's own words"
        );
        let failed = ExposeFailure::Publish {
            port: 3000,
            source: io::Error::other("gvproxy refused"),
        };
        assert!(
            failed.to_string().contains("3000"),
            "the publish failure names the port it could not bind: {failed}"
        );
    }

    #[test]
    fn parse_status_code_reads_the_code() {
        assert_eq!(parse_status_code(b"HTTP/1.1 200 OK\r\n\r\n").unwrap(), 200);
        assert_eq!(
            parse_status_code(b"HTTP/1.0 500 Internal Server Error\r\n").unwrap(),
            500
        );
    }

    #[test]
    fn parse_status_code_rejects_a_malformed_line() {
        assert!(parse_status_code(b"not http\r\n").is_err());
    }

    #[test]
    fn warn_limiter_suppresses_within_the_interval() {
        let limiter = PolicyWarnLimiter::new();
        let t0 = Instant::now();
        // First emission at t0 is allowed; a second within the interval is not.
        assert!(limiter.should_warn_at("box", "egress-undeclared-subnet", t0));
        assert!(!limiter.should_warn_at(
            "box",
            "egress-undeclared-subnet",
            t0 + Duration::from_millis(10)
        ));
        // Once the interval has elapsed it warns again.
        assert!(limiter.should_warn_at("box", "egress-undeclared-subnet", t0 + WARN_MIN_INTERVAL));
    }

    #[test]
    fn warn_limiter_keys_by_box_and_rule() {
        // NET-062 rate-limits "per PTask per rule": one box's flood never
        // silences another box's single drop, and a box hitting several rules in
        // the same minute is still heard once per rule.
        let limiter = PolicyWarnLimiter::new();
        let t0 = Instant::now();
        assert!(limiter.should_warn_at("box-a", "rule-1", t0));
        // A different box under the same rule is not silenced by box-a's drop…
        assert!(limiter.should_warn_at("box-b", "rule-1", t0));
        // …and neither is the same box under a different rule.
        assert!(limiter.should_warn_at("box-a", "rule-2", t0));
        // But the same pair within the interval still is.
        assert!(!limiter.should_warn_at("box-a", "rule-1", t0 + Duration::from_secs(1)));
        assert!(!limiter.should_warn_at("box-b", "rule-1", t0 + Duration::from_secs(1)));
    }

    #[test]
    fn warn_limiter_keys_ingress_drops_by_rule_not_port() {
        // The destination port is a structured field, not part of the rule
        // key: a port scan against one box is one rule hit per minute, not one
        // emission per probed port.
        let limiter = PolicyWarnLimiter::new();
        let src = Some(SocketAddr::from(([100, 64, 0, 9], 40000)));
        let emitted = [80u16, 8080]
            .into_iter()
            .filter(|&dst_port| {
                limiter.warn(
                    "box",
                    Direction::Ingress,
                    src,
                    Proto::from_ipproto(IpProto::Tcp),
                    Some(dst_port),
                    "no ingress mapping",
                )
            })
            .count();
        assert_eq!(emitted, 1);
    }

    #[test]
    fn direction_renders_the_r2_7_field_values() {
        // R2.7 spells the `direction` structured field `egress`/`ingress`.
        assert_eq!(Direction::Egress.to_string(), "egress");
        assert_eq!(Direction::Ingress.to_string(), "ingress");
    }

    #[test]
    fn proto_renders_the_r2_7_field_values() {
        // R2.7 names the three declared protocols `tcp`/`udp`/`icmp`; anything
        // else a box can send is rendered as its IPv4 protocol number, and the
        // family/truncation drops (which carry no L4 protocol) as `ipv6`/`none`.
        assert_eq!(Proto::from_ipproto(IpProto::Tcp).to_string(), "tcp");
        assert_eq!(Proto::from_ipproto(IpProto::Udp).to_string(), "udp");
        assert_eq!(Proto::from_ipproto(IpProto::Icmp).to_string(), "icmp");
        assert_eq!(Proto::from_ipv4_number(47).to_string(), "ip-47");
        assert_eq!(Proto::Ipv6.to_string(), "ipv6");
        assert_eq!(Proto::None.to_string(), "none");
    }

    #[test]
    fn content_length_parses_case_insensitively_or_absent() {
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n"),
            Some(6)
        );
        assert_eq!(
            content_length(b"HTTP/1.1 200 OK\r\ncontent-length:  0\r\n\r\n"),
            Some(0)
        );
        assert_eq!(content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn exchange_frames_by_content_length_without_a_server_close() {
        // Regression for G-N8: the response must be framed by `Content-Length`,
        // never by the server closing the socket. On the KVM libkrun vsock shuttle
        // a server-initiated close drops the still-buffered response, so `exchange`
        // must return the full reply from a peer that stays open. If it ever
        // reverts to read-to-EOF, this test hangs (the peer never closes).
        let (client, mut server) = tokio::io::duplex(1024);
        let server = crate::traced::spawn(async move {
            let mut buf = [0u8; 256];
            // Drain the request (headers + empty body arrive together here).
            let _ = server.read(&mut buf).await.unwrap();
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nWEB_OK")
                .await
                .unwrap();
            // Hold the connection open — do NOT close — until the caller is done.
            server
        });

        let resp = exchange(
            client,
            b"POST /services/forwarder/expose HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .expect("exchange returns the framed response without waiting for EOF");

        assert_eq!(parse_status_code(&resp).unwrap(), 200);
        assert_eq!(body_after_headers(&resp), b"WEB_OK");
        drop(server.await.unwrap());
    }

    // ---- NET-123's forwarder-conducted range probe -----------------------
    /// NET-017: a withdrawn publish's unexpose reads how many accepted
    /// connections the switch closed and logs it, and the sibling publish
    /// of the same in-box port is never asked to come down.
    mod closed_on_retract {
        use super::forwarder_probe::read_request;
        use super::*;
        use tokio::net::UnixListener;
        use tokio::sync::mpsc;
        use tracing::Instrument as _;

        #[derive(Clone, Default)]
        struct LogCapture(Arc<Mutex<Vec<u8>>>);

        impl LogCapture {
            fn contents(&self) -> String {
                String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
            }
        }

        impl std::io::Write for LogCapture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
            type Writer = LogCapture;
            fn make_writer(&self) -> Self::Writer {
                self.clone()
            }
        }

        /// A switch whose `/unexpose` answers each `local` with the body
        /// `reply` picks, and reports every request's body.
        fn spawn_switch(
            path: std::path::PathBuf,
            reply: impl Fn(&str) -> String + Send + Sync + 'static,
        ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<String>) {
            let listener = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel(16);
            let handle = crate::traced::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = String::from_utf8(read_request(&mut sock).await).unwrap();
                    let answer = reply(&body);
                    sock.write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{answer}",
                            answer.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("the fake switch must answer");
                    if tx.send(body).await.is_err() {
                        return;
                    }
                }
            });
            (handle, rx)
        }

        #[tokio::test]
        async fn retracting_one_publish_closes_only_its_accepted_connections() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let retracted = ExposedMapping {
                local: "127.0.0.5:8080".to_string(),
                protocol: "tcp".to_string(),
            };
            let sibling = ExposedMapping {
                local: "127.0.0.6:9090".to_string(),
                protocol: "tcp".to_string(),
            };
            // The retracted publish held two connections. A switch that
            // reports no count stands in for an unpatched one.
            let (server, mut asked) = spawn_switch(sock.clone(), |body| {
                if body.contains("127.0.0.5:8080") {
                    r#"{"closed":2}"#.to_string()
                } else {
                    String::new()
                }
            });
            let control = ControlChannel::Unix(sock);

            let log = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(log.clone())
                .with_ansi(false)
                .finish();
            let guard = tracing::subscriber::set_default(subscriber);
            let span = tracing::info_span!("listen", session = "web-box");
            let closed = unexpose_mapping(&control, &retracted)
                .instrument(span.clone())
                .await
                .expect("the retracted publish comes down");
            assert_eq!(closed, ClosedConnections(Some(2)));
            assert!(
                log.contents().is_empty(),
                "the shared unexpose logs nothing, so a move or a revoke never claims a withdrawal: {}",
                log.contents()
            );
            span.in_scope(|| log_withdrawal(&retracted, closed));

            let first = asked.recv().await.expect("the switch was asked");
            assert!(
                first.contains("127.0.0.5:8080"),
                "the unexpose names the retracted publish: {first}"
            );
            assert!(
                asked.try_recv().is_err(),
                "the sibling publish of the same in-box port is not asked to come down"
            );
            let text = log.contents();
            let line = text
                .lines()
                .find(|l| l.contains("withdrew a published port"))
                .unwrap_or_else(|| panic!("no retraction line in the log: {text}"));
            assert!(
                line.contains("the switch closed the connections it accepted"),
                "a reported count is said as closed connections: {line}"
            );
            assert!(line.contains("web-box"), "the line names the box: {line}");
            assert!(
                line.contains("port=8080"),
                "the line names the port: {line}"
            );
            assert!(
                line.contains("closed_connections=2"),
                "the line carries the switch's count: {line}"
            );

            // A reply with no count is logged as unknown, never as zero.
            let closed = unexpose_mapping(&control, &sibling)
                .await
                .expect("the sibling publish comes down when it is retracted");
            assert_eq!(closed, ClosedConnections(None));
            log_withdrawal(&sibling, closed);
            drop(guard);
            let text = log.contents();
            let line = text
                .lines()
                .filter(|l| l.contains("withdrew a published port"))
                .nth(1)
                .unwrap_or_else(|| panic!("no second retraction line: {text}"));
            assert!(line.contains("port=9090"), "{line}");
            assert!(line.contains("closed_connections=unknown"), "{line}");
            assert!(
                line.contains("did not report how many accepted connections it closed"),
                "an unknown count says what is known: {line}"
            );
            assert!(
                !line.contains("the switch closed the connections"),
                "an unknown count claims no closed connection: {line}"
            );
            server.abort();
        }

        #[test]
        fn the_closed_count_reads_from_the_unexpose_reply() {
            assert_eq!(
                ClosedConnections::from_reply(br#"{"closed":3}"#),
                ClosedConnections(Some(3))
            );
            assert_eq!(
                ClosedConnections::from_reply(b"{\"closed\":0}\n"),
                ClosedConnections(Some(0))
            );
            assert_eq!(ClosedConnections::from_reply(b""), ClosedConnections(None));
            assert_eq!(
                ClosedConnections::from_reply(b"{}"),
                ClosedConnections(None)
            );
            assert_eq!(
                ClosedConnections::from_reply(b"not json"),
                ClosedConnections(None)
            );
            assert_eq!(ClosedConnections(None).to_string(), "unknown");
            assert_eq!(ClosedConnections(Some(4)).to_string(), "4");
        }
    }

    mod forwarder_probe {
        use std::collections::HashMap;
        use std::io;
        use std::net::Ipv4Addr;
        use std::path::PathBuf;
        use std::time::Duration;

        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio::net::{UnixListener, UnixStream};
        use tokio::sync::mpsc;

        use super::super::{
            ControlChannel, GVPROXY_CONTROL_TIMEOUT, RANGE_PROBE_BUDGET, RANGE_PROBE_PORT,
            RANGE_PROBE_REQUEST_BUDGET, UnexposeRequest, post_json, probe_publish_surface,
            probe_publish_surface_within,
        };

        /// Reads one control request off `sock`: its head up to the
        /// end-of-head marker, then exactly its `Content-Length` body — the
        /// mirror of `post_json`'s keep-alive framing, so the fake forwarder
        /// never blocks reading past what the probe sent.
        pub(super) async fn read_request(sock: &mut UnixStream) -> Vec<u8> {
            let mut buf = Vec::with_capacity(256);
            let mut scratch = [0u8; 512];
            let head_end = loop {
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) {
                    break i;
                }
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request head");
                assert!(n > 0, "the probe closed before sending its head");
                buf.extend_from_slice(&scratch[..n]);
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
            let len: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let n = sock
                    .read(&mut scratch)
                    .await
                    .expect("the fake forwarder must receive the request body");
                assert!(n > 0, "the probe closed mid-body");
                buf.extend_from_slice(&scratch[..n]);
            }
            buf[head_end..head_end + len].to_vec()
        }

        /// The `local` address a request body names, for the decide closure.
        fn local_of(body: &[u8]) -> String {
            let text = String::from_utf8_lossy(body);
            text.split("\"local\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default()
                .to_string()
        }

        /// Serves a gvproxy-shaped control channel at `path`: every request
        /// is read in full, then answered with the status `decide` picks for
        /// the `local` address its body names — the stand-in for the host
        /// gvproxy whose loopback carries only the aliases `decide` accepts,
        /// where a bind on a missing alias is answered `500` the way the real
        /// forwarder answers an `EADDRNOTAVAIL`. `delay` parks each answer,
        /// for the one test that needs a forwarder slower than its budget.
        /// Every round's `local` is handed to the returned receiver; the
        /// returned handle aborts the server when the test is done with it.
        pub(super) fn spawn_forwarder_answering(
            path: PathBuf,
            delay: Duration,
            decide: impl Fn(&str) -> u16 + Send + Sync + 'static,
        ) -> (tokio::task::JoinHandle<()>, mpsc::Receiver<String>) {
            let listener = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel(512);
            let decide = std::sync::Arc::new(decide);
            let handle = crate::traced::spawn(async move {
                // Sequential on purpose: the probe is a walk, one request per
                // address, so one connection served at a time is its shape.
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let body = read_request(&mut sock).await;
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let local = local_of(&body);
                    let status = decide(&local);
                    let reason = if status == 200 {
                        "OK"
                    } else {
                        "Internal Server Error"
                    };
                    sock.write_all(
                        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n")
                            .as_bytes(),
                    )
                    .await
                    .expect("the fake forwarder must answer");
                    if tx.send(local).await.is_err() {
                        return;
                    }
                }
            });
            (handle, rx)
        }

        /// A host gvproxy that binds every address of the reserved range —
        /// the Linux host of the KVM lane, whose `lo` owns all of `127/8` —
        /// so the daemon behind it reads the range present and grants
        /// per-box addresses: the whole range walked, every round released
        /// behind the walk, every address asked at the probe's fixed port.
        #[tokio::test]
        async fn reads_the_range_present_when_every_expose_binds() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(
                probe.probed,
                254,
                "the walk covers every usable host: {}",
                probe.summary()
            );
            assert!(
                probe.present(),
                "a forwarder that binds every address vouches for the range: {}",
                probe.summary()
            );
            assert_eq!(probe.first_failure, None);
            assert_eq!(probe.surface(), "reserved-range");

            // One expose and one unexpose per address: the bind is released
            // the moment it answers, so the probe leaves nothing bound.
            let mut rounds: HashMap<String, usize> = HashMap::new();
            let mut requests = 0usize;
            while let Some(local) = asked.recv().await {
                requests += 1;
                *rounds.entry(local).or_default() += 1;
            }
            assert_eq!(
                rounds.len(),
                254,
                "every address of the range was asked, at the probe port: {requests} requests"
            );
            assert!(
                rounds.values().all(|&seen| seen == 2),
                "every bound round was released by its unexpose: {rounds:?}"
            );
            let round = |addr: std::net::Ipv4Addr| format!("{addr}:{RANGE_PROBE_PORT}");
            assert_eq!(rounds.get(&round(Ipv4Addr::new(127, 0, 64, 1))), Some(&2));
            assert_eq!(rounds.get(&round(Ipv4Addr::new(127, 0, 64, 254))), Some(&2));
            assert!(
                rounds
                    .keys()
                    .all(|local| local.ends_with(&format!(":{RANGE_PROBE_PORT}"))),
                "every round asked at the probe's fixed port: {rounds:?}"
            );
        }

        /// #2748: the VM host's egress gate admits one probe round at a time
        /// and answers 409 while another is still bound there. That is
        /// contention, not an answer about the address: the walk waits it
        /// out and asks again, and reads the range present once the round
        /// binds.
        #[tokio::test]
        async fn waits_out_the_gates_outstanding_round_and_reads_the_answer_after_it() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let contended = format!("{}:{RANGE_PROBE_PORT}", Ipv4Addr::new(127, 0, 64, 5));
            let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = std::sync::Arc::clone(&asked);
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, move |local| {
                    if local == contended
                        && counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 3
                    {
                        409
                    } else {
                        200
                    }
                });
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();
            assert!(
                probe.present(),
                "contention is waited out, not read as a missing address: {}",
                probe.summary()
            );
            assert_eq!(probe.first_failure, None);
            assert!(asked.load(std::sync::atomic::Ordering::SeqCst) >= 4);
        }

        /// #2748: contention that outlasts the walk's budget ends the walk
        /// inconclusive, a fault of the channel, never a refusal. The landing
        /// keeps a present verdict over such a walk, so a guest that holds a
        /// probe round cannot flip the range to absent.
        #[tokio::test]
        async fn contention_past_the_budget_reads_inconclusive_never_refused() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let contended = format!("{}:{RANGE_PROBE_PORT}", Ipv4Addr::new(127, 0, 64, 5));
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, move |local| {
                    if local == contended { 409 } else { 200 }
                });
            let probe = probe_publish_surface_within(
                &ControlChannel::Unix(sock),
                Duration::from_secs(2),
                RANGE_PROBE_REQUEST_BUDGET,
            )
            .await;
            forwarder.abort();
            assert!(!probe.present(), "{}", probe.summary());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 5), io::ErrorKind::TimedOut)),
                "contention reads as a fault of the channel, not a refusal: {}",
                probe.summary()
            );
        }

        /// A range address whose probe port something already holds: a box's
        /// forward through this forwarder (`proxy already running`) at one
        /// address, a host_ip mirror held by another host process (the OS's
        /// bind text) at another. Both refusals say the address exists, so
        /// the walk counts each one bound and reads the range present. The
        /// walk sends no unexpose for a held address, so the holder's forward
        /// stays up.
        #[tokio::test]
        async fn counts_an_address_whose_probe_port_is_held_as_bound() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let box_held = format!("{}:{RANGE_PROBE_PORT}", Ipv4Addr::new(127, 0, 64, 3));
            let mirror_held = format!("{}:{RANGE_PROBE_PORT}", Ipv4Addr::new(127, 0, 64, 9));
            let (tx, mut asked) = mpsc::channel::<(String, String)>(1024);
            let (box_held_s, mirror_held_s) = (box_held.clone(), mirror_held.clone());
            let forwarder = crate::traced::spawn(async move {
                loop {
                    let Ok((mut conn, _)) = listener.accept().await else {
                        return;
                    };
                    // An expose body carries `remote`, an unexpose body
                    // does not: that tells the two verbs apart.
                    let body = read_request(&mut conn).await;
                    let local = local_of(&body);
                    let verb = if String::from_utf8_lossy(&body).contains("\"remote\"") {
                        "expose"
                    } else {
                        "unexpose"
                    };
                    let said = if verb == "expose" && local == box_held_s {
                        Some("proxy already running".to_string())
                    } else if verb == "expose" && local == mirror_held_s {
                        Some(format!("listen tcp {local}: bind: address already in use"))
                    } else {
                        None
                    };
                    let answer = match said {
                        Some(said) => format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{said}",
                            said.len()
                        ),
                        None => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                    };
                    conn.write_all(answer.as_bytes())
                        .await
                        .expect("the fake forwarder must answer");
                    if tx.send((verb.to_string(), local)).await.is_err() {
                        return;
                    }
                }
            });
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert!(
                probe.present(),
                "a held probe port says the address exists: {}",
                probe.summary()
            );
            assert_eq!(probe.first_failure, None);
            assert_eq!(probe.bound, 254, "{}", probe.summary());

            let mut unexposed = Vec::new();
            while let Some((verb, local)) = asked.recv().await {
                if verb == "unexpose" {
                    unexposed.push(local);
                }
            }
            assert_eq!(
                unexposed.len(),
                252,
                "one release per address the probe bound"
            );
            assert!(
                !unexposed.contains(&box_held) && !unexposed.contains(&mirror_held),
                "the walk never releases a forward it did not bind: {unexposed:?}"
            );
        }

        /// A probe forward that an earlier walk left bound is released, not
        /// counted. The first walk's unexpose fails at one address, so its
        /// probe forward stays in the forwarder's table. The host then loses
        /// that address. The forwarder still answers `already running` there
        /// from its table, but the next walk releases its own leftover, asks
        /// again, and reads the refusal: the range is absent.
        #[tokio::test]
        async fn a_probe_forward_left_by_an_earlier_walk_is_released_not_counted() {
            use std::collections::BTreeSet;
            use std::sync::{Arc, Mutex};

            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let listener = UnixListener::bind(&sock).unwrap();
            let stuck = format!("{}:{RANGE_PROBE_PORT}", Ipv4Addr::new(127, 0, 64, 5));
            // The forwarder's forward table, the addresses the host binds,
            // and how many unexposes at the stuck address still fail.
            let table: Arc<Mutex<BTreeSet<String>>> = Arc::default();
            let host_has_stuck = Arc::new(Mutex::new(true));
            let failing_unexposes = Arc::new(Mutex::new(1u32));
            let (table_s, host_s, failing_s, stuck_s) = (
                table.clone(),
                host_has_stuck.clone(),
                failing_unexposes.clone(),
                stuck.clone(),
            );
            let forwarder = crate::traced::spawn(async move {
                loop {
                    let Ok((mut conn, _)) = listener.accept().await else {
                        return;
                    };
                    let body = read_request(&mut conn).await;
                    let local = local_of(&body);
                    let expose = String::from_utf8_lossy(&body).contains("\"remote\"");
                    let said: Option<String> = {
                        let mut table = table_s.lock().unwrap();
                        if expose {
                            if table.contains(&local) {
                                Some("proxy already running".to_string())
                            } else if local == stuck_s && !*host_s.lock().unwrap() {
                                Some(format!(
                                    "listen tcp {local}: bind: can't assign requested address"
                                ))
                            } else {
                                table.insert(local.clone());
                                None
                            }
                        } else {
                            let mut failing = failing_s.lock().unwrap();
                            if local == stuck_s && *failing > 0 {
                                *failing -= 1;
                                Some("unexpose failed".to_string())
                            } else {
                                table.remove(&local);
                                None
                            }
                        }
                    };
                    let answer = match said {
                        Some(said) => format!(
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{said}",
                            said.len()
                        ),
                        None => "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(),
                    };
                    conn.write_all(answer.as_bytes())
                        .await
                        .expect("the fake forwarder must answer");
                }
            });
            let control = ControlChannel::Unix(sock);

            let first = probe_publish_surface(&control).await;
            assert!(first.present(), "{}", first.summary());
            assert!(
                table.lock().unwrap().contains(&stuck),
                "the failed unexpose left the probe forward bound"
            );

            *host_has_stuck.lock().unwrap() = false;
            let second = probe_publish_surface(&control).await;
            forwarder.abort();

            assert!(
                !second.present(),
                "a leftover probe forward never vouches for an address the host lost: {}",
                second.summary()
            );
            assert_eq!(
                second.first_failure,
                Some((
                    Ipv4Addr::new(127, 0, 64, 5),
                    io::ErrorKind::AddrNotAvailable
                )),
            );
            assert!(
                table.lock().unwrap().is_empty(),
                "the second walk released its leftover"
            );
        }

        /// The stock macOS host's shape (`docs/spikes/2026-09-22-macos-loopback-alias.md`):
        /// every bind on the range refused, so every expose is answered `500`
        /// — the range reads absent and the daemon behind that forwarder
        /// publishes on the `127.0.0.1` interim, the state that keeps an
        /// own-address box's activate from failing on a host whose `lo0`
        /// carries no alias yet.
        #[tokio::test]
        async fn reads_the_range_absent_when_the_host_refuses_every_bind() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 500);
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 0);
            assert!(!probe.present());
            assert!(probe.interim());
            assert_eq!(probe.surface(), "127.0.0.1-interim");
            // The forwarder answered and refused, so the walk records the
            // bind refusal's kind, `AddrNotAvailable` — the answer a
            // session-start walk lands absent on. The address is the
            // record's, never guessed.
            assert_eq!(
                probe.first_failure,
                Some((
                    Ipv4Addr::new(127, 0, 64, 1),
                    io::ErrorKind::AddrNotAvailable
                ))
            );
        }

        /// A *partial* alias set must read absent, exactly as the local
        /// probe's does: the addresses the allocator could still hand out are
        /// the missing ones, and a fetch aimed at one hangs rather than
        /// refusing.
        #[tokio::test]
        async fn reads_a_partial_range_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |local| {
                    if local.starts_with("127.0.64.100:") {
                        500
                    } else {
                        200
                    }
                });
            let probe = probe_publish_surface(&ControlChannel::Unix(sock)).await;
            forwarder.abort();

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 253);
            assert!(!probe.present(), "one missing alias fails the whole range");
            assert!(
                probe.interim(),
                "a partially-aliased host publishes on the interim"
            );
            assert_eq!(
                probe.first_failure.map(|(addr, _)| addr),
                Some(Ipv4Addr::new(127, 0, 64, 100))
            );
        }

        /// A control channel with nothing listening — a shuttle bridged to
        /// a gvproxy that is not up — is not a fact about the host's loopback
        /// at all, and reads absent: an unreadable publish surface never
        /// vouches for an address.
        #[tokio::test]
        async fn reads_an_unreachable_forwarder_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let probe =
                probe_publish_surface(&ControlChannel::Unix(dir.path().join("absent.sock"))).await;

            assert_eq!(probe.probed, 254, "{}", probe.summary());
            assert_eq!(probe.bound, 0);
            assert!(!probe.present());
            assert!(probe.interim());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::NotFound)),
                "the first refusal names the first address, never a made-up one"
            );
        }

        /// A walk that outruns its budget is read as it stopped: the addresses
        /// it never reached are the ones it cannot vouch for, so the probed
        /// count is widened to the whole range — `present` then demands every
        /// address — and the record names where the vouching stopped.
        #[tokio::test]
        async fn reads_a_walk_that_outran_its_budget_absent() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            // A forwarder slower than the budget: every answer parks long
            // past it, so the walk cannot get past its first round.
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::from_millis(50), |_| 200);
            let probe = probe_publish_surface_within(
                &ControlChannel::Unix(sock),
                Duration::from_millis(1),
                RANGE_PROBE_REQUEST_BUDGET,
            )
            .await;
            forwarder.abort();

            assert_eq!(
                probe.probed, 254,
                "an overran walk is widened to the whole range, so `present` \
                 demands every address it never reached"
            );
            assert!(
                !probe.present(),
                "a walk that did not finish may not vouch for the range: {}",
                probe.summary()
            );
            assert!(probe.interim());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::TimedOut)),
                "the address whose round the budget expired inside is the record's"
            );
        }

        /// A forwarder that parks its answer stalls one *round* of the walk,
        /// and the walk reads that round at its own bound — not at the publish
        /// verbs' [`GVPROXY_CONTROL_TIMEOUT`] — stopping at the first address
        /// with the channel's own `TimedOut`, which is not a fact about the
        /// host's loopback and so never a bind refusal the range is read from.
        /// The budget stays the walk's whole one, so what is exercised here is
        /// the round bound alone.
        #[tokio::test]
        async fn a_stalled_round_costs_the_walk_only_its_own_bound() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            // Parks far past the round's bound and far inside the publish
            // verbs' one, so only the round bound can cut the walk short.
            let (forwarder, _asked) =
                spawn_forwarder_answering(sock.clone(), Duration::from_millis(60), |_| 200);
            let probe = probe_publish_surface_within(
                &ControlChannel::Unix(sock),
                RANGE_PROBE_BUDGET,
                Duration::from_millis(1),
            )
            .await;
            forwarder.abort();

            assert_eq!(probe.probed, 1, "{}", probe.summary());
            assert_eq!(probe.bound, 0);
            assert!(!probe.present());
            assert!(probe.interim());
            assert_eq!(
                probe.first_failure,
                Some((Ipv4Addr::new(127, 0, 64, 1), io::ErrorKind::TimedOut)),
                "the stalled round is the channel's own timeout, never a bind refusal"
            );
        }

        /// The round bound the stalled round above is read at: at most a
        /// second, and always tighter than the publish verbs'
        /// [`GVPROXY_CONTROL_TIMEOUT`]. The walk is two rounds per address of
        /// the range on one channel, so a channel that cannot answer one round
        /// in a second is one the walk stops asking — while the launch and
        /// teardown verbs keep their own, roomier bound.
        #[test]
        fn the_walks_round_bound_is_tighter_than_the_publish_verbs() {
            assert!(
                RANGE_PROBE_REQUEST_BUDGET <= Duration::from_secs(1),
                "the walk's round bound is {RANGE_PROBE_REQUEST_BUDGET:?}"
            );
            assert!(
                RANGE_PROBE_REQUEST_BUDGET < GVPROXY_CONTROL_TIMEOUT,
                "the walk never inherits the publish verbs' bound"
            );
        }

        /// The probe's request shape is the forwarder's own: an expose whose
        /// `local` is the address under test at the probe port, and an
        /// unexpose naming exactly the bind it released — the same verbs the
        /// publishes ride, with a `remote` the probe never dials.
        #[tokio::test]
        async fn exposes_and_releases_the_probe_binds_over_the_control_channel() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            // One round only: bind the range's first address, release it.
            let expose = super::super::ExposeRequest {
                local: format!("127.0.64.1:{RANGE_PROBE_PORT}"),
                remote: "127.0.0.1:1".to_string(),
                protocol: "tcp".to_string(),
            };
            post_json(
                &ControlChannel::Unix(sock.clone()),
                "/services/forwarder/expose",
                &expose,
            )
            .await
            .expect("the fake forwarder must bind the probe address");
            let asked_expose = asked.recv().await.expect("the round's expose was recorded");
            let unexpose = UnexposeRequest {
                local: expose.local.clone(),
                protocol: expose.protocol,
            };
            post_json(
                &ControlChannel::Unix(sock),
                "/services/forwarder/unexpose",
                &unexpose,
            )
            .await
            .expect("the fake forwarder must release the probe bind");
            let asked_unexpose = asked
                .recv()
                .await
                .expect("the round's unexpose was recorded");
            forwarder.abort();

            assert_eq!(asked_expose, format!("127.0.64.1:{RANGE_PROBE_PORT}"));
            assert_eq!(asked_unexpose, asked_expose);
        }
    }

    // ---- a shared-address port's forward bound at its hand-over (NET-129) --
    mod handed_port {
        use std::net::Ipv4Addr;

        use tokio::io::AsyncWriteExt as _;
        use tokio::net::UnixListener;

        use super::super::{
            ControlChannel, HandedBind, PortMapping, bind_handed_port, handed_bind,
            is_already_running,
        };
        use super::forwarder_probe::read_request;

        const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 128, 10);

        fn mapping() -> PortMapping {
            PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: boxes::IpProto::Tcp,
            }
        }

        /// A forwarder that answers one expose with `status` and `body`,
        /// framed as the real one frames its answers, and hands back the
        /// request body it read.
        fn forwarder_answering_once(
            path: std::path::PathBuf,
            status: u16,
            body: &'static str,
        ) -> tokio::task::JoinHandle<String> {
            let listener = UnixListener::bind(&path).unwrap();
            crate::traced::spawn(async move {
                let (mut sock, _) = listener.accept().await.expect("the bind is asked");
                let request = String::from_utf8_lossy(&read_request(&mut sock).await).into_owned();
                sock.write_all(
                    format!(
                        "HTTP/1.1 {status} Whatever\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("the fake forwarder must answer");
                request
            })
        }

        /// The switch binds the forward: the bind posts the expose the
        /// box's own attach posts for the mapping, and hands back the
        /// forwarder to track, naming the listener and the inside port.
        #[tokio::test]
        async fn a_bound_hand_over_hands_back_the_forwarder_to_track() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_once(sock.clone(), 200, "");

            let bind = bind_handed_port(
                &ControlChannel::Unix(sock),
                PUBLISHED,
                LEASE,
                &mapping(),
                None,
            )
            .await
            .expect("the switch bound the forward");

            let request = forwarder.await.expect("the fake forwarder ran");
            assert!(
                request.contains("\"local\":\"127.0.64.9:18080\""),
                "{request}"
            );
            assert!(
                request.contains("\"remote\":\"100.64.128.10:80\""),
                "{request}"
            );
            let HandedBind::Bound(tracked) = bind else {
                panic!("a 2xx answer is a bound forward");
            };
            assert_eq!(tracked.local(), "127.0.64.9:18080");
            assert_eq!(tracked.internal_port(), 80);
            // TCP and UDP on one port are two forwards: the tracked TCP
            // one is not the UDP mapping's.
            assert!(tracked.is_forward_of(PUBLISHED, &mapping()));
            let udp = PortMapping {
                proto: boxes::IpProto::Udp,
                ..mapping()
            };
            assert!(!tracked.is_forward_of(PUBLISHED, &udp));
        }

        /// The forwarder's own answer for a listener that is already bound.
        /// On a native host it is a failed bind: a forward still stands at
        /// the listener. Behind a VM host's gate the same answer is the
        /// gate keeping the publish for the old holder's row to end, so the
        /// forwarder is handed back to track. Any other refusal fails on
        /// both.
        #[tokio::test]
        async fn an_already_running_answer_is_held_only_behind_a_vm_hosts_gate() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_once(sock.clone(), 500, "proxy already running\n");
            let control = ControlChannel::Unix(sock);
            assert!(!control.host_unbinds_declared_forwards());

            let Err(native) = bind_handed_port(&control, PUBLISHED, LEASE, &mapping(), None).await
            else {
                panic!("on a native host an already-bound listener is a failed bind");
            };
            let _request = forwarder.await.expect("the fake forwarder ran");
            assert!(is_already_running(&native), "got: {native}");

            let tracked = || super::declared_release::declared_at("127.0.64.9:18080");
            assert!(matches!(
                handed_bind(true, Err(native), tracked()),
                Ok(HandedBind::HeldByHost(_))
            ));
            let refused = || {
                std::io::Error::other(
                    "gvproxy /services/forwarder/expose returned HTTP 500: listen tcp: bind failed",
                )
            };
            assert!(!is_already_running(&refused()));
            assert!(handed_bind(true, Err(refused()), tracked()).is_err());
            assert!(handed_bind(false, Err(refused()), tracked()).is_err());
        }
    }

    // ---- who unbinds a declared forward when its box stops (NET-121) ------
    mod declared_release {
        use std::sync::Arc;
        use std::sync::atomic::AtomicBool;
        use std::time::Duration;

        use super::super::{
            ControlChannel, ExposedMapping, PortForwarder, release_declared_ingress,
        };
        use super::forwarder_probe::spawn_forwarder_answering;

        /// A declared forwarder bound at `local`, as `apply_ingress` builds
        /// one, with no session gate behind it.
        pub(super) fn declared_at(local: &str) -> PortForwarder {
            PortForwarder {
                mapping: ExposedMapping {
                    local: local.to_string(),
                    protocol: "tcp".to_string(),
                },
                internal_port: 80,
                gate: None,
                revoked: Arc::new(AtomicBool::new(false)),
            }
        }

        /// On a VM-backed host the host's egress gate refuses any withdrawal
        /// of a declared port and unbinds the forward itself at box end, so
        /// the daemon asks the switch for nothing. It says one info line per
        /// forward, and no "removing ingress port mapping" warning.
        #[tokio::test]
        async fn declared_forwards_left_to_the_host_on_a_vm_host() {
            let log = crate::test_harness::captured_log();
            let control = ControlChannel::Vsock { cid: 2, port: 1 };
            assert!(control.host_unbinds_declared_forwards());
            let bound = [declared_at("127.0.64.201:18201")];

            tokio::time::timeout(
                Duration::from_secs(1),
                release_declared_ingress(&control, &bound),
            )
            .await
            .expect("releasing on a VM host asks nothing of the switch, so it returns at once");

            let logged = log.contents();
            assert!(
                logged.lines().any(|line| line
                    .contains("left the declared ingress forwarder for the host to unbind")
                    && line.contains("port=18201")),
                "each declared forward says it was left to the host, got: {logged}"
            );
            assert!(
                !logged
                    .lines()
                    .any(|line| line.contains("127.0.64.201:18201")
                        && line.contains("removing ingress port mapping")),
                "no retraction was attempted, so none failed, got: {logged}"
            );
        }

        /// On a native host the daemon drives the switch directly, so it
        /// still unbinds a declared forward itself when the box stops.
        #[tokio::test]
        async fn declared_forwards_unbound_by_the_daemon_on_a_native_host() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let (forwarder, mut asked) =
                spawn_forwarder_answering(sock.clone(), Duration::ZERO, |_| 200);
            let control = ControlChannel::Unix(sock);
            assert!(!control.host_unbinds_declared_forwards());

            release_declared_ingress(&control, &[declared_at("127.0.64.202:18202")]).await;
            forwarder.abort();

            assert_eq!(
                asked.recv().await.as_deref(),
                Some("127.0.64.202:18202"),
                "the daemon asked the switch to unbind the declared forward"
            );
        }
    }

    // ---- a host port another process already holds (reported as EADDRINUSE) --
    mod host_port_in_use {
        use std::io;
        use std::net::Ipv4Addr;

        use tokio::io::AsyncWriteExt as _;
        use tokio::net::UnixListener;

        use super::super::{
            ControlChannel, IngressPolicy, PORT_HELD_BINDS, PORT_HELD_RETRY, PortMapping,
            apply_declared, apply_ingress, host_ports_in_use, is_address_in_use, port_held_by,
            port_in_use_refusal,
        };
        use super::forwarder_probe::read_request;

        const PUBLISHED: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 9);
        const LEASE: Ipv4Addr = Ipv4Addr::new(100, 64, 128, 10);

        fn mapping(external_port: u16) -> PortMapping {
            PortMapping {
                external_port,
                internal_port: 80,
                proto: boxes::IpProto::Tcp,
            }
        }

        fn ingress(ports: &[u16]) -> IngressPolicy {
            IngressPolicy {
                port_mappings: ports.iter().map(|&port| mapping(port)).collect(),
                dynamic_allowed_range: None,
                dynamic_ingress: None,
            }
        }

        /// Serves a gvproxy-shaped control channel at `path`: one request per
        /// entry of `answers`, each answered with its status and body — the
        /// stand-in for the host forwarder whose `expose` of a taken port
        /// answers `500` with the OS's bind text in its body. The OS's own
        /// words arrive as an HTTP body, so the answers here carry them.
        fn forwarder_answering_in_turn(
            path: std::path::PathBuf,
            answers: Vec<(u16, &'static str)>,
        ) -> tokio::task::JoinHandle<Vec<String>> {
            let listener = UnixListener::bind(&path).unwrap();
            crate::traced::spawn(async move {
                let mut asked = Vec::new();
                for (status, body) in answers {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return asked;
                    };
                    asked
                        .push(String::from_utf8_lossy(&read_request(&mut sock).await).into_owned());
                    sock.write_all(
                        format!(
                            "HTTP/1.1 {status} Internal Server Error\r\n\
                             Content-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .expect("the fake forwarder must answer");
                }
                asked
            })
        }

        /// The OS's bind text as the forwarder returns it to the caller of
        /// `expose`: the status line in the wrapper's own words, the OS's
        /// message in the body.
        const IN_USE: (u16, &str) = (
            500,
            "listen tcp 127.0.0.1:18999: bind: address already in use",
        );

        /// One declared port taken by another process fails the apply
        /// (NET-121): the forward already bound is rolled back with an
        /// unexpose, and the error names the taken port in place of the
        /// forwarder's raw refusal. The caller then withdraws the name, as
        /// it does for every failed apply.
        #[tokio::test]
        async fn a_taken_host_port_fails_the_apply_and_rolls_back() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            // Two declared ports: the first binds, the second is taken, and
            // the third request is the rollback of the first.
            let forwarder =
                forwarder_answering_in_turn(sock.clone(), vec![(200, ""), IN_USE, (200, "")]);
            let err = match apply_ingress(
                &ControlChannel::Unix(sock),
                PUBLISHED,
                LEASE,
                &ingress(&[18080, 18999]),
                None,
                &[],
            )
            .await
            {
                Err(e) => e,
                Ok(_) => panic!("a taken host port must fail the apply"),
            };

            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(
                port_in_use_refusal(&err),
                Some(minimald_rpc::PortInUseRefusal {
                    port: 18999,
                    box_port: 80,
                    holder: minimald_rpc::PortHolder::Host,
                }),
                "the error carries the typed refusal for the finalize to read"
            );
            assert_eq!(
                err.to_string(),
                "Port 18999 is already in use on this machine by another \
                 program on this machine.\nChoose another host port in --ingress (for \
                 example --ingress 19000:80) or in [network] ingress in \
                 minimal.toml.",
                "the error names the taken port and the next step, and no \
                 forwarder internals"
            );
            let asked = forwarder
                .await
                .expect("the fake forwarder served every round");
            assert_eq!(asked.len(), 3, "expose, expose, rollback: {asked:?}");
            assert!(
                asked[2].contains("127.0.64.9:18080"),
                "the rollback releases the forward that bound: {asked:?}"
            );
        }

        /// NET-144 on a VM-backed host, where the daemon cannot probe the
        /// host's ports: finalize binds the declared forwards at publish, and
        /// a port a program on the host holds fails that bind with the same
        /// refusal text as the native probe. On a VM-backed host the host
        /// unbinds the declared forwards, so the rollback asks the switch
        /// for nothing: the forwarder sees exactly the one expose.
        #[tokio::test]
        async fn activation_refused_when_declared_port_is_held_on_a_vm_host_at_publish() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_in_turn(sock.clone(), vec![IN_USE]);
            let err = match apply_declared(
                &ControlChannel::Unix(sock),
                true,
                PUBLISHED,
                LEASE,
                &ingress(&[18999]),
                None,
                &[],
                &|_| minimald_rpc::PortHolder::Host,
            )
            .await
            {
                Err(e) => e,
                Ok(_) => panic!("a held host port must fail the bind at publish"),
            };
            assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
            assert_eq!(
                err.to_string(),
                "Port 18999 is already in use on this machine by another \
                 program on this machine.\nChoose another host port in --ingress (for \
                 example --ingress 19000:80) or in [network] ingress in \
                 minimal.toml.",
                "the VM-backed refusal is the native refusal's text"
            );
            let asked = forwarder.await.expect("the fake forwarder ran");
            assert_eq!(asked.len(), 1, "one expose and no rollback: {asked:?}");
            assert!(
                asked[0].contains("\"local\":\"127.0.64.9:18999\"")
                    && asked[0].contains("\"remote\":\"100.64.128.10:80\""),
                "the bind names the published address and the handed switch address: {asked:?}"
            );
        }

        /// After the bind at publish, the box's first attach posts the same
        /// expose, and the VM host's switch answers that the listener is
        /// already bound. Behind a VM host's gate that answer is the box's
        /// own forward, so the attach tracks it as bound. On a native host
        /// the same answer still fails the apply.
        #[tokio::test]
        async fn activation_refused_when_declared_port_is_held_not_by_the_forward_bound_at_publish()
        {
            for host_holds_listeners in [true, false] {
                let dir = tempfile::TempDir::new().unwrap();
                let sock = dir.path().join("gvproxy.sock");
                let forwarder = forwarder_answering_in_turn(
                    sock.clone(),
                    vec![(500, "proxy already running\n"), (200, "")],
                );
                let applied = apply_declared(
                    &ControlChannel::Unix(sock),
                    host_holds_listeners,
                    PUBLISHED,
                    LEASE,
                    &ingress(&[18080]),
                    None,
                    &[],
                    &|_| minimald_rpc::PortHolder::Host,
                )
                .await;
                if host_holds_listeners {
                    let bound = applied.expect("the forward bound at publish is the box's own");
                    assert_eq!(bound.len(), 1);
                    assert_eq!(bound[0].local(), "127.0.64.9:18080");
                } else {
                    let Err(err) = applied else {
                        panic!("on a native host a bound listener fails");
                    };
                    assert!(port_in_use_refusal(&err).is_none(), "got: {err}");
                }
                forwarder.abort();
            }
        }

        /// The activation probe names exactly the TCP ports another process
        /// holds at the published address. A free port, a yielded port and
        /// a UDP mapping on the held port all stay out of the list, and a
        /// host that binds the forwards itself is not probed at all.
        #[test]
        fn the_probe_names_only_a_port_another_process_holds() {
            let native = ControlChannel::Unix("/nonexistent/gvproxy.sock".into());
            let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let held_port = held.local_addr().unwrap().port();
            let free = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let free_port = free.local_addr().unwrap().port();
            drop(free);

            let mut declared = ingress(&[held_port, free_port]);
            assert_eq!(
                host_ports_in_use(&native, Ipv4Addr::LOCALHOST, &declared, &[]),
                [held_port]
            );
            assert!(
                host_ports_in_use(&native, Ipv4Addr::LOCALHOST, &declared, &[held_port]).is_empty(),
                "a yielded port is the collision report's to name"
            );
            let vm_backed = ControlChannel::Vsock { cid: 2, port: 1024 };
            assert!(
                host_ports_in_use(&vm_backed, Ipv4Addr::LOCALHOST, &declared, &[]).is_empty(),
                "on a VM-backed host the forwarder binds on the host OS, so a \
                 bind in the guest proves nothing and the probe is skipped"
            );
            declared.port_mappings[0].proto = boxes::IpProto::Udp;
            assert!(
                host_ports_in_use(&native, Ipv4Addr::LOCALHOST, &declared, &[]).is_empty(),
                "a UDP mapping is not probed with a TCP bind"
            );
        }

        /// A port held only for a moment, as a parallel probe of the same
        /// port holds it, is not reported: the probe binds again before it
        /// names the port. A port held across every bind still is.
        #[test]
        fn a_port_held_only_for_a_moment_is_not_reported() {
            let native = ControlChannel::Unix("/nonexistent/gvproxy.sock".into());
            let in_use = || Err(io::Error::from(io::ErrorKind::AddrInUse));
            for free_at in 2..=PORT_HELD_BINDS {
                let mut binds = 0;
                assert!(
                    !port_held_by(|| {
                        binds += 1;
                        if binds < free_at { in_use() } else { Ok(()) }
                    }),
                    "a port freed by bind {free_at} is not held by another program"
                );
                assert_eq!(
                    binds, free_at,
                    "the probe stops at the first bind that succeeds"
                );
            }
            let mut binds = 0;
            assert!(
                port_held_by(|| {
                    binds += 1;
                    in_use()
                }),
                "a port that refuses every bind is held"
            );
            assert_eq!(
                binds, PORT_HELD_BINDS,
                "the probe binds before it names a held port"
            );

            let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let port = held.local_addr().unwrap().port();
            let declared = ingress(&[port]);
            let started = std::time::Instant::now();
            assert_eq!(
                host_ports_in_use(&native, Ipv4Addr::LOCALHOST, &declared, &[]),
                [port],
                "a port held across every bind is still reported"
            );
            assert!(
                started.elapsed() >= PORT_HELD_RETRY * (PORT_HELD_BINDS - 1),
                "the probe binds again before it names a held port"
            );
            drop(held);
        }

        /// Only the OS's own words get the taken-port error: any other
        /// refusal of the bind — a permission denied, a missing address, a
        /// crashed forwarder — rolls back and fails with the forwarder's
        /// refusal as it came.
        #[tokio::test]
        async fn any_other_refusal_still_rolls_back_and_fails() {
            let dir = tempfile::TempDir::new().unwrap();
            let sock = dir.path().join("gvproxy.sock");
            let forwarder = forwarder_answering_in_turn(
                sock.clone(),
                vec![(200, ""), (500, "listen tcp: permission denied")],
            );
            let err = match apply_ingress(
                &ControlChannel::Unix(sock),
                PUBLISHED,
                LEASE,
                &ingress(&[18080, 18181]),
                None,
                &[],
            )
            .await
            {
                Err(e) => e,
                Ok(_) => panic!("a refusal that is not the OS's bind text still fails"),
            };

            assert!(
                !is_address_in_use(&err),
                "a permission-denied refusal is not the bind text: {err}"
            );
            forwarder
                .await
                .expect("the fake forwarder served both rounds");
        }

        /// The classifier's own words: the status line the wrapper writes,
        /// the OS's phrase the body carries. A refusal that says either half
        /// alone — a 200 that carries the phrase, a 500 that does not — is
        /// not the bind text.
        #[test]
        fn the_classifier_reads_the_wrappers_own_words() {
            let said = |body: &str| {
                std::io::Error::other(format!(
                    "gvproxy /services/forwarder/expose returned HTTP 500: {body}"
                ))
            };
            assert!(is_address_in_use(&said(
                "listen tcp 127.0.0.1:18999: bind: address already in use"
            )));
            assert!(!is_address_in_use(&said(
                "listen tcp 127.0.0.1:18999: bind: permission denied"
            )));
            assert!(!is_address_in_use(&said("proxy already running")));
            assert!(!is_address_in_use(&std::io::Error::other(
                "connection closed before the answer"
            )));
        }
    }
}
