//! WireGuard mesh peer for authenticated remote PTask-to-PTask access (Unit 4).
//!
//! `minimald` joins a WireGuard mesh as a **subnet-router** peer: it advertises
//! its local gvproxy switch subnet (see [`super`]) as the AllowedIPs other
//! peers route to, so a packet for a remote PTask's switch IP is carried over
//! the encrypted tunnel to the `minimald` that owns that switch and injected
//! onto it (Tailscale-style subnet-router model, R4.1/R4.2).
//!
//! The WireGuard data plane is [`boringtun`] — a pure-Rust implementation, so
//! no Go/cgo toolchain is pulled into the build (spec Design Considerations).
//! Every per-peer [`boringtun::noise::Tunn`] is driven by one async pump task
//! ([`Mesh::start`]) over a single UDP socket: it encrypts outbound IP packets,
//! decrypts inbound datagrams onto a tunnel sink, completes handshakes, and
//! keeps a live [status snapshot](MeshHandle::status) for the `GetMeshStatus`
//! RPC (R4.6).
//!
//! The whole module is compiled only under the `networking-wg` feature, so the
//! default `minimald` build carries no WireGuard code (R4.7).
//!
//! Covers R4.1 (subnet-router peer, key generation), R4.2 (remote PTask reach
//! over the tunnel), R4.5 (auth-failure logging with no topology leak), R4.6
//! (mesh-status snapshot), and R4.7 (feature-gated).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Largest datagram the pump reads or writes. A WireGuard data packet is the
/// inner MTU plus the fixed transport overhead; 1500 + 80 covers it.
const MAX_DATAGRAM: usize = 1580;

/// How often the pump services per-peer timers (keepalive, rekey, handshake
/// retransmit). WireGuard's own resolution is one second; a quarter-second tick
/// keeps handshake latency low without busy-spinning.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Standard WireGuard persistent-keepalive interval (seconds) for a configured
/// peer, so an established session survives NAT/firewall idle timeouts.
const PERSISTENT_KEEPALIVE: u16 = 25;

/// Errors produced while configuring or running the WireGuard mesh.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WgError {
    /// A base64 WireGuard key was malformed or not 32 bytes.
    #[error("invalid WireGuard key: {0}")]
    InvalidKey(String),
    /// A CIDR string (`a.b.c.d/n`) for an advertised subnet or AllowedIPs entry
    /// could not be parsed.
    #[error("invalid CIDR {value:?}: {reason}")]
    InvalidCidr { value: String, reason: String },
    /// Binding the mesh UDP listener failed.
    #[error("binding WireGuard UDP listener on {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// A 32-byte WireGuard public key, rendered as standard base64 (the format
/// `wg`/`wg-quick` use, so v1 manual key exchange is copy-paste compatible).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WgPublicKey([u8; 32]);

impl WgPublicKey {
    /// The raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Standard-base64 rendering (44 characters).
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

impl From<PublicKey> for WgPublicKey {
    fn from(pk: PublicKey) -> Self {
        Self(pk.to_bytes())
    }
}

impl From<WgPublicKey> for PublicKey {
    fn from(k: WgPublicKey) -> Self {
        PublicKey::from(k.0)
    }
}

impl FromStr for WgPublicKey {
    type Err = WgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|e| WgError::InvalidKey(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WgError::InvalidKey("expected 32 bytes".to_string()))?;
        Ok(Self(arr))
    }
}

impl fmt::Display for WgPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

// A public key is not a secret, but its Debug is still the opaque base64 rather
// than 32 raw bytes — keeps logs readable and consistent with Display.
impl fmt::Debug for WgPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WgPublicKey({})", self.to_base64())
    }
}

/// A WireGuard private key plus its derived public key.
///
/// The [`StaticSecret`] is never logged, serialized through [`Debug`], or
/// exposed; only [`public`](Self::public) and an explicit
/// [`private_base64`](Self::private_base64) (for persisting a generated key to
/// a config the operator controls) leave the type.
pub struct Keypair {
    secret: StaticSecret,
    public: WgPublicKey,
}

impl Keypair {
    /// Generates a fresh keypair from the OS CSPRNG (R4.1 key generation).
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = WgPublicKey::from(PublicKey::from(&secret));
        Self { secret, public }
    }

    /// Rebuilds a keypair from a base64-encoded private key (manual v1 key
    /// exchange / config load).
    ///
    /// # Errors
    ///
    /// Returns [`WgError::InvalidKey`] if the input is not 32 base64 bytes.
    pub fn from_base64(private: &str) -> Result<Self, WgError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(private.trim())
            .map_err(|e| WgError::InvalidKey(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| WgError::InvalidKey("expected 32 bytes".to_string()))?;
        let secret = StaticSecret::from(arr);
        let public = WgPublicKey::from(PublicKey::from(&secret));
        Ok(Self { secret, public })
    }

    /// This node's public key, the identity peers reference and the mesh-status
    /// RPC reports.
    #[must_use]
    pub fn public(&self) -> WgPublicKey {
        self.public
    }

    /// The base64 private key, for persisting a freshly [generated](Self::generate)
    /// key into operator-owned config. Never logged by this module.
    #[must_use]
    pub fn private_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.secret.to_bytes())
    }
}

/// An IPv4 CIDR (`addr/prefix`) used for advertised subnets and per-peer
/// AllowedIPs. A `/32` names a single host; the mesh is IPv4-only (spec
/// non-goal: IPv6 within the switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    /// Builds a CIDR, validating the prefix is `0..=32`.
    ///
    /// # Errors
    ///
    /// Returns [`WgError::InvalidCidr`] for a prefix above 32.
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, WgError> {
        if prefix > 32 {
            return Err(WgError::InvalidCidr {
                value: format!("{addr}/{prefix}"),
                reason: "prefix must be 0..=32".to_string(),
            });
        }
        Ok(Self { addr, prefix })
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    /// Whether `ip` falls within this CIDR — the AllowedIPs routing test.
    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & self.mask() == u32::from(self.addr) & self.mask()
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = WgError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| WgError::InvalidCidr {
            value: s.to_string(),
            reason: reason.to_string(),
        };
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| invalid("missing '/prefix'"))?;
        let addr = addr
            .parse::<Ipv4Addr>()
            .map_err(|e| invalid(&e.to_string()))?;
        let prefix = prefix.parse::<u8>().map_err(|e| invalid(&e.to_string()))?;
        Ipv4Cidr::new(addr, prefix)
    }
}

/// A configured mesh peer (R4.1 — manual key exchange in v1).
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Human-readable peer name, reported in mesh status. Never sent over the
    /// wire and never revealed to an unauthenticated caller (R4.5).
    pub name: String,
    /// The peer's WireGuard public key.
    pub public_key: WgPublicKey,
    /// The peer's UDP endpoint, if known. A peer with no endpoint can only be
    /// reached after it initiates (roaming initiator).
    pub endpoint: Option<SocketAddr>,
    /// Subnets this peer routes for — its advertised switch subnet (and/or a
    /// `/32` for the peer itself). Outbound packets are routed to the peer
    /// whose AllowedIPs contain the destination.
    pub allowed_ips: Vec<Ipv4Cidr>,
}

/// The full mesh configuration for this node.
pub struct MeshConfig {
    /// This node's keypair.
    pub keypair: Keypair,
    /// UDP port the mesh listens on for WireGuard traffic.
    pub listen_port: u16,
    /// Subnets this node advertises to the mesh — typically its gvproxy switch
    /// subnet (R4.1 subnet-router advertisement).
    pub advertised_subnets: Vec<Ipv4Cidr>,
    /// The configured peers.
    pub peers: Vec<PeerConfig>,
}

impl MeshConfig {
    /// Builds a config for a fresh node with a newly generated keypair.
    #[must_use]
    pub fn generate(listen_port: u16, advertised_subnets: Vec<Ipv4Cidr>) -> Self {
        Self {
            keypair: Keypair::generate(),
            listen_port,
            advertised_subnets,
            peers: Vec::new(),
        }
    }
}

/// A point-in-time view of one peer for the mesh-status RPC.
#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub name: String,
    pub public_key: WgPublicKey,
    pub endpoint: Option<SocketAddr>,
    /// Seconds since the last completed handshake, or `None` if no handshake
    /// has completed yet.
    pub last_handshake_secs: Option<u64>,
}

/// A handle to a running mesh: read [status](Self::peers), [inject outbound
/// packets](Self::send_outbound), and keep the pump alive (dropping the handle
/// aborts the pump).
#[derive(Debug)]
pub struct MeshHandle {
    own_public_key: WgPublicKey,
    advertised_subnets: Vec<Ipv4Cidr>,
    outbound: mpsc::Sender<Vec<u8>>,
    status: watch::Receiver<Vec<PeerSnapshot>>,
    pump: JoinHandle<()>,
}

impl MeshHandle {
    /// This node's public key (the identity reported as `own_public_key`).
    #[must_use]
    pub fn own_public_key(&self) -> WgPublicKey {
        self.own_public_key
    }

    /// The subnets this node advertises to the mesh.
    #[must_use]
    pub fn advertised_subnets(&self) -> &[Ipv4Cidr] {
        &self.advertised_subnets
    }

    /// The current per-peer status (name, key, endpoint, last handshake).
    #[must_use]
    pub fn peers(&self) -> Vec<PeerSnapshot> {
        self.status.borrow().clone()
    }

    /// Whether the pump task is still running. The pump `break`s out of its
    /// loop on a fatal socket error, after which the watch snapshot is frozen
    /// and stale; callers (e.g. `GetMeshStatus`) use this to report the mesh as
    /// no longer configured rather than serving dead peer state.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.pump.is_finished()
    }

    /// Queues an outbound IPv4 packet for encryption and routing to the peer
    /// whose AllowedIPs contain its destination. A packet with no matching peer
    /// is dropped by the pump.
    ///
    /// # Errors
    ///
    /// Returns the packet back if the pump has stopped.
    pub fn send_outbound(&self, packet: Vec<u8>) -> Result<(), Vec<u8>> {
        self.outbound.try_send(packet).map_err(|e| e.into_inner())
    }
}

impl Drop for MeshHandle {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// One peer's live runtime state inside the pump.
struct PeerRuntime {
    cfg: PeerConfig,
    tunn: Tunn,
    /// The endpoint we last heard from / send to. Learned from the source of an
    /// inbound datagram when the config carried none.
    endpoint: Option<SocketAddr>,
    /// Whether a handshake has completed, so the transition is logged once.
    handshook: bool,
}

/// Starts the mesh: binds the UDP socket, builds a [`Tunn`] per peer, and
/// spawns the pump task. Decrypted inbound IP packets are delivered to
/// `tunnel_sink`; outbound packets are injected via [`MeshHandle::send_outbound`].
///
/// # Errors
///
/// Returns [`WgError::Bind`] if the UDP listener cannot bind.
pub async fn start(
    config: MeshConfig,
    tunnel_sink: mpsc::Sender<Vec<u8>>,
) -> Result<MeshHandle, WgError> {
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port));
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|source| WgError::Bind {
            addr: bind_addr,
            source,
        })?;
    Ok(build_handle(config, Arc::new(socket), tunnel_sink))
}

/// Starts the mesh on a UDP socket that was already bound by the caller.
///
/// Used when the socket must be created inside a specific network namespace —
/// the two-namespace UC7 integration test binds in each namespace (via `setns`)
/// before handing the socket here. The socket is switched to non-blocking and
/// adopted by the tokio reactor.
///
/// # Errors
///
/// Returns [`WgError::Bind`] if the socket cannot be made non-blocking or
/// adopted by the runtime.
pub fn start_with_socket(
    config: MeshConfig,
    socket: std::net::UdpSocket,
    tunnel_sink: mpsc::Sender<Vec<u8>>,
) -> Result<MeshHandle, WgError> {
    let addr = socket
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.listen_port)));
    socket
        .set_nonblocking(true)
        .map_err(|source| WgError::Bind { addr, source })?;
    let socket = UdpSocket::from_std(socket).map_err(|source| WgError::Bind { addr, source })?;
    Ok(build_handle(config, Arc::new(socket), tunnel_sink))
}

/// Builds the peer runtimes, channels, and status watch, then spawns the pump.
/// Shared by [`start`] and [`start_with_socket`].
fn build_handle(
    config: MeshConfig,
    socket: Arc<UdpSocket>,
    tunnel_sink: mpsc::Sender<Vec<u8>>,
) -> MeshHandle {
    let local_addr = socket.local_addr().ok();

    let own_public_key = config.keypair.public();
    let advertised_subnets = config.advertised_subnets.clone();

    // Build a Tunn per peer. The local index base must be unique per peer; a
    // simple incrementing counter suffices (boringtun shifts it internally).
    let peers: Vec<PeerRuntime> = config
        .peers
        .into_iter()
        .enumerate()
        .map(|(i, cfg)| {
            let tunn = Tunn::new(
                StaticSecret::from(config.keypair.secret.to_bytes()),
                PublicKey::from(cfg.public_key),
                None,
                Some(PERSISTENT_KEEPALIVE),
                (i as u32) + 1,
                None,
            );
            PeerRuntime {
                endpoint: cfg.endpoint,
                cfg,
                tunn,
                handshook: false,
            }
        })
        .collect();

    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
    let (status_tx, status_rx) = watch::channel(initial_snapshot(&peers));

    tracing::info!(
        own_public_key = %own_public_key,
        listen_port = config.listen_port,
        advertised = advertised_subnets.len(),
        peers = peers.len(),
        "starting WireGuard mesh peer"
    );

    let pump = tokio::spawn(pump(
        socket,
        local_addr,
        peers,
        outbound_rx,
        tunnel_sink,
        status_tx,
    ));

    MeshHandle {
        own_public_key,
        advertised_subnets,
        outbound: outbound_tx,
        status: status_rx,
        pump,
    }
}

fn initial_snapshot(peers: &[PeerRuntime]) -> Vec<PeerSnapshot> {
    peers
        .iter()
        .map(|p| PeerSnapshot {
            name: p.cfg.name.clone(),
            public_key: p.cfg.public_key,
            endpoint: p.endpoint,
            last_handshake_secs: None,
        })
        .collect()
}

/// The async pump: one task owns every [`Tunn`] and the single UDP socket, so
/// no `Tunn` is shared across tasks (it is `!Sync`-friendly this way).
async fn pump(
    socket: Arc<UdpSocket>,
    local_addr: Option<SocketAddr>,
    mut peers: Vec<PeerRuntime>,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    tunnel_sink: mpsc::Sender<Vec<u8>>,
    status_tx: watch::Sender<Vec<PeerSnapshot>>,
) {
    // Kick off a handshake with every peer that has a known endpoint, so the
    // tunnel is warm before the first packet (R4.1 mesh join).
    let mut buf = vec![0u8; MAX_DATAGRAM];
    for peer in &mut peers {
        if let Some(endpoint) = peer.endpoint
            && let TunnResult::WriteToNetwork(packet) =
                peer.tunn.format_handshake_initiation(&mut buf, false)
        {
            let out = packet.to_vec();
            let _ = socket.send_to(&out, endpoint).await;
        }
    }

    let mut ticker = tokio::time::interval(TIMER_TICK);
    let mut recv_buf = vec![0u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            // Inbound encrypted datagrams from peers.
            r = socket.recv_from(&mut recv_buf) => {
                match r {
                    Ok((n, src)) => {
                        let datagram: Vec<u8> = recv_buf[..n].to_vec();
                        handle_inbound(&socket, &mut peers, src, &datagram, &tunnel_sink).await;
                        publish_status(&mut peers, &status_tx);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "WireGuard UDP receive failed; stopping mesh pump");
                        break;
                    }
                }
            }
            // Outbound plaintext IP packets to encrypt and route.
            pkt = outbound_rx.recv() => {
                match pkt {
                    Some(packet) => handle_outbound(&socket, &mut peers, &packet, local_addr).await,
                    None => break, // handle dropped
                }
            }
            // Periodic per-peer timer servicing (keepalive, rekey, retransmit).
            _ = ticker.tick() => {
                service_timers(&socket, &mut peers).await;
                publish_status(&mut peers, &status_tx);
            }
        }
    }
}

/// Routes one inbound datagram to its peer, drives `decapsulate` until the
/// network-write queue drains, and forwards any decrypted IP packet to the
/// tunnel sink.
async fn handle_inbound(
    socket: &UdpSocket,
    peers: &mut [PeerRuntime],
    src: SocketAddr,
    datagram: &[u8],
    tunnel_sink: &mpsc::Sender<Vec<u8>>,
) {
    // Try each candidate peer in priority order until one authenticates the
    // datagram. boringtun returns `TunnResult::Err` when the datagram does not
    // belong to a peer's session, so a clean `Err` on the first `decapsulate`
    // is the signal to move to the next candidate; any other result means this
    // peer owns the datagram and we drive it to completion. Probing this way —
    // exact endpoint match first, then every endpoint-less peer — lets a
    // roaming peer (new source address) and any of several endpoint-less peers
    // still be matched, instead of stopping at the single first candidate. Each
    // datagram is decapsulated exactly once for the owning peer (the prior
    // `Err` probes leave no lasting session state and never consume it).
    let mut buf = vec![0u8; MAX_DATAGRAM];
    for idx in route_candidates(peers, src) {
        let mut result = peers[idx]
            .tunn
            .decapsulate(Some(src.ip()), datagram, &mut buf);
        // The first probe of a non-owning peer returns `Err`: skip to the next
        // candidate. (A decode error on the *owning* peer is handled in the
        // drain loop below, where it is logged against the authenticated peer.)
        if matches!(result, TunnResult::Err(_)) {
            continue;
        }
        loop {
            match result {
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    // An authenticated peer's decode error: log the peer name (it
                    // is already authenticated, so this leaks nothing new) and
                    // the error kind, but no addresses (R4.5).
                    tracing::warn!(peer = %peers[idx].cfg.name, error = ?e, "WireGuard decapsulation error");
                    break;
                }
                TunnResult::WriteToNetwork(packet) => {
                    let out = packet.to_vec();
                    // Learn/refresh the peer endpoint from where this arrived.
                    peers[idx].endpoint = Some(src);
                    let _ = socket.send_to(&out, src).await;
                    // Per boringtun: repeat decapsulate with an empty datagram
                    // until Done to flush any further queued network writes.
                    result = peers[idx].tunn.decapsulate(None, &[], &mut buf);
                }
                TunnResult::WriteToTunnelV4(packet, _src_ip) => {
                    let pkt = packet.to_vec();
                    let _ = tunnel_sink.send(pkt).await;
                    break;
                }
                TunnResult::WriteToTunnelV6(_, _) => break, // IPv4-only mesh (spec non-goal)
            }
        }
        return;
    }
    // No candidate authenticated this datagram. Log the bare source only —
    // never a switch IP or PTask name (R4.5: no topology in auth failures).
    tracing::warn!(remote = %src, "WireGuard datagram from unrecognised source dropped");
}

/// The ordered list of peer indices to try for an inbound datagram: the exact
/// endpoint match first (cheapest, the common case), then every endpoint-less
/// peer (each a possible roaming initiator whose endpoint was not
/// preconfigured). With v1 manual config and known endpoints the first entry
/// almost always authenticates.
fn route_candidates(peers: &[PeerRuntime], src: SocketAddr) -> Vec<usize> {
    let mut candidates: Vec<usize> = Vec::new();
    if let Some(i) = peers.iter().position(|p| p.endpoint == Some(src)) {
        candidates.push(i);
    }
    for (i, p) in peers.iter().enumerate() {
        if p.endpoint.is_none() && !candidates.contains(&i) {
            candidates.push(i);
        }
    }
    candidates
}

/// Encrypts one outbound IP packet and sends it to the peer whose AllowedIPs
/// contain the destination address (subnet-router routing, R4.2).
async fn handle_outbound(
    socket: &UdpSocket,
    peers: &mut [PeerRuntime],
    packet: &[u8],
    local_addr: Option<SocketAddr>,
) {
    let Some(IpAddr::V4(dst)) = Tunn::dst_address(packet) else {
        return; // non-IPv4 or unparsable: dropped (IPv4-only mesh)
    };
    let Some(idx) = peers
        .iter()
        .position(|p| p.cfg.allowed_ips.iter().any(|c| c.contains(dst)))
    else {
        tracing::debug!(%dst, "no mesh peer advertises a route for destination; dropping");
        return;
    };
    let Some(endpoint) = peers[idx].endpoint else {
        tracing::debug!(peer = %peers[idx].cfg.name, "peer endpoint unknown; cannot send yet");
        return;
    };
    // Don't loop a packet back to ourselves if a misconfig points a peer at our
    // own listener.
    if local_addr == Some(endpoint) {
        return;
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    match peers[idx].tunn.encapsulate(packet, &mut buf) {
        TunnResult::WriteToNetwork(out) => {
            let out = out.to_vec();
            let _ = socket.send_to(&out, endpoint).await;
        }
        TunnResult::Done => {}
        TunnResult::Err(e) => {
            tracing::warn!(peer = %peers[idx].cfg.name, error = ?e, "WireGuard encapsulation error");
        }
        _ => {}
    }
}

/// Services every peer's WireGuard timers, sending any keepalive/handshake the
/// timer state machine produces.
async fn service_timers(socket: &UdpSocket, peers: &mut [PeerRuntime]) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    for peer in peers.iter_mut() {
        if let TunnResult::WriteToNetwork(packet) = peer.tunn.update_timers(&mut buf)
            && let Some(endpoint) = peer.endpoint
        {
            let out = packet.to_vec();
            let _ = socket.send_to(&out, endpoint).await;
        }
    }
}

/// Rebuilds the status snapshot from live `Tunn` stats and publishes it,
/// logging the first completed handshake per peer (R4.1 peer-change events).
fn publish_status(peers: &mut [PeerRuntime], status_tx: &watch::Sender<Vec<PeerSnapshot>>) {
    let snapshots = peers
        .iter_mut()
        .map(|peer| {
            // stats().0 is the time since the last completed handshake.
            let since = peer.tunn.stats().0;
            if since.is_some() && !peer.handshook {
                peer.handshook = true;
                tracing::info!(
                    peer = %peer.cfg.name,
                    public_key = %peer.cfg.public_key,
                    "WireGuard handshake completed"
                );
            }
            PeerSnapshot {
                name: peer.cfg.name.clone(),
                public_key: peer.cfg.public_key,
                endpoint: peer.endpoint,
                last_handshake_secs: since.map(|d| d.as_secs()),
            }
        })
        .collect::<Vec<_>>();
    // Ignore send error: a closed receiver means the handle was dropped and the
    // pump is about to be aborted.
    let _ = status_tx.send(snapshots);
}

/// Builds the wire-level [`minimald_rpc::MeshStatus`] from a running mesh handle
/// (or the disabled status when there is no mesh).
#[must_use]
pub fn status_response(mesh: Option<&MeshHandle>) -> minimald_rpc::MeshStatus {
    let Some(mesh) = mesh else {
        return minimald_rpc::MeshStatus::unconfigured();
    };
    let peers = mesh
        .peers()
        .into_iter()
        .map(|p| {
            minimald_rpc::MeshPeerStatus::new(
                p.name,
                p.public_key.to_base64(),
                p.endpoint.map(|e| e.to_string()),
                p.last_handshake_secs,
            )
        })
        .collect();
    minimald_rpc::MeshStatus::new(
        mesh.own_public_key().to_base64(),
        mesh.advertised_subnets()
            .iter()
            .map(ToString::to_string)
            .collect(),
        peers,
    )
}

/// Builds a minimal, valid IPv4 packet with a UDP-ish payload for routing the
/// destination address through `dst_address`. Used by the data-plane tests and
/// by callers that need a probe packet; the payload is opaque to WireGuard.
#[must_use]
pub fn ipv4_test_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // identification
    pkt.extend_from_slice(&[0x40, 0]); // flags: don't fragment
    pkt.push(64); // TTL
    pkt.push(17); // protocol: UDP
    pkt.extend_from_slice(&[0, 0]); // header checksum (unchecked by boringtun)
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    pkt.extend_from_slice(payload);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, timeout};

    #[test]
    fn keypair_public_round_trips_through_base64() {
        let kp = Keypair::generate();
        let b64 = kp.public().to_base64();
        let parsed: WgPublicKey = b64.parse().unwrap();
        assert_eq!(parsed, kp.public());
        assert_eq!(b64.len(), 44); // 32 bytes in standard base64
    }

    #[test]
    fn keypair_from_base64_recovers_the_same_public_key() {
        let kp = Keypair::generate();
        let recovered = Keypair::from_base64(&kp.private_base64()).unwrap();
        assert_eq!(recovered.public(), kp.public());
    }

    #[test]
    fn invalid_public_key_is_rejected() {
        assert!("not-base64!!".parse::<WgPublicKey>().is_err());
        // Valid base64 but wrong length.
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(short.parse::<WgPublicKey>().is_err());
    }

    #[test]
    fn cidr_contains_matches_only_addresses_in_range() {
        let net: Ipv4Cidr = "100.64.0.0/16".parse().unwrap();
        assert!(net.contains(Ipv4Addr::new(100, 64, 0, 2)));
        assert!(net.contains(Ipv4Addr::new(100, 64, 255, 254)));
        assert!(!net.contains(Ipv4Addr::new(100, 65, 0, 1)));
        let host: Ipv4Cidr = "10.0.0.5/32".parse().unwrap();
        assert!(host.contains(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(!host.contains(Ipv4Addr::new(10, 0, 0, 6)));
    }

    #[test]
    fn cidr_rejects_bad_prefix_and_shape() {
        assert!("10.0.0.0/33".parse::<Ipv4Cidr>().is_err());
        assert!("10.0.0.0".parse::<Ipv4Cidr>().is_err());
        assert!("nope/8".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn disabled_status_reports_unconfigured() {
        let s = status_response(None);
        assert!(!s.configured);
        assert!(s.own_public_key.is_none());
        assert!(s.peers.is_empty());
    }

    /// Brings up two meshes on loopback, each advertising a `/32` for a fake
    /// switch host and pointing at the other, then drives a real WireGuard
    /// handshake and relays one IP packet A→B through the encrypted tunnel.
    ///
    /// This exercises the full data plane this module owns — key exchange,
    /// handshake, AllowedIPs routing, encapsulate/decapsulate — over real UDP,
    /// and is the runnable counterpart to the `#[ignore]` two-namespace UC7
    /// integration test.
    #[tokio::test]
    async fn two_meshes_handshake_and_relay_a_packet() {
        // Fake "switch" hosts each mesh advertises and routes for.
        let a_switch = Ipv4Addr::new(100, 64, 0, 2);
        let b_switch = Ipv4Addr::new(100, 65, 0, 2);

        let a_kp = Keypair::generate();
        let b_kp = Keypair::generate();
        let a_pub = a_kp.public();
        let b_pub = b_kp.public();

        // Pre-bind two ephemeral loopback sockets so the test never collides with
        // an occupied port or a parallel run; each peer needs the other's bound
        // address up front, which `start_with_socket` lets us supply.
        let a_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let a_port = a_sock.local_addr().unwrap().port();
        let b_port = b_sock.local_addr().unwrap().port();

        let (a_sink_tx, mut a_sink_rx) = mpsc::channel::<Vec<u8>>(8);
        let (b_sink_tx, mut b_sink_rx) = mpsc::channel::<Vec<u8>>(8);

        let a_cfg = MeshConfig {
            keypair: a_kp,
            listen_port: a_port,
            advertised_subnets: vec![Ipv4Cidr::new(a_switch, 32).unwrap()],
            peers: vec![PeerConfig {
                name: "b".to_string(),
                public_key: b_pub,
                endpoint: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, b_port))),
                allowed_ips: vec![Ipv4Cidr::new(b_switch, 32).unwrap()],
            }],
        };
        let b_cfg = MeshConfig {
            keypair: b_kp,
            listen_port: b_port,
            advertised_subnets: vec![Ipv4Cidr::new(b_switch, 32).unwrap()],
            peers: vec![PeerConfig {
                name: "a".to_string(),
                public_key: a_pub,
                endpoint: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, a_port))),
                allowed_ips: vec![Ipv4Cidr::new(a_switch, 32).unwrap()],
            }],
        };

        let a = start_with_socket(a_cfg, a_sock, a_sink_tx).unwrap();
        let b = start_with_socket(b_cfg, b_sock, b_sink_tx).unwrap();

        // Wait for the handshake to complete (status reports a last-handshake).
        let handshook = timeout(Duration::from_secs(5), async {
            loop {
                if a.peers().iter().any(|p| p.last_handshake_secs.is_some())
                    && b.peers().iter().any(|p| p.last_handshake_secs.is_some())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(handshook.is_ok(), "mesh handshake did not complete in time");

        // Send an IP packet from A destined to B's advertised switch host; it
        // must arrive, decrypted, on B's tunnel sink.
        let payload = b"uc7-remote-ptask";
        let packet = ipv4_test_packet(a_switch, b_switch, payload);
        a.send_outbound(packet.clone()).unwrap();

        let received = timeout(Duration::from_secs(5), b_sink_rx.recv())
            .await
            .expect("timed out waiting for tunneled packet")
            .expect("tunnel sink closed");
        assert_eq!(
            &received, &packet,
            "decrypted packet must match what was sent"
        );

        // Nothing should have leaked onto A's own sink.
        assert!(a_sink_rx.try_recv().is_err());

        // Status reflects the established peer.
        let status = status_response(Some(&a));
        assert!(status.configured);
        assert_eq!(
            status.own_public_key.as_deref(),
            Some(a_pub.to_base64()).as_deref()
        );
        assert_eq!(status.peers.len(), 1);
        assert_eq!(status.peers[0].name, "b");
    }
}
