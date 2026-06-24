//! gvproxy switch lifecycle and IP allocation for `OwnIp` PTasks.
//!
//! This module owns the per-host gvproxy ("gvisor-tap-vsock") switch process
//! and the address book that backs it. An `OwnIp` PTask gets its own network
//! namespace plus a tap device that is bridged into the switch by an async
//! relay (see [`switch`]); from the switch's point of view every PTask is one
//! more L2 client on the same subnet, so two `OwnIp` PTasks on the same host
//! can talk directly (UC6) while a `NoNet` PTask — which never gets a tap or a
//! relay — sees only an empty namespace and cannot egress (UC1).
//!
//! The concrete attachment protocol (HTTP `POST /connect` on the control
//! socket, then HyperKit-framed Ethernet frames — no SCM_RIGHTS fd passing)
//! was pinned by the gvproxy v0.8.9 spike (`docs/spikes/2026-06-21-gvproxy-attachment.md`)
//! and is implemented in [`switch`].
//!
//! Covers R1.4 (gvproxy child lifecycle), R1.6 (per-host IP allocation with no
//! reuse), and R1.8 (structured tracing for every switch lifecycle event).

pub mod dns;
pub mod policy;
pub mod proxy;
pub mod switch;

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::sync::watch;

/// Default gvproxy switch subnet: the RFC 6598 (CGNAT) `100.64.0.0/16` block.
///
/// Chosen so PTask switch addresses never collide with the common RFC 1918
/// ranges a host or its containers already use. Configurable via
/// [`SwitchSubnet`] so a deployment that already uses `100.64/10` can override
/// it.
pub const DEFAULT_SUBNET: SwitchSubnet = SwitchSubnet {
    base: Ipv4Addr::new(100, 64, 0, 0),
    prefix: 16,
};

/// MTU advertised to the switch and the tap devices. gvproxy's own default.
pub const DEFAULT_MTU: u16 = 1500;

/// Stable, locally-administered MAC for the switch gateway.
pub const GATEWAY_MAC: MacAddr = MacAddr([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd]);

/// How long to wait for gvproxy's control socket to appear after spawn.
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for gvproxy to exit after `SIGTERM` before escalating to
/// `SIGKILL`. Mirrors the vmm child teardown budget in `minvmd`.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Errors produced while managing the gvproxy switch or allocating addresses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The prefix length is outside the range accepted by [`SwitchSubnet::new`].
    ///
    /// Distinct from [`SubnetExhausted`](Self::SubnetExhausted): a prefix that
    /// puts the subnet outside `8..=29` is a misconfiguration (the prefix was
    /// never valid), not an exhausted valid subnet.
    #[error("prefix /{0} is outside the valid range /8..=/29 for a gvproxy switch subnet")]
    InvalidPrefix(u8),
    /// The configured subnet has no remaining host address to hand out.
    #[error("gvproxy subnet {0} is exhausted; no free PTask address remains")]
    SubnetExhausted(SwitchSubnet),
    /// A subnet was constructed with a prefix outside the supported `8..=29`
    /// range — a configuration error, distinct from runtime address exhaustion.
    #[error(
        "gvproxy subnet prefix /{0} is invalid; must be in 8..=29 (narrower has \
         no room for a PTask address; wider lets the high octet vary, which the \
         derived MAC cannot keep collision-free)"
    )]
    InvalidPrefix(u8),
    /// Spawning the gvproxy binary failed.
    #[error("spawning gvproxy at {path:?}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// gvproxy's control socket never appeared within [`SOCKET_READY_TIMEOUT`].
    #[error("gvproxy control socket {0:?} did not appear within {1:?}")]
    SocketTimeout(PathBuf, Duration),
    /// Writing the generated gvproxy YAML config failed.
    #[error("writing gvproxy config {path:?}: {source}")]
    WriteConfig {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// gvproxy exited before it was asked to stop.
    #[error("gvproxy exited unexpectedly (status {0:?})")]
    UnexpectedExit(Option<i32>),
    /// An I/O error not attributable to a more specific failure mode.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl MacAddr {
    /// Derives a stable, locally-administered unicast MAC for a switch IP.
    ///
    /// Uses the QEMU OUI `52:54:00` (locally administered) followed by the
    /// low three octets of the address. Within a single `/16` (or narrower)
    /// switch subnet the low three octets are unique, so the derived MAC is
    /// collision-free and deterministic — minimald can pre-seed gvproxy's
    /// static-lease table without round-tripping through DHCP.
    #[must_use]
    pub fn for_switch_ip(ip: Ipv4Addr) -> Self {
        let o = ip.octets();
        Self([0x52, 0x54, 0x00, o[1], o[2], o[3]])
    }
}

/// An IPv4 subnet (`base`/`prefix`) the switch hands addresses out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchSubnet {
    base: Ipv4Addr,
    prefix: u8,
}

impl fmt::Display for SwitchSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

impl Default for SwitchSubnet {
    fn default() -> Self {
        DEFAULT_SUBNET
    }
}

impl SwitchSubnet {
    /// Builds a subnet from a base address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::InvalidPrefix`] for a prefix outside `8..=29`. A
    /// prefix narrower than /29 has no room for the reserved
    /// network/gateway/host-alias/broadcast addresses plus a PTask address. A
    /// prefix wider than /8 lets the high octet vary, which
    /// [`MacAddr::for_switch_ip`] does not fold into the derived MAC, so two
    /// addresses differing only in that octet would collide.
    pub fn new(base: Ipv4Addr, prefix: u8) -> Result<Self, NetError> {
        // Reserve four addresses (network, gateway, host-alias, broadcast): a
        // /29 (8 addresses) leaves four allocatable hosts, a /30 (4) leaves
        // none, so anything narrower than /29 has no room for a PTask. The lower
        // bound keeps MacAddr::for_switch_ip collision-free — it derives the MAC
        // from the low three octets, so the high octet must be pinned by the
        // prefix (/8 or narrower). An out-of-range prefix is a misconfiguration,
        // not runtime exhaustion, so it is reported as InvalidPrefix.
        if !(8..=29).contains(&prefix) {
            return Err(NetError::InvalidPrefix(prefix));
        }
        Ok(Self { base, prefix })
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    /// The prefix length (the `/N` of the subnet), used to render a PTask's
    /// address as CIDR when configuring its tap.
    #[must_use]
    pub fn prefix(self) -> u8 {
        self.prefix
    }

    /// The network address (host bits zeroed).
    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.base) & self.mask())
    }

    /// The broadcast address (host bits set).
    #[must_use]
    pub fn broadcast(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) | !self.mask())
    }

    /// The gateway address: the first usable host (`network + 1`).
    #[must_use]
    pub fn gateway(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network()) + 1)
    }

    /// The host alias address (`broadcast - 1`): a virtual IP that gvproxy NATs
    /// to the host loopback so a PTask can reach host services. Reserved, never
    /// handed to a PTask.
    #[must_use]
    pub fn host_alias(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.broadcast()) - 1)
    }

    /// The first address that may be allocated to a PTask (`network + 2`,
    /// i.e. the first host after the gateway).
    fn first_ptask(self) -> u32 {
        u32::from(self.network()) + 2
    }

    /// The last address that may be allocated to a PTask (`broadcast - 2`,
    /// leaving the host alias at `broadcast - 1` reserved).
    fn last_ptask(self) -> u32 {
        u32::from(self.broadcast()) - 2
    }
}

/// One PTask's place on the switch: a never-reused IP and its derived MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtaskLease {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// Returned by [`GvproxySwitch::attach`].
pub struct AttachResult {
    /// The allocated IP/MAC for this PTask's tap device.
    pub lease: PtaskLease,
    /// Fires (`true`) when gvproxy exits unexpectedly; the PTask should tear
    /// down its tap relay on receipt.
    pub exit_signal: watch::Receiver<bool>,
}

/// Hands out unique switch addresses, never reusing one for the lifetime of
/// the allocator (R1.6).
#[derive(Debug)]
pub struct IpAllocator {
    subnet: SwitchSubnet,
    /// The next host offset to try; only ever advances.
    next: u32,
    /// Every address handed out, in allocation order. Doubles as the
    /// static-lease table written into gvproxy's config.
    leases: Vec<PtaskLease>,
}

impl IpAllocator {
    /// Creates an allocator over the given subnet, starting at the first
    /// allocatable PTask address.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        Self {
            next: subnet.first_ptask(),
            subnet,
            leases: Vec::new(),
        }
    }

    /// The subnet this allocator draws from.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Allocates the next free address and its derived MAC.
    ///
    /// Addresses are sequential and never reused, even after the PTask
    /// detaches, so a stale frame from a torn-down PTask can never be
    /// misdelivered to a freshly-attached one.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::SubnetExhausted`] once the subnet's host range is
    /// used up.
    pub fn allocate(&mut self) -> Result<PtaskLease, NetError> {
        if self.next > self.subnet.last_ptask() {
            return Err(NetError::SubnetExhausted(self.subnet));
        }
        let ip = Ipv4Addr::from(self.next);
        self.next += 1;
        let lease = PtaskLease {
            ip,
            mac: MacAddr::for_switch_ip(ip),
        };
        self.leases.push(lease);
        Ok(lease)
    }

    /// Every lease handed out so far, oldest first.
    #[must_use]
    pub fn leases(&self) -> &[PtaskLease] {
        &self.leases
    }
}

/// Renders the gvproxy YAML config for the given subnet and static leases.
///
/// gvproxy v0.8.9 has no `-subnet` CLI flag: the subnet, gateway, NAT alias,
/// and DHCP static leases are all expressed through a `-config` YAML file (see
/// the spike). minimald owns the allocation table and writes it here before
/// every (re)start so the switch's static leases match minimald's address
/// book.
///
/// gvproxy reads this file only at spawn time, so a rewrite triggered by a
/// later [`attach`](GvproxySwitch::attach) takes effect only on the next switch
/// (re)start. That is intentional: an `OwnIp` PTask configures its switch
/// address statically (the spike's static-lease recipe) rather than via DHCP,
/// so `dhcpStaticLeases` is a startup-time seed, not a live source a running
/// gvproxy must re-read for each new PTask.
#[must_use]
pub fn render_gvproxy_config(subnet: SwitchSubnet, leases: &[PtaskLease]) -> String {
    let mut s = String::with_capacity(256 + leases.len() * 48);
    s.push_str("stack:\n");
    s.push_str(&format!("  mtu: {DEFAULT_MTU}\n"));
    s.push_str(&format!("  subnet: \"{subnet}\"\n"));
    s.push_str(&format!("  gatewayIP: \"{}\"\n", subnet.gateway()));
    s.push_str(&format!("  gatewayMacAddress: \"{GATEWAY_MAC}\"\n"));
    s.push_str("  nat:\n");
    s.push_str(&format!("    \"{}\": \"127.0.0.1\"\n", subnet.host_alias()));
    s.push_str("  gatewayVirtualIPs:\n");
    s.push_str(&format!("    - \"{}\"\n", subnet.host_alias()));
    s.push_str("  dhcpStaticLeases:\n");
    if leases.is_empty() {
        // gvproxy accepts an empty map; keep the key present for clarity.
        s.push_str("    {}\n");
    } else {
        for lease in leases {
            s.push_str(&format!("    \"{}\": \"{}\"\n", lease.ip, lease.mac));
        }
    }
    s
}

/// Supervises the single per-host gvproxy switch process (R1.4).
///
/// The switch is reference-counted against the set of attached `OwnIp` PTasks:
/// it is spawned lazily on the first attach and torn down after the last
/// detach. Teardown follows the same `SIGTERM` → grace → `SIGKILL` escalation
/// the vmm child uses.
#[derive(Debug)]
pub struct GvproxySwitch {
    /// Path to the pinned gvproxy binary (see `scripts/fetch-gvproxy.sh`).
    binary: PathBuf,
    /// Directory for the generated config, control socket, and pid file.
    state_dir: PathBuf,
    /// The address book; also the source of the static-lease table.
    allocator: IpAllocator,
    /// Number of attached PTasks; the switch runs while this is non-zero.
    attached: usize,
    /// The running gvproxy child, if started.
    child: Option<Child>,
    /// Signals attached PTasks when gvproxy exits unexpectedly. Replaced
    /// on each unexpected exit so new attachers get a fresh receiver.
    exit_tx: watch::Sender<bool>,
}

impl GvproxySwitch {
    /// Builds a switch supervisor. Does not spawn anything; the first
    /// [`attach`](Self::attach) starts gvproxy.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self::with_subnet(binary, state_dir, SwitchSubnet::default())
    }

    /// Builds a switch supervisor over a non-default subnet.
    #[must_use]
    pub fn with_subnet(
        binary: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        subnet: SwitchSubnet,
    ) -> Self {
        let (exit_tx, _) = watch::channel(false);
        Self {
            binary: binary.into(),
            state_dir: state_dir.into(),
            allocator: IpAllocator::new(subnet),
            attached: 0,
            child: None,
            exit_tx,
        }
    }

    /// The control socket path gvproxy listens on (host side only).
    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.state_dir.join("gvproxy-api.sock")
    }

    /// The subnet this switch hands PTask addresses out of. The launcher needs
    /// it to render a lease's CIDR and the gateway when configuring a tap.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.allocator.subnet()
    }

    fn config_path(&self) -> PathBuf {
        self.state_dir.join("gvproxy.yaml")
    }

    fn pid_path(&self) -> PathBuf {
        self.state_dir.join("gvproxy.pid")
    }

    /// Allocates an address for a new PTask, (re)writes the config, ensures
    /// gvproxy is running, and bumps the attach count.
    ///
    /// Returns an [`AttachResult`] with the allocated lease and a receiver that
    /// fires `true` when gvproxy exits unexpectedly; the caller should tear down
    /// the PTask's tap relay when the signal fires.
    ///
    /// # Errors
    ///
    /// Propagates config-write, spawn, and socket-readiness failures.
    pub async fn attach(&mut self) -> Result<AttachResult, NetError> {
        let lease = self.allocator.allocate()?;
        self.write_config()?;
        self.ensure_running().await?;
        self.attached += 1;
        tracing::info!(
            ip = %lease.ip,
            mac = %lease.mac,
            attached = self.attached,
            "attached OwnIp PTask to gvproxy switch"
        );
        let exit_signal = self.exit_tx.subscribe();
        Ok(AttachResult { lease, exit_signal })
    }

    /// Records that a PTask detached. When the last one leaves, the switch is
    /// stopped.
    ///
    /// # Errors
    ///
    /// Propagates teardown failures from [`stop`](Self::stop).
    pub async fn detach(&mut self) -> Result<(), NetError> {
        self.attached = self.attached.saturating_sub(1);
        tracing::info!(attached = self.attached, "detached OwnIp PTask from switch");
        if self.attached == 0 {
            self.stop().await?;
        }
        Ok(())
    }

    fn write_config(&self) -> Result<(), NetError> {
        std::fs::create_dir_all(&self.state_dir).map_err(|source| NetError::WriteConfig {
            path: self.state_dir.clone(),
            source,
        })?;
        let path = self.config_path();
        let body = render_gvproxy_config(self.allocator.subnet(), self.allocator.leases());
        std::fs::write(&path, body).map_err(|source| NetError::WriteConfig { path, source })
    }

    /// Spawns gvproxy if it is not already running and waits for its control
    /// socket to appear.
    async fn ensure_running(&mut self) -> Result<(), NetError> {
        if let Some(child) = &mut self.child {
            // Detect a switch that died out from under us so the caller does
            // not relay onto a dead socket (R1.4 unexpected-exit handling).
            match child.try_wait() {
                Ok(Some(status)) => {
                    tracing::error!(
                        ?status,
                        "gvproxy exited unexpectedly; signalling attached PTasks"
                    );
                    // Replace the channel so future attachers get a fresh receiver
                    // while all current receivers fire and know to tear down.
                    let (new_tx, _) = watch::channel(false);
                    let old_tx = std::mem::replace(&mut self.exit_tx, new_tx);
                    let _ = old_tx.send(true);
                    self.child = None;
                    // Do NOT reset self.attached: old PTasks will call detach()
                    // as they observe the exit signal, decrementing the counter
                    // naturally. Resetting here races with new-generation
                    // attachers and can cause a stale detach() to saturating_sub
                    // the new generation's count to 0, triggering a spurious
                    // stop() on a live switch.
                }
                Ok(None) => return Ok(()),
                Err(e) => return Err(NetError::Io(e)),
            }
        }

        let sock = self.control_socket();
        // A stale socket from a previous run blocks gvproxy's own bind. If it
        // cannot be cleared, fail now rather than let `wait_for_socket` mistake
        // the leftover path for a freshly-bound one and report a switch that
        // never actually came up.
        match std::fs::remove_file(&sock) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(NetError::Io(e)),
        }

        let mut cmd = Command::new(&self.binary);
        cmd.arg("-config")
            .arg(self.config_path())
            .arg("-listen")
            .arg(format!("unix://{}", sock.display()))
            .arg("-pid-file")
            .arg(self.pid_path())
            // Disable the default 127.0.0.1:2222 -> 192.168.127.2:22 forward,
            // which targets an address that does not exist on our subnet.
            .arg("-ssh-port")
            .arg("-1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // If the supervisor is dropped without a clean `stop()` (an error path
        // or a panic), make sure gvproxy is reaped rather than orphaned.
        cmd.kill_on_drop(true);

        tracing::info!(binary = %self.binary.display(), socket = %sock.display(), "spawning gvproxy switch");
        let child = cmd.spawn().map_err(|source| NetError::Spawn {
            path: self.binary.clone(),
            source,
        })?;
        self.child = Some(child);

        // If the control socket never appears, tear the half-started child down
        // so its timeout cannot leave gvproxy orphaned and a later attach does
        // not relay onto a process that never bound.
        if let Err(e) = self.wait_for_socket(&sock).await {
            let _ = self.stop().await;
            return Err(e);
        }
        Ok(())
    }

    async fn wait_for_socket(&mut self, sock: &Path) -> Result<(), NetError> {
        let deadline = tokio::time::Instant::now() + SOCKET_READY_TIMEOUT;
        loop {
            // Probe with an actual connect rather than just checking file
            // existence: bind() creates the socket file before listen() is
            // called, so sock.exists() can return true while ECONNREFUSED
            // would still occur in attach_to_switch on a scheduler stall
            // between gvproxy's bind and listen.
            match tokio::net::UnixStream::connect(sock).await {
                Ok(_) => return Ok(()),
                Err(e)
                    if e.kind() == io::ErrorKind::ConnectionRefused
                        || e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(NetError::Io(e)),
            }
            // If gvproxy died during startup, surface its status rather than
            // spinning until the timeout. A try_wait() error (e.g. the child was
            // already reaped) is surfaced too, not swallowed into a misleading
            // SocketTimeout.
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        let code = status.code();
                        self.child = None;
                        return Err(NetError::UnexpectedExit(code));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.child = None;
                        return Err(NetError::Io(e));
                    }
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(NetError::SocketTimeout(
                    sock.to_path_buf(),
                    SOCKET_READY_TIMEOUT,
                ));
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Stops gvproxy with `SIGTERM`, escalating to `SIGKILL` after [`TERM_GRACE`].
    ///
    /// # Errors
    ///
    /// Propagates I/O errors from awaiting the child.
    pub async fn stop(&mut self) -> Result<(), NetError> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Some(pid) = child.id() {
            tracing::info!(pid, "stopping gvproxy switch (SIGTERM)");
            // SAFETY: kill(pid, SIGTERM) only delivers a signal to the named,
            // still-owned child process; it has no other effect and cannot
            // violate any memory invariant.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        match tokio::time::timeout(TERM_GRACE, child.wait()).await {
            Ok(Ok(status)) => {
                tracing::info!(?status, "gvproxy switch stopped");
            }
            Ok(Err(e)) => return Err(NetError::Io(e)),
            Err(_) => {
                tracing::warn!("gvproxy did not exit after SIGTERM; sending SIGKILL");
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
        let _ = std::fs::remove_file(self.control_socket());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_subnet_is_rfc6598_slash16() {
        let s = SwitchSubnet::default();
        assert_eq!(s.to_string(), "100.64.0.0/16");
        assert_eq!(s.gateway(), Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(s.broadcast(), Ipv4Addr::new(100, 64, 255, 255));
        assert_eq!(s.host_alias(), Ipv4Addr::new(100, 64, 255, 254));
    }

    #[test]
    fn allocate_yields_unique_sequential_addresses() {
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let first = a.allocate().unwrap();
        let second = a.allocate().unwrap();
        assert_eq!(first.ip, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(second.ip, Ipv4Addr::new(100, 64, 0, 3));
        assert_ne!(first.ip, second.ip);
        assert_eq!(a.leases().len(), 2);
    }

    #[test]
    fn allocate_never_reuses_after_logical_release() {
        // The allocator has no `free`: addresses only ever advance, so even a
        // long-lived process never hands the same address to two PTasks.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let one = a.allocate().unwrap().ip;
        let two = a.allocate().unwrap().ip;
        let three = a.allocate().unwrap().ip;
        assert!(one < two && two < three);
    }

    #[test]
    fn mac_is_derived_deterministically_from_ip() {
        // 52:54:00 OUI followed by the low three octets of 100.64.0.2 in hex:
        // 64 -> 0x40, 0 -> 0x00, 2 -> 0x02.
        let ip = Ipv4Addr::new(100, 64, 0, 2);
        assert_eq!(MacAddr::for_switch_ip(ip).to_string(), "52:54:00:40:00:02");
        // Stable across calls.
        assert_eq!(MacAddr::for_switch_ip(ip), MacAddr::for_switch_ip(ip));
    }

    #[test]
    fn allocator_exhausts_a_tiny_subnet() {
        // /29 => 8 addresses; network, gateway, host-alias, broadcast reserved,
        // leaving exactly four allocatable hosts (.2 through .5).
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        let mut a = IpAllocator::new(subnet);
        let got: Vec<_> = std::iter::from_fn(|| a.allocate().ok())
            .map(|l| l.ip)
            .collect();
        assert_eq!(
            got,
            vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 4),
                Ipv4Addr::new(10, 0, 0, 5),
            ]
        );
        assert!(matches!(a.allocate(), Err(NetError::SubnetExhausted(_))));
    }

    #[test]
    fn subnet_rejects_overly_narrow_prefix() {
        // /30 is a misconfiguration (no room for a PTask), not an exhausted
        // valid subnet — so the distinct InvalidPrefix error is returned.
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 30),
            Err(NetError::InvalidPrefix(30))
        ));
    }

    #[test]
    fn subnet_rejects_overly_wide_prefix() {
        // A prefix wider than /8 lets the high octet vary, which the derived MAC
        // does not cover, so the constructor rejects it to keep MACs unique.
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 7),
            Err(NetError::InvalidPrefix(7))
        ));
    }

    #[test]
    fn config_contains_subnet_gateway_and_leases() {
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let lease = a.allocate().unwrap();
        let cfg = render_gvproxy_config(a.subnet(), a.leases());
        assert!(cfg.contains("subnet: \"100.64.0.0/16\""));
        assert!(cfg.contains("gatewayIP: \"100.64.0.1\""));
        assert!(cfg.contains(&format!("\"{}\": \"{}\"", lease.ip, lease.mac)));
        // Host alias is NAT'd to loopback and never allocated.
        assert!(cfg.contains("\"100.64.255.254\": \"127.0.0.1\""));
    }

    #[test]
    fn empty_config_still_emits_a_lease_map() {
        let cfg = render_gvproxy_config(SwitchSubnet::default(), &[]);
        assert!(cfg.contains("dhcpStaticLeases:"));
        assert!(cfg.contains("{}"));
    }
}
