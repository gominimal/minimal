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

pub mod answerer;
pub mod dns;
pub mod loopback;
pub mod policy;
pub mod proxy;
pub mod switch;

// The own-IP switch attach, and the mode-to-provider factory that reaches it.
// Not `#[cfg(not(test))]`: `provider` carries unit tests, and gating the module
// would compile them out.
pub(crate) mod gvproxy_network;
pub(crate) mod provider;

// The DNS gate the relay legs share: pins the addresses a box's allowed
// names resolved to for their admission window (NET-066), refuses denied
// ranges at resolution time (NET-067), and answers AAAA/HTTPS/SVCB empty
// (NET-136). Relay-internal, so no more public than this.
pub(crate) mod dns_gate;

// WireGuard mesh peer (Unit 4). Compiled only under `networking-wg` so the
// default build carries no WireGuard code (R4.7).
#[cfg(feature = "networking-wg")]
pub mod wg;

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::sync::watch;

// The gvproxy-switch primitives (subnet arithmetic, MAC derivation, wire
// constants, `-config` rendering) live in the shared `switch` crate.
// Re-exported here so `minimald::net::{SwitchSubnet, MacAddr, …}` keeps working.
// `::switch` (leading `::`) is the extern crate, disambiguated from the sibling
// `crate::net::switch` relay module.
pub use ::switch::{
    DEFAULT_MTU, DEFAULT_SUBNET, InvalidPrefix, MacAddr, SwitchSubnet, VSOCK_GVPROXY_SHUTTLE_PORT,
    VSOCK_HOST_CID, render_gvproxy_config,
};
// The default address plan itself (NET-102) is imported un-re-exported: the
// plan is a definition the allocation below draws from, not part of the
// `minimald::net::*` vocabulary callers consume.
use ::switch::AddressPlan;

/// How the per-host gvproxy switch is reached, selected by deployment model.
///
/// On DM2 (native Linux) `minimald` owns gvproxy: it is spawned locally and
/// PTask taps attach over its `-listen` UNIX socket. On DM1/3/4 (a libkrun VM)
/// `minvmd` owns the host gvproxy; the in-guest `minimald` does **not** spawn
/// gvproxy — each PTask tap attaches over an AF_VSOCK shuttle to the host
/// switch. Keeping the two as an enum (rather than an `Option<sock>` plus a
/// bool) makes the illegal "spawn locally *and* shuttle to host" state
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SwitchTransport {
    /// DM2: `minimald` spawns + owns gvproxy locally; taps attach over its UNIX
    /// control socket.
    #[default]
    LocalSpawn,
    /// DM1/3/4: gvproxy runs on the host (owned by `minvmd`); taps attach over a
    /// vsock shuttle to `(cid, port)`. `minimald` never spawns gvproxy here.
    HostShuttle { cid: u32, port: u32 },
}

/// How long to wait for gvproxy's control socket to appear after spawn.
const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait for gvproxy to exit after `SIGTERM` before escalating to
/// `SIGKILL`. Mirrors the vmm child teardown budget in `minvmd`.
const TERM_GRACE: Duration = Duration::from_secs(5);

/// Errors produced while managing the gvproxy switch or allocating addresses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// The daemon's self-allocation reserve — the sub-run of the plan's PTask
    /// run it draws task sandboxes and unregistered boxes from — has no
    /// address left. Explicit, never wrapped: a spent address stays spent.
    #[error(
        "the self-allocation reserve on subnet {0} is exhausted; no daemon-side address remains"
    )]
    SubnetExhausted(SwitchSubnet),
    /// The host handed the box a switch address outside the plan's PTask run
    /// (T66): the daemon's subnet cannot honor it, and attaching with it
    /// would source frames from an address no row of the host-side table is
    /// keyed by.
    #[error("handed switch address {address} is outside the plan's PTask run on subnet {subnet}")]
    HandedAddressOutsidePlan {
        address: Ipv4Addr,
        subnet: SwitchSubnet,
    },
    /// The host handed the box a switch address an attach still holds (T66):
    /// two taps on one address would key one PTask's frames to the other's
    /// host-side row, so the collision is refused, never shared. Every lease
    /// is withdrawn when its attach ends ([`IpAllocator::release`], via
    /// [`SwitchClient::detach`]), so the same box re-attaching — the
    /// re-attach an in-process host rebuild produces, where this allocator
    /// survives the rebuild — re-hands its own address instead of meeting
    /// this refusal.
    #[error("handed switch address {address} is already held by a lease (MAC {holder})")]
    HandedAddressCollision { address: Ipv4Addr, holder: MacAddr },
    /// The host handed the box a switch address inside this daemon's
    /// self-allocation reserve (T66) — the sub-run task sandboxes and
    /// unregistered boxes draw from. Host and daemon keep disjoint sub-runs
    /// of the plan's PTask run (the daemon's half is [`self_allocation_run`],
    /// the host's mirror `minvmd`'s `box_registry::hand_out_run`), so a
    /// handed address inside the reserve means the two sides disagree about
    /// the split — a skewed pair, a misconfigured host. Attaching with it
    /// would put the box's tap beside the daemon's own draws; refused, never
    /// shared.
    #[error(
        "handed switch address {address} is inside this daemon's self-allocation reserve on subnet {subnet}"
    )]
    HandedAddressInReserve {
        address: Ipv4Addr,
        subnet: SwitchSubnet,
    },
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

/// One PTask's place on the switch: a never-reused IP and its derived MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtaskLease {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// Returned by [`SwitchClient::attach`].
pub struct AttachResult {
    /// The allocated IP/MAC for this PTask's tap device.
    pub lease: PtaskLease,
    /// Fires (`true`) when gvproxy exits unexpectedly; the PTask should tear
    /// down its tap relay on receipt.
    pub exit_signal: watch::Receiver<bool>,
}

/// The sub-run of `subnet`'s PTask run this daemon **self-allocates** from:
/// the run's lower half, `[first_ptask, midpoint]`, as an inclusive
/// `(first, last)` pair — the hand-out run above it keeps one address
/// more, a PTask run holding an odd number of addresses.
///
/// The plan's PTask run is split into two disjoint sub-runs so the two
/// allocators that draw on it cannot meet: this daemon self-allocates task
/// sandboxes and unregistered boxes from the lower half, and the VM host
/// daemon hands registered boxes only from the upper half — the run above
/// this reserve. The host's half is the same midpoint rule mirrored in
/// `minvmd`'s `box_registry::hand_out_run`; one rule, two statements, so
/// change both together — each side's tests pin the default plan's split
/// literally.
///
/// This is the interim allocation shape (NET-138): task sandboxes
/// self-allocate from the reserve until the task registering every live box
/// host-side retires daemon-side allocation, after which a daemon with a
/// control socket draws nothing — every own-address box arrives handed.
#[must_use]
pub fn self_allocation_run(subnet: SwitchSubnet) -> (u32, u32) {
    let first = subnet.first_ptask();
    let last = subnet.last_ptask();
    let reserve_len = (last - first).div_ceil(2);
    (first, first + reserve_len - 1)
}

/// Hands out unique switch addresses, never reusing a drawn one for the
/// lifetime of the allocator (R1.6).
///
/// Two allocation shapes: [`Self::allocate`] draws a self-allocation from
/// the plan run's lower half — the sub-run [`self_allocation_run`] reserves
/// for this daemon (task sandboxes, unregistered boxes) — and [`Self::hand`]
/// records the address the VM host daemon handed a registered box, from the
/// upper half. The two sub-runs are disjoint, so a self-allocation can never
/// spend a handed address, nor the reverse. A lease's life is its
/// attachment's, handed or drawn alike: it joins the static-lease table the
/// switch is configured from when the tap arrives and leaves with the attach
/// ([`Self::release`], via [`SwitchClient::detach`]), so the table holds only
/// live taps. The never-reuse rule is carried by the draw cursor, not by the
/// table — `next` never regresses, so a withdrawn drawn address is never
/// re-drawn, and it is never handed either (it sits in the reserve, which
/// [`Self::hand`] refuses). A handed address, by contrast, is the registered
/// box's — the host-side row is keyed by it — and the same box re-attaching
/// re-hands it; that re-hand is not a reuse: it is the same row coming back,
/// and the collision refusal guards only an address an attach still holds.
///
/// The interim this shape ships in: task sandboxes self-allocate from the
/// reserve until the task registering every live box host-side (NET-138)
/// retires self-allocation, after which no daemon-side draw happens once a
/// control socket exists — every own-address box arrives handed.
#[derive(Debug)]
pub struct IpAllocator {
    subnet: SwitchSubnet,
    /// This daemon's self-allocation reserve, inclusive — both bounds from
    /// [`self_allocation_run`]. `allocate` draws inside it and nothing else.
    reserve: (u32, u32),
    /// The next host offset to draw for a self-allocation; only ever
    /// advances, within the reserve.
    next: u32,
    /// Every address handed out, in allocation order. Doubles as the
    /// static-lease table written into gvproxy's config, which therefore
    /// holds only live taps: a lease leaves with its attach
    /// ([`Self::release`]), handed or drawn alike.
    leases: Vec<PtaskLease>,
}

impl IpAllocator {
    /// Creates an allocator over the given subnet, starting at the first
    /// allocatable PTask address.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        Self {
            next: subnet.first_ptask(),
            reserve: self_allocation_run(subnet),
            subnet,
            leases: Vec::new(),
        }
    }

    /// Creates an allocator over the switch crate's default address plan
    /// (NET-102): the block an un-enrolled host self-allocates box addresses
    /// from, because no control plane has handed it one. The plan's switch
    /// subnet is where the leases come from; its reserved local range is where
    /// their published addresses will.
    #[must_use]
    pub fn for_default_plan() -> Self {
        Self::new(AddressPlan::default().switch_subnet())
    }

    /// The subnet this allocator draws from.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Allocates the next free address and its derived MAC, drawing from the
    /// daemon's self-allocation reserve — the plan run's lower half.
    ///
    /// Addresses are sequential and never reused, even after the PTask
    /// detaches, so a stale frame from a torn-down PTask can never be
    /// misdelivered to a freshly-attached one.
    ///
    /// # Errors
    ///
    /// Returns [`NetError::SubnetExhausted`] once the reserve is used up —
    /// explicitly, with no wrap and no reuse; a spent address stays spent.
    pub fn allocate(&mut self) -> Result<PtaskLease, NetError> {
        if self.next > self.reserve.1 {
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

    /// Records `ip` as the switch address a registered box attaches at (T66):
    /// the VM host daemon allocated it into its table and handed it back, so
    /// the daemon mints nothing. The lease joins [`Self::leases`] — the
    /// static-lease table the switch is configured from — and leaves with
    /// the box's attach ([`Self::release`]), so the same box re-attaching
    /// re-hands it: the host's persisted row still holds the address, and
    /// detach never touches that row. A drawn lease ([`Self::allocate`])
    /// leaves the same way, and its address is never seen again — the draw
    /// cursor never regresses, and the reserve [`Self::hand`] refuses — so
    /// the never-reuse rule (R1.6) is carried by the cursor, not by a lease
    /// the table keeps for a tap that is gone.
    ///
    /// Three refusals, never a share:
    ///
    /// * an address outside the plan's PTask run
    ///   ([`NetError::HandedAddressOutsidePlan`]) — the subnet cannot honor
    ///   it;
    /// * an address inside this daemon's self-allocation reserve
    ///   ([`NetError::HandedAddressInReserve`]) — the host hands only from
    ///   the run above the reserve, so one there means the two sides
    ///   disagree about the split;
    /// * an address a recorded lease still holds
    ///   ([`NetError::HandedAddressCollision`]) — two taps on one address
    ///   would key one PTask's frames to the other's host-side row. What the
    ///   refusal guards is a live attach: the lease of an attach that ended
    ///   is withdrawn ([`Self::release`]), so the same box's re-attach
    ///   re-hands its own address instead of meeting this refusal.
    ///
    /// # Errors
    ///
    /// [`NetError::HandedAddressOutsidePlan`] when `ip` is outside the
    /// plan's PTask run: the address cannot be honored on this subnet.
    /// [`NetError::HandedAddressInReserve`] when `ip` is inside the daemon's
    /// self-allocation reserve. [`NetError::HandedAddressCollision`] when a
    /// recorded lease still holds `ip`.
    pub fn hand(&mut self, ip: Ipv4Addr) -> Result<PtaskLease, NetError> {
        let ip_num = u32::from(ip);
        if ip_num < self.subnet.first_ptask() || ip_num > self.subnet.last_ptask() {
            return Err(NetError::HandedAddressOutsidePlan {
                address: ip,
                subnet: self.subnet,
            });
        }
        let (reserve_first, reserve_last) = self.reserve;
        if (reserve_first..=reserve_last).contains(&ip_num) {
            return Err(NetError::HandedAddressInReserve {
                address: ip,
                subnet: self.subnet,
            });
        }
        if let Some(lease) = self.leases.iter().find(|lease| lease.ip == ip) {
            return Err(NetError::HandedAddressCollision {
                address: ip,
                holder: lease.mac,
            });
        }
        let lease = PtaskLease {
            ip,
            mac: MacAddr::for_switch_ip(ip),
        };
        self.leases.push(lease);
        Ok(lease)
    }

    /// Withdraws the lease for `ip`, when the allocator holds one: the
    /// attachment ended, so the lease ends with it — every attachment's,
    /// handed or drawn alike. A handed address is free for the same box to
    /// re-hand on the re-attach an in-process host rebuild or a restart
    /// produces (T66): the host's persisted row still holds it, and nothing
    /// here does. A drawn address is never re-drawn — the draw cursor never
    /// regresses (R1.6), so a stale frame from a torn-down PTask can never be
    /// misdelivered to a freshly-attached one — and never handed either: it
    /// sits in the reserve [`Self::hand`] refuses. An address the allocator
    /// never recorded withdraws nothing.
    ///
    /// Returns whether a lease was withdrawn.
    pub(crate) fn release(&mut self, ip: Ipv4Addr) -> bool {
        let held = self.leases.iter().any(|lease| lease.ip == ip);
        self.leases.retain(|lease| lease.ip != ip);
        held
    }
}

impl Default for IpAllocator {
    /// The plan an un-enrolled host self-allocates from (NET-102): an
    /// allocator with no subnet named draws from the switch crate's default
    /// plan rather than an implicit constant of its own.
    fn default() -> Self {
        Self::for_default_plan()
    }
}

///
/// The switch is reference-counted against the set of attached `OwnIp` PTasks:
/// it is spawned lazily on the first attach and torn down after the last
/// detach. Teardown follows the same `SIGTERM` → grace → `SIGKILL` escalation
/// the vmm child uses.
#[derive(Debug)]
pub struct SwitchClient {
    /// Path to the pinned gvproxy binary (see `scripts/fetch-gvproxy.sh`).
    binary: PathBuf,
    /// Directory for the generated config, control socket, and pid file.
    state_dir: PathBuf,
    /// The address book; also the source of the static-lease table.
    allocator: IpAllocator,
    /// Number of attached PTasks; the switch runs while this is non-zero.
    attached: usize,
    /// The running gvproxy child, if started. Always `None` in
    /// [`SwitchTransport::HostShuttle`] mode (the host owns gvproxy).
    child: Option<Child>,
    /// Signals attached PTasks when gvproxy exits unexpectedly. Replaced
    /// on each unexpected exit so new attachers get a fresh receiver.
    exit_tx: watch::Sender<bool>,
    /// How PTask taps reach the switch: local spawn (DM2) or a
    /// vsock shuttle to the host gvproxy (DM1/3/4).
    transport: SwitchTransport,
    /// Which daemon instance this switch belongs to, as a hostname label:
    /// the daemon's own id, which the `OwnIp` attach path registers its
    /// DNS names under so two daemons on one host mint distinct ones
    /// (NET-027). Defaults to the single-daemon id `local`.
    host_id: String,
}

impl SwitchClient {
    /// Builds a switch supervisor. Does not spawn anything; the first
    /// [`attach`](Self::attach) starts gvproxy. The allocator draws from the
    /// switch crate's default address plan (NET-102) — the block an un-enrolled
    /// host self-allocates from.
    #[must_use]
    pub fn new(binary: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self::with_subnet(binary, state_dir, AddressPlan::default().switch_subnet())
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
            transport: SwitchTransport::default(),
            host_id: crate::net::dns::DEFAULT_HOST_ID.to_owned(),
        }
    }

    /// Names this daemon instance's DNS registrations under a host id other
    /// than the single-daemon default. The daemon passes its own instance
    /// id, so a second daemon on the same host registers under its own
    /// label instead of overwriting the first's records.
    #[must_use]
    pub fn with_host_id(mut self, host_id: impl Into<String>) -> Self {
        self.host_id = host_id.into();
        self
    }

    /// The host id this daemon's `OwnIp` DNS names register under.
    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Sets how PTask taps reach the switch. The DM2 default is
    /// [`SwitchTransport::LocalSpawn`]; in a libkrun VM (DM1/3/4) the caller sets
    /// [`SwitchTransport::HostShuttle`] so this `minimald` attaches taps to the
    /// host-owned gvproxy over vsock instead of spawning gvproxy in-guest.
    #[must_use]
    pub fn with_transport(mut self, transport: SwitchTransport) -> Self {
        self.transport = transport;
        self
    }

    /// How this switch's PTask taps reach the gvproxy switch.
    #[must_use]
    pub fn transport(&self) -> SwitchTransport {
        self.transport
    }

    /// How many `OwnIp` PTasks are attached; the switch runs while non-zero.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.attached
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

    /// Every lease this switch knows — self-allocated and handed (T66)
    /// alike, oldest first — the table the generated config is written
    /// from. A diagnostic surface for the addresses the switch has handed
    /// out and which shape of attach took them, without reaching into the
    /// allocator.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn leases(&self) -> &[PtaskLease] {
        self.allocator.leases()
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
        // DM2 spawns + configures gvproxy locally; DM1/3/4 (HostShuttle) leaves
        // gvproxy to `minvmd` on the host, so skip the spawn/config steps and
        // only track the attach count.
        if matches!(self.transport, SwitchTransport::LocalSpawn) {
            self.write_config().await?;
            self.ensure_running().await?;
        }
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

    /// Attaches a PTask with the switch address the host handed it (T66)
    /// instead of drawing one: the box was registered on the host-side table
    /// keyed by this address, so the daemon reuses it and mints nothing.
    ///
    /// The handed address is recorded like an allocated one — it joins the
    /// static-lease table the switch is configured from
    /// ([`IpAllocator::hand`]) — and leaves with the attach: [`Self::detach`]
    /// withdraws it, so the same box's re-attach re-hands it. That re-handed
    /// address comes from the host's persisted row — the registration
    /// allocated it into the host-side table and nothing on the host
    /// withdraws it — and detach never touches that row: the daemon-side
    /// lease ends with the attach, the host-side row does not. What this
    /// daemon cannot yet check is that the address it is handed is still the
    /// row's for this box: the host-row check by box id — the same address
    /// for the same box, a refusal on mismatch — lands with the box id in
    /// the registration (T44, #1660, NET-133), which names it as the gap;
    /// until then this daemon attaches with whatever the create request
    /// carries. A drawn lease, by contrast, is never re-drawn: the draw
    /// cursor never regresses (the never-reuse rule). Everything else
    /// matches [`Self::attach`], including the DM2 config/spawn steps
    /// and the attach count.
    ///
    /// # Errors
    ///
    /// [`NetError::HandedAddressOutsidePlan`] when the host handed an
    /// address this daemon's subnet cannot honor,
    /// [`NetError::HandedAddressInReserve`] when it handed one from the
    /// daemon's own self-allocation reserve, and
    /// [`NetError::HandedAddressCollision`] when an attach still holds the
    /// handed address; propagates config-write, spawn, and socket-readiness
    /// failures as [`Self::attach`] does.
    pub async fn attach_handed(&mut self, handed: Ipv4Addr) -> Result<AttachResult, NetError> {
        let lease = self.allocator.hand(handed)?;
        // DM2 spawns + configures gvproxy locally; DM1/3/4 (HostShuttle) leaves
        // gvproxy to `minvmd` on the host, so skip the spawn/config steps and
        // only track the attach count — same shape as [`Self::attach`].
        if matches!(self.transport, SwitchTransport::LocalSpawn) {
            self.write_config().await?;
            self.ensure_running().await?;
        }
        self.attached += 1;
        tracing::info!(
            ip = %lease.ip,
            mac = %lease.mac,
            attached = self.attached,
            "attached OwnIp PTask to gvproxy switch at its handed address"
        );
        let exit_signal = self.exit_tx.subscribe();
        Ok(AttachResult { lease, exit_signal })
    }

    /// Records that a PTask detached, withdrawing its lease with it (T66):
    /// a lease's life is its attachment's, handed or drawn alike — a task
    /// sandbox's self-drawn address ends with the sandbox the way a
    /// registered box's handed one ends with the box's attach. The handed
    /// address is the registered box's, keyed by the host-side row, so once
    /// the box's attach ends the same box re-attaching re-hands it — the
    /// collision refusal then guards only an address an attach still holds.
    /// A drawn address is never re-drawn: the allocator's draw cursor never
    /// regresses (R1.6), so the rule holds without the table keeping a lease
    /// for a tap that is gone; see [`IpAllocator::release`]. When the last
    /// one leaves, the switch is stopped.
    ///
    /// # Errors
    ///
    /// Propagates teardown failures from [`stop`](Self::stop).
    pub async fn detach(&mut self, released: Ipv4Addr) -> Result<(), NetError> {
        self.attached = self.attached.saturating_sub(1);
        if self.allocator.release(released) {
            tracing::debug!(ip = %released, "released the lease with the attach");
        }
        tracing::info!(attached = self.attached, "detached OwnIp PTask from switch");
        if self.attached == 0 {
            self.stop().await?;
        }
        Ok(())
    }

    async fn write_config(&self) -> Result<(), NetError> {
        tokio::fs::create_dir_all(&self.state_dir)
            .await
            .map_err(|source| NetError::WriteConfig {
                path: self.state_dir.clone(),
                source,
            })?;
        let path = self.config_path();
        let leases: Vec<_> = self
            .allocator
            .leases()
            .iter()
            .map(|l| (l.ip, l.mac))
            .collect();
        let body = render_gvproxy_config(self.allocator.subnet(), &leases);
        tokio::fs::write(&path, body)
            .await
            .map_err(|source| NetError::WriteConfig { path, source })
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
        match tokio::fs::remove_file(&sock).await {
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
        let _ = tokio::fs::remove_file(self.control_socket()).await;
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
    fn allocator_uses_default_plan() {
        // NET-102: an un-enrolled host self-allocates box addresses from the
        // switch crate's default plan, so an allocator with no subnet named
        // draws from that plan rather than a constant of minimald's own.
        let plan = AddressPlan::default();
        let mut a = IpAllocator::for_default_plan();
        assert_eq!(a.subnet(), plan.switch_subnet());
        // The first lease is the plan's first allocatable box address...
        let lease = a.allocate().unwrap();
        assert_eq!(lease.ip, Ipv4Addr::from(plan.switch_subnet().first_ptask()));
        assert_eq!(lease.ip, Ipv4Addr::new(100, 64, 0, 2));
        // ...and the default allocator is the same one.
        assert_eq!(
            IpAllocator::default().allocate().unwrap().ip,
            Ipv4Addr::new(100, 64, 0, 2)
        );
        // The plan's reserved local range — where those boxes' published
        // addresses come from on the host's loopback — is the same block the
        // zone's published names answer at (NET-127). One definition now: the
        // answerer re-exports the switch crate's constant, so this asserts the
        // plan is built from the range it serves rather than bridging two
        // constants that could drift.
        assert_eq!(
            plan.reserved_local_range(),
            crate::net::dns::RESERVED_LOCAL_RANGE
        );
        // Every loopback slice the plan pairs with one of its switches stays
        // inside that range, so a published box answers on the host's
        // loopback, at an address no other switch on the host holds.
        let (range_net, range_prefix) = plan.reserved_local_range();
        let range_first = u32::from(range_net);
        let range_len = 1u32 << (32 - range_prefix);
        for index in 0..plan.switch_capacity() {
            let slice = plan.switch_slice(index).unwrap().loopback();
            assert!(u32::from(slice.first()) >= range_first);
            assert!(u32::from(slice.last()) < range_first + range_len);
        }
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
        // /29 => 8 addresses; network, gateway, proxy, daemon, host-alias,
        // broadcast reserved, leaving exactly two allocatable hosts (.2 and
        // .3). The run splits at its midpoint, so this daemon's reserve is .2
        // alone and the host's hand-out run is .3 alone — exhaustion is
        // explicit on each side, with no wrap and no reuse. The proxy's
        // address (.4, `broadcast - 3`) is infrastructure above the run, so
        // it is refused as a handed address, exactly as one past the run
        // would be.
        let subnet = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        assert_eq!(
            subnet.box_egress_proxy_address(),
            Ipv4Addr::new(10, 0, 0, 4)
        );
        let mut a = IpAllocator::new(subnet);
        assert_eq!(a.allocate().unwrap().ip, Ipv4Addr::new(10, 0, 0, 2));
        assert!(matches!(a.allocate(), Err(NetError::SubnetExhausted(_))));
        // The reserve bounds only the daemon's draws: the run's remainder is
        // still there for the host's hand-outs, none of them ever drawn.
        a.hand(Ipv4Addr::new(10, 0, 0, 3)).unwrap();
        assert!(matches!(
            a.hand(Ipv4Addr::new(10, 0, 0, 4)),
            Err(NetError::HandedAddressOutsidePlan { .. })
        ));
        assert!(matches!(
            a.hand(Ipv4Addr::new(10, 0, 0, 3)),
            Err(NetError::HandedAddressCollision { .. })
        ));
    }

    #[test]
    fn self_allocation_run_splits_the_plan_ptask_run() {
        // The default plan's split, pinned literally: the daemon's reserve
        // is the PTask run's lower half and the host hands registered boxes
        // from the run above it. The mirror is `minvmd`'s
        // `box_registry::hand_out_run` — one rule, two statements; change
        // both together.
        let subnet = SwitchSubnet::default();
        let (reserve_first, reserve_last) = self_allocation_run(subnet);
        assert_eq!(
            (reserve_first, reserve_last),
            (
                u32::from(Ipv4Addr::new(100, 64, 0, 2)),
                u32::from(Ipv4Addr::new(100, 64, 127, 254)),
            ),
            "the reserve is the run's lower half, starting at the first PTask address"
        );
        assert_eq!(
            reserve_last + 1,
            u32::from(Ipv4Addr::new(100, 64, 127, 255)),
            "the host's hand-out run starts immediately above the reserve"
        );
        assert!(
            subnet.first_ptask() <= reserve_first && reserve_last < subnet.last_ptask(),
            "both sub-runs are inside the plan's PTask run, and neither is empty"
        );
        // A tiny subnet splits in half, so both sides keep at least one
        // address: a /29's two PTask addresses give the reserve .2 and the
        // hand-out run .3 alone (the proxy at .4 sits above the run).
        let tiny = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 29).unwrap();
        assert_eq!(
            self_allocation_run(tiny),
            (
                u32::from(Ipv4Addr::new(10, 0, 0, 2)),
                u32::from(Ipv4Addr::new(10, 0, 0, 2)),
            )
        );
    }

    #[test]
    fn hand_refuses_an_address_in_the_self_allocation_reserve() {
        // The host hands registered boxes only from the run above this
        // daemon's self-allocation reserve, so an address inside the reserve
        // means the two sides disagree about the split — a skewed pair, a
        // misconfigured host. Refused, never attached beside the daemon's
        // own draws: the sequence a shared run once allowed, a task sandbox
        // self-allocating an address a box is then handed, ends at the
        // refusal.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let task = a.allocate().unwrap();
        assert_eq!(task.ip, Ipv4Addr::new(100, 64, 0, 2));
        let err = a.hand(task.ip).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::HandedAddressInReserve { address, .. } if address == task.ip
            ),
            "handing a reserve address is refused, held or not"
        );
        // The refusal is positional, not lease-dependent: an unheld reserve
        // address refuses the same way, and a refusal records nothing — the
        // table holds the task's draw alone.
        assert!(matches!(
            a.hand(Ipv4Addr::new(100, 64, 64, 128)),
            Err(NetError::HandedAddressInReserve { .. })
        ));
        assert_eq!(a.leases().len(), 1, "a refusal adds no lease");
        // The task's address stays the task's: the next draw takes the
        // reserve's next address, never the refused one again.
        assert_eq!(a.allocate().unwrap().ip, Ipv4Addr::new(100, 64, 0, 3));
    }

    #[test]
    fn hand_refuses_an_address_a_local_lease_holds() {
        // An address a recorded lease still holds refuses a second hand:
        // two taps on one address would key one PTask's frames to the
        // other's host-side row. What the refusal guards is a live attach —
        // `handed_lease_releases_on_detach_and_the_box_rehands` covers the
        // release that lets the same box re-attach. With the run split, a
        // locally-drawn lease always sits in the daemon's reserve
        // (`hand_refuses_an_address_in_the_self_allocation_reserve` refuses
        // that shape outright), so the lease this one exercises is a handed
        // one — the same refusal rule.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let box_a = a.hand(Ipv4Addr::new(100, 64, 127, 255)).unwrap();
        // A task's sandbox self-allocates beside it, from the reserve...
        let task = a.allocate().unwrap();
        assert_eq!(task.ip, Ipv4Addr::new(100, 64, 0, 2));
        // ...and handing the box's address again is refused with the holder
        // named. The refusal changes nothing: no duplicate joined the table,
        // and handing the same address again refuses just the same — the
        // address stays with its holder while its attach lives.
        let err = a.hand(box_a.ip).unwrap_err();
        assert!(
            matches!(
                err,
                NetError::HandedAddressCollision { address, holder }
                    if address == box_a.ip && holder == box_a.mac
            ),
            "handing a lease's address is refused with the holder named"
        );
        assert_eq!(a.leases().len(), 2);
        assert!(matches!(
            a.hand(box_a.ip),
            Err(NetError::HandedAddressCollision { .. })
        ));
    }

    #[test]
    fn handed_lease_releases_on_detach_and_the_box_rehands() {
        // T66's re-attach: a lease — handed or drawn alike — leaves the
        // table when its attach ends, so the same box re-attaching — the
        // re-attach an in-process host rebuild produces, where this
        // allocator survives the rebuild — re-hands its own address instead
        // of meeting the collision refusal.
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let handed_ip = Ipv4Addr::new(100, 64, 128, 9);
        let lease = a
            .hand(handed_ip)
            .expect("the hand-out run's address is handed");
        assert_eq!(a.leases().len(), 1);

        // A drawn lease leaves the same way — a task sandbox's self-drawn
        // address ends with its sandbox — and the never-reuse rule (R1.6) is
        // carried by the cursor, not by the table: the next draw is a higher
        // address, never the withdrawn one.
        let task = a.allocate().unwrap();
        assert!(a.release(task.ip), "the drawn lease is withdrawn");
        assert_eq!(a.leases(), &[lease], "only the handed lease remains");
        let redrawn = a.allocate().unwrap();
        assert_eq!(
            redrawn.ip,
            Ipv4Addr::new(100, 64, 0, 3),
            "the withdrawn address is never re-drawn"
        );
        // An address the allocator never recorded releases nothing.
        assert!(!a.release(Ipv4Addr::new(100, 64, 200, 1)));
        assert_eq!(a.leases().len(), 2);

        // A handed address an attach still holds refuses a second hand: the
        // refusal guards a live attach, and the lease's withdrawal is what
        // lets the re-attach through.
        assert!(matches!(
            a.hand(handed_ip),
            Err(NetError::HandedAddressCollision { .. })
        ));

        // The handed lease releases, and the re-hand records the same lease
        // again — the same address, the same derived MAC, the same row the
        // host-side table is keyed by — beside the draw that replaced the
        // withdrawn one.
        assert!(a.release(handed_ip));
        assert_eq!(
            a.leases(),
            &[redrawn],
            "the table holds the live draw alone"
        );
        let rehanded = a
            .hand(handed_ip)
            .expect("the same box re-attaching re-hands its own address");
        assert_eq!(rehanded.ip, lease.ip);
        assert_eq!(rehanded.mac, lease.mac);
    }

    #[test]
    fn subnet_rejects_overly_narrow_prefix() {
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 30),
            Err(InvalidPrefix(30))
        ));
    }

    #[test]
    fn subnet_rejects_overly_wide_prefix() {
        // A prefix wider than /8 lets the high octet vary, which the derived MAC
        // does not cover, so the constructor rejects it to keep MACs unique.
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 7),
            Err(InvalidPrefix(7))
        ));
    }

    #[test]
    fn config_contains_subnet_gateway_and_leases() {
        let mut a = IpAllocator::new(SwitchSubnet::default());
        let lease = a.allocate().unwrap();
        let leases: Vec<_> = a.leases().iter().map(|l| (l.ip, l.mac)).collect();
        let cfg = render_gvproxy_config(a.subnet(), &leases);
        assert!(cfg.contains("subnet: \"100.64.0.0/16\""));
        assert!(cfg.contains("gatewayIP: \"100.64.0.1\""));
        assert!(cfg.contains(&format!("\"{}\": \"{}\"", lease.ip, lease.mac)));
        // NET-132: the box egress proxy address is infrastructure and must not be
        // handled by gvproxy's NAT or virtual-IP machinery.
        assert!(!cfg.contains("100.64.255.252"));
        // Host alias is NAT'd to loopback and never allocated.
        assert!(cfg.contains("\"100.64.255.254\": \"127.0.0.1\""));
        // NET-003: the static zone entry the bundle's switch-configuration copy
        // shows — `host` answered in `min.internal.` at the NAT'd alias.
        assert!(cfg.contains("    - name: \"min.internal.\"\n"));
        assert!(cfg.contains("        - name: \"host\"\n          ip: \"100.64.255.254\"\n"));
    }

    #[test]
    fn empty_config_still_emits_a_lease_map() {
        let cfg = render_gvproxy_config(SwitchSubnet::default(), &[]);
        assert!(cfg.contains("dhcpStaticLeases:"));
        assert!(cfg.contains("{}"));
    }

    #[test]
    fn transport_defaults_to_local_spawn() {
        let switch = SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy");
        assert_eq!(switch.transport(), SwitchTransport::LocalSpawn);
    }

    #[test]
    fn with_transport_selects_host_shuttle() {
        let switch = SwitchClient::new("/usr/bin/gvproxy", "/run/minimal/gvproxy").with_transport(
            SwitchTransport::HostShuttle {
                cid: VSOCK_HOST_CID,
                port: VSOCK_GVPROXY_SHUTTLE_PORT,
            },
        );
        assert_eq!(
            switch.transport(),
            SwitchTransport::HostShuttle { cid: 2, port: 1024 }
        );
    }

    #[tokio::test]
    async fn host_shuttle_attach_allocates_without_spawning_gvproxy() {
        // In HostShuttle mode `minvmd` owns gvproxy, so `attach` must not try to
        // spawn the (here nonexistent) binary: it allocates a lease and only
        // tracks the attach count. A LocalSpawn switch pointed at the same
        // missing binary would instead fail in `ensure_running`.
        let dir = tempfile::TempDir::new().expect("tempdir");
        let mut switch =
            SwitchClient::new("/nonexistent/gvproxy-binary", dir.path().join("gvproxy"))
                .with_transport(SwitchTransport::HostShuttle {
                    cid: VSOCK_HOST_CID,
                    port: VSOCK_GVPROXY_SHUTTLE_PORT,
                });

        let result = switch.attach().await.expect("host-shuttle attach");
        assert_eq!(result.lease.ip, Ipv4Addr::new(100, 64, 0, 2));
        // No gvproxy child was spawned; detach decrements the count and
        // withdraws the lease with the attach — the drawn address stays
        // spent regardless, the draw cursor never regresses.
        switch.detach(result.lease.ip).await.expect("detach");
    }
}
