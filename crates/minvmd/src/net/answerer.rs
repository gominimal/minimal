//! The VM host daemon's zone answerer: the box zone (`*.min.internal`),
//! answered on the host loopback from the host-authored table (NET-138) —
//! the answering half a VM-backed host has on the *host*, which is the
//! whole point of the split: the table this daemon fills outside the VM
//! ([`crate::box_registry`]) is the one the zone must answer from, and the
//! in-VM daemon no longer answers at all (`minimald` starts no answerer in
//! a microVM; the host answerer owns the zone on this host).
//!
//! The answer *semantics* are not this module's to invent: they are the
//! shared decision ([`sessions::core::zone_answer`]) — the same one the
//! native daemon's answerer calls — and what this module owns beside it is
//! the DNS wire (decoding a query, encoding the reply the decision's
//! verdict names, the SOA its negatives cite), the host loopback listener,
//! and one machine-shaped rule below.
//!
//! That rule is **who holds the answerer**. The answerer port is the
//! machine's, so exactly one process on the host may serve it — and the one
//! that should is the **installed host service** the privileged step
//! installs (NET-122's sub-requirement): `minzoned`, which the service
//! manager runs as the operator, its listener and its machine-global
//! channel socket the manager's own, so the zone survives every session on
//! the host. This daemon is one of that service's *nodes*. Whether the
//! service is installed is its install marker's to say (the unit file),
//! never the channel socket's existence: installed, the node connects to
//! the machine-global channel and publishes its table's rows there — a
//! connect is what starts a socket-activated service, so a channel that
//! refuses or times out is an error surfaced at session start, never a
//! reason to hold the port. Not installed, the node tries the interim's
//! per-user channel, and only when that is absent does it host the
//! answerer itself, as the recorded interim (NET-138): it binds the port
//! and the interim channel both, serves the zone from its own table merged
//! with the rows of the operator's other nodes (named VMs and VMs under
//! other state dirs alike), and they publish into it.
//! Never both: a port held with no channel behind it is a surfaced
//! collision, not a fallback. The privileged step hands the port over from
//! a hosting daemon by asking it to release (over the control socket):
//! the daemon frees the port, waits a bounded window for the service's
//! channel, and re-binds the interim if the channel never comes.
//!
//! The channel — the service's and the interim holder's, one wire for
//! both, so a node's publish path is the same either way — carries a
//! hello naming the node and the channel's protocol version
//! ([`CHANNEL_PROTOCOL_VERSION`], the number the CLI's probe compares
//! between an installed copy and the daemon, so an upgrade re-surfaces the
//! privileged step), then one publish per line: a whole table's zone
//! rows, with the connection's reply naming the rows it refused. A name
//! belongs to the connection that first published it — a second node's
//! publish of a held name is refused and reported — and a published A
//! address outside the host-answerable range (NET-127) is refused with
//! its reason. A publish is held while its connection lives and retired
//! the moment it ends, so a restarted service holds nothing until its
//! nodes connect again — and a node keeps its connection for the session,
//! re-publishes idempotently on every table change, and reconnects with
//! backoff the moment the service's end closes, so a service restart is a
//! short absence window and never a session restart. The connection's
//! peer uid is the service's own or the connection is refused: the
//! channel is the operator's, not the machine's.
//!
//! Answer semantics, decided by the shared core and gated on the lookup
//! originating on this machine (NET-006 — the zone leaves the machine with
//! *nothing*, not even a refusal):
//!
//! | Lookup | Reply |
//! |---|---|
//! | A, held with a host-answerable address | that address (NET-127) |
//! | A, held without one (a box's switch lease) | NODATA (NET-124) |
//! | any other type, held name | NODATA (NET-124) |
//! | held, stopped namespace | NODATA, never NXDOMAIN (NET-128) |
//! | anything, name nothing holds | NXDOMAIN (NET-125) |
//! | a name outside the box zone | REFUSED |
//! | anything but a standard query | NOTIMP |
//!
//! Every negative carries the zone's SOA with a 15 s `minimum` (NET-124),
//! and every record the answerer emits holds a TTL of at most 15 s
//! (NET-126) — the constants are the shared decision's.
//!
//! The observability contract, as the phase's diagnostics state it: one
//! debug line per answered lookup naming the name, the type, and the answer
//! class; one info line at daemon start naming publish-or-host, the hook
//! port and the channel path; at the answerer service, one info line per
//! node connection and disconnection, and one warn line per refused channel
//! peer naming its uid.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, UdpSocket};
use std::os::unix::io::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use minimald_rpc::ZoneAnswererStatus;
use serde::{Deserialize, Serialize};

use sessions::core::zone_answer::{self, ZoneRow, ZoneView};

use crate::box_registry::{BoxRegistry, is_host_answerable};

/// The `component` field every answerer log line carries — the same one the
/// native daemon's answerer logs under, because it is the same zone service
/// either daemon hosts, and a bundle's daemon log names whichever host holds
/// it.
const COMPONENT: &str = "zone-answerer";

/// The machine's answerer port: the next one after the egress (`:7654`) and
/// mTLS (`:7655`) proxies, mirroring the native daemon's own default
/// (`ANSWERER_PORT` in minimald's `net/answerer.rs`) — `minvmd` does not
/// depend on the daemon, so the value is pinned here beside the one it
/// mirrors, and the e2e lane names it in the resolver command it builds.
///
/// This is a rendezvous, not the node's handed pair: a daemon that finds it
/// held registers with the holder at it, so it is never probed away to an
/// OS-assigned port no resolver would be told about (the guest's handed
/// answerer port — which the guest now binds nothing on — still is).
pub const DEFAULT_ANSWERER_PORT: u16 = 7656;

/// The interim answerer channel socket's file name inside a state dir's
/// provider-instance dir. Deliberately beside [`crate::control`]'s
/// `control.sock` rather than in the `paths` crate: this name only means
/// something where two VM host daemons share a machine.
pub const CHANNEL_SOCK_FILE: &str = "answerer.sock";

/// Largest datagram the answerer reads: a DNS query fits far below this
/// (queries are tens of bytes), and a larger datagram is dropped rather than
/// buffered unbounded.
const MAX_DATAGRAM: usize = 4096;

/// The channel's protocol version: bumped whenever the channel's wire
/// changes, because a daemon and an installed answerer copy can be from
/// different releases of this codebase — the service checks the number a
/// node's hello carries against its own before it holds any of that node's
/// rows, and the CLI's step probe runs `<installed copy>
/// --protocol-version` and compares the printed number with the daemon's
/// own (this constant, the same install), re-surfacing the privileged step
/// on a mismatch so an upgrade re-runs it and the installed copy is never
/// left speaking a wire the daemon no longer understands.
pub const CHANNEL_PROTOCOL_VERSION: u32 = 3;

/// How long the serving side waits for a connecting node's hello before
/// dropping the connection: a connection that never speaks is a stray
/// connect, not a node, and must not pin the per-connection slot.
const HELLO_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a node waits for the serving side's reply to its hello or a
/// publish: a socket-activated service starts at the connect, so the bound
/// only has to cover the manager's start latency, and a reply that misses
/// it means the answerer is not serving — surfaced, retried with backoff,
/// never hosted around.
const CHANNEL_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The first backoff a node waits between attempts on a channel that is
/// present but not answering, doubling each attempt up to [`PORT_RECHECK`]:
/// a restarting service is back inside a second or two, and a broken one is
/// retried at the re-check cadence rather than hammered.
const CHANNEL_RETRY: Duration = Duration::from_millis(250);

/// How often a served connection or listener is polled for a stop of the
/// serving loops: the stop handle is the restart proof's, always unset in
/// production, and the poll slice bounds how long after the flag a loop
/// keeps serving (see [`read_line_resumable`] for why the slice is a read
/// timeout and not a non-blocking flip).
const CONNECTION_POLL: Duration = Duration::from_millis(250);

/// How long a released interim waits for the installed service's channel
/// before it re-binds on its own: longer than the privileged step's whole
/// handover (2 s for the port, 5 s for the unit), so a daemon never re-binds
/// while the unit is still starting, and short enough that the hook port is
/// never left unanswered past it.
const RELEASE_WINDOW: Duration = Duration::from_secs(15);

/// How often a released interim retries the service's channel inside the
/// release window, and polls for a cancel.
const RELEASE_POLL: Duration = Duration::from_millis(250);

/// How long the control socket waits for the acquisition to answer a
/// release or a cancel: the release itself is a stop and a join, well
/// inside this.
const RELEASE_REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest line either side of the channel will read: a publish
/// carries one row per published namespace; anything past this bound is not
/// one.
const MAX_REQUEST_LINE: usize = 64 * 1024;

/// How long a node waits before re-deciding the answerer when nothing woke
/// it — a table change ping, or the held connection's end: long enough
/// that a live answerer sees no chatter, short enough that a channel that
/// came up while the node idled is found within half a minute.
const PORT_RECHECK: Duration = Duration::from_secs(30);

/// The machine-global channel socket the installed answerer service's unit
/// holds (NET-122's host service): one per host, whatever any node's state
/// dir — on Linux under the socket unit's own `RuntimeDirectory`, on macOS
/// under the root-owned `Application Support` dir the privileged step
/// makes (it survives a reboot, which `/var/run` does not).
#[cfg(target_os = "macos")]
pub const GLOBAL_CHANNEL_SOCK: &str = "/Library/Application Support/minimal/run/answerer.sock";
/// See the macOS arm.
#[cfg(not(target_os = "macos"))]
pub const GLOBAL_CHANNEL_SOCK: &str = "/run/minimal/answerer.sock";

/// The installed service's marker: the unit file whose presence — and only
/// whose presence — says the answerer service is installed on this host
/// (the LaunchDaemon plist on macOS, the systemd socket unit on Linux).
/// The channel socket's path existing never says so: a stale socket file
/// with no marker beside it is a leftover, not a service.
#[cfg(target_os = "macos")]
pub const INSTALL_MARKER: &str = "/Library/LaunchDaemons/dev.gominimal.zone.plist";
/// See the macOS arm.
#[cfg(not(target_os = "macos"))]
pub const INSTALL_MARKER: &str = "/etc/systemd/system/minzoned.socket";

/// The variable that overrides [`GLOBAL_CHANNEL_SOCK`] — read only by test
/// and debug builds (the e2e harness's), never by a release build, so no
/// production configuration can point a node at another channel.
pub const CHANNEL_SOCK_ENV: &str = "MINIMAL_ANSWERER_CHANNEL_SOCK";

/// The variable that overrides [`INSTALL_MARKER`], under the same rule as
/// [`CHANNEL_SOCK_ENV`].
pub const INSTALL_MARKER_ENV: &str = "MINIMAL_ANSWERER_INSTALL_MARKER";

/// A path override from `var`, honoured only in test and debug builds.
fn debug_path_override(var: &str) -> Option<PathBuf> {
    #[cfg(any(test, debug_assertions))]
    {
        std::env::var_os(var)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(any(test, debug_assertions)))]
    {
        let _ = var;
        None
    }
}

/// The machine-global answerer channel's path from an override, when one
/// is given — the pure half of [`resolve_channel_sock`]: no state dir, no
/// VM name, nothing per node enters it.
fn channel_sock_from(override_path: Option<PathBuf>) -> PathBuf {
    override_path.unwrap_or_else(|| PathBuf::from(GLOBAL_CHANNEL_SOCK))
}

/// Resolve the answerer channel socket's path: the one machine-global
/// channel the installed service holds ([`GLOBAL_CHANNEL_SOCK`]), the same
/// for every node on the host whatever its state dir. The one definition
/// every reader shares — the node daemons that connect to it, and the CLI
/// that renders the unit holding it.
#[must_use]
pub fn resolve_channel_sock() -> PathBuf {
    channel_sock_from(debug_path_override(CHANNEL_SOCK_ENV))
}

/// Resolve the installed service's marker ([`INSTALL_MARKER`]).
#[must_use]
pub fn resolve_install_marker() -> PathBuf {
    debug_path_override(INSTALL_MARKER_ENV).unwrap_or_else(|| PathBuf::from(INSTALL_MARKER))
}

/// The interim holder's channel's file name, in the operator's per-user
/// run dir ([`interim_channel_sock`]).
pub const INTERIM_CHANNEL_SOCK_FILE: &str = "answerer-interim.sock";

/// The interim holder's channel for the operator: one per user, whatever
/// the node's state dir, so every state dir the operator runs resolves the
/// same path — the node that hosts the interim binds it, and every other
/// node of the operator (a named VM, or a VM under another `--minimal-dir`)
/// publishes into it instead of binding (NET-081: a second helper writes
/// into it over the same channel). The pure half: `runtime_dir` is
/// `$XDG_RUNTIME_DIR` on Linux, `home` the operator's home on macOS, and
/// `uid` the operator's.
fn interim_channel_sock_from(
    runtime_dir: Option<PathBuf>,
    home: Option<PathBuf>,
    uid: u32,
) -> PathBuf {
    if cfg!(target_os = "macos") {
        let _ = (runtime_dir, uid);
        home.unwrap_or_else(|| PathBuf::from("/var/empty"))
            .join("Library/Application Support/minimal/run")
            .join(INTERIM_CHANNEL_SOCK_FILE)
    } else {
        let _ = home;
        match runtime_dir.filter(|dir| dir.is_absolute()) {
            Some(dir) => dir.join("minimal").join(INTERIM_CHANNEL_SOCK_FILE),
            None => PathBuf::from(format!("/tmp/minimal-{uid}")).join(INTERIM_CHANNEL_SOCK_FILE),
        }
    }
}

/// This operator's interim channel ([`interim_channel_sock_from`] over the
/// process's own environment and uid).
#[must_use]
pub fn interim_channel_sock() -> PathBuf {
    // SAFETY: geteuid only reads the process's own uid.
    let uid = unsafe { libc::geteuid() };
    interim_channel_sock_from(
        std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from),
        std::env::var_os("HOME").map(PathBuf::from),
        uid,
    )
}

/// Makes the interim channel's directory ready to bind in: created 0700
/// when absent; refused when it exists owned by another uid or open to
/// group or other — the `/tmp/minimal-<uid>` fallback lives in a shared,
/// sticky dir another user could have pre-created.
fn prepare_interim_dir(sock: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    let Some(dir) = sock.parent() else {
        return Ok(());
    };
    match std::fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir),
        Err(error) => Err(error),
        Ok(meta) => {
            // SAFETY: geteuid only reads the process's own uid.
            let uid = unsafe { libc::geteuid() };
            if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "the interim answerer channel's dir {} is not a directory owned by \
                         uid {uid} with mode 0700 (owner {}, mode {:o}); refusing to bind in it",
                        dir.display(),
                        meta.uid(),
                        meta.mode() & 0o7777
                    ),
                ));
            }
            Ok(())
        }
    }
}

/// A node's id for a state base and VM name: the canonical state dir — so
/// the id is the same across restarts and across symlinked spellings of one
/// dir — and the VM's name. Name ownership on the channel is per node, so
/// two nodes under different state dirs never share one even when both run
/// the default VM.
fn node_id_for(base: &Path, vm: &str) -> String {
    let canonical = std::fs::canonicalize(base).unwrap_or_else(|_| base.to_path_buf());
    format!("{}#{vm}", canonical.display())
}

/// This daemon's node id ([`node_id_for`] over its own state base and VM).
#[must_use]
pub fn node_id() -> String {
    node_id_for(
        crate::state::state_base_dir().as_utf8_path().as_std_path(),
        crate::state::vm_name(),
    )
}

/// The paths one acquisition decides over: the machine-global channel, the
/// interim's per-user channel, the install marker that says whether
/// the service is installed, and the release window a handover waits.
#[derive(Debug, Clone)]
struct ChannelPaths {
    /// The installed service's machine-global channel.
    global: PathBuf,
    /// The interim holder's per-user channel.
    interim: PathBuf,
    /// The installed service's marker file.
    marker: PathBuf,
    /// How long a released interim waits for the service's channel before
    /// it re-binds ([`RELEASE_WINDOW`] in production).
    release_window: Duration,
}

// ── the channel's wire ───────────────────────────────────────────────────────

/// One row of a registration: the zone name (`<name>.min.internal`), the
/// host-answerable address a lookup may be told, and the row's liveness —
/// the [`ZoneRow`] the sender's view holds, on the wire. The sender's
/// registry built the row (NET-138: a registered row is host-authored by
/// the daemon that owns the table it came from); the holder re-applies the
/// address gate as it folds the row in, so no registration can put an
/// address in the zone the host may not be told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RegisteredRow {
    /// The full zone name, as the sender's view held it.
    name: String,
    /// The address an A lookup gets, if there is one to tell.
    address: Option<Ipv4Addr>,
    /// Whether the namespace the name names is running.
    live: bool,
}

/// The first line a node sends on the channel: who is connecting, and which
/// protocol its copy speaks. The node id is the node's canonical state dir
/// and its VM's name ([`node_id`]), the handle name ownership is kept by
/// and a service log names a connected machine by; the version is [`CHANNEL_PROTOCOL_VERSION`] as the
/// connecting copy holds it, and a mismatch is the one reason a healthy
/// channel refuses a node outright.
#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    /// The connecting node's id: its canonical state dir and VM name.
    node: String,
    /// The channel protocol version the connecting copy speaks.
    version: u32,
}

/// One publish over the channel: a whole table's zone rows, one line. The
/// *message*, not the publish itself — that is the node's held connection
/// ([`Registration`]), which outlives the line it arrived by for exactly as
/// long as its rows are held.
#[derive(Debug, Serialize, Deserialize)]
struct PublishRequest {
    /// The sender's zone rows, in the sender's name order.
    rows: Vec<RegisteredRow>,
}

/// A node's request for a box's published address (design §7.1): the
/// answerer — the installed service, or the interim while it hosts — picks
/// the lowest free address of the box range and records it against the
/// node and the box, so co-resident nodes never self-assign and never
/// meet. Asking again for the same box hands back the same address.
#[derive(Debug, Serialize, Deserialize)]
struct AllocateRequest {
    /// The box's name, as the node's registry holds it.
    allocate: String,
}

/// A node's release of a box's published address: the box is gone, so the
/// address returns to the range.
#[derive(Debug, Serialize, Deserialize)]
struct ReleaseAddressRequest {
    /// The box's name, as the node's registry holds it.
    release: String,
}

/// Any line a node sends after its hello.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum NodeLine {
    /// A whole table's zone rows.
    Publish(PublishRequest),
    /// A box address request.
    Allocate(AllocateRequest),
    /// A box address release.
    Release(ReleaseAddressRequest),
}

/// One row the serving side refused to hold, with the reason it named: the
/// reply a publish carries names every row it did not take, so the node
/// that sent it can warn about the name it lost — and about the address the
/// host may not be told — at the moment it happens, not at the first lookup
/// that finds the row absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RefusedRow {
    /// The refused row's zone name.
    name: String,
    /// Why the serving side refused it.
    reason: String,
}

/// The serving side's one-line reply to a hello or a publish: the ack a node
/// waits for, so it knows its rows are answering before it stops trying —
/// or the reason it is not — and, on a hello, which kind of answerer is
/// holding the port (the installed service, or the interim holder
/// daemon), the fact the node's own start line names.
#[derive(Debug, Serialize, Deserialize)]
struct RegistrationReply {
    /// Whether the line was held.
    ok: bool,
    /// The reason a line was refused, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The rows a publish carried that were not held, with their reasons.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refused: Vec<RefusedRow>,
    /// Who answered a hello: `service` (the installed host service) or
    /// `daemon` (the interim holder). Absent on a publish's reply, and on
    /// old wires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    holder: Option<String>,
    /// The address an allocation handed out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<Ipv4Addr>,
}

impl RegistrationReply {
    /// The ack a hello gets, naming the kind of answerer that gave it.
    fn hello(holder: impl Into<String>) -> Self {
        Self {
            ok: true,
            error: None,
            refused: Vec::new(),
            holder: Some(holder.into()),
            address: None,
        }
    }

    /// The ack a publish gets, carrying the rows it refused.
    fn published(refused: Vec<RefusedRow>) -> Self {
        Self {
            ok: true,
            error: None,
            refused,
            holder: None,
            address: None,
        }
    }

    /// The ack an allocation gets, carrying the address it handed out.
    fn allocated(address: Ipv4Addr) -> Self {
        Self {
            ok: true,
            error: None,
            refused: Vec::new(),
            holder: None,
            address: Some(address),
        }
    }

    /// A refusal carrying `reason`.
    fn refused(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(reason.into()),
            refused: Vec::new(),
            holder: None,
            address: None,
        }
    }
}

/// Who holds the answerer's port, as the interim holder daemon names itself
/// in a hello's reply — the other kind is the installed service's own
/// ([`SERVICE_HOLDER`]); the node's start info line repeats the fact so a
/// bundle says whether it published into the service or the interim.
const DAEMON_HOLDER: &str = "daemon";

/// Who holds the answerer's port, as the installed service names itself in
/// a hello's reply (see [`DAEMON_HOLDER`]).
pub(crate) const SERVICE_HOLDER: &str = "service";

// ── the holder's registered tables ───────────────────────────────────────────

/// One node's held publish: the id its hello named, and the rows its
/// connection holds. The id rides in the map so a later publish's refusal
/// can name the node that keeps the name, and the connect and disconnect
/// lines can name the machine they are about.
#[derive(Debug)]
struct NodeRows {
    /// The node id the connection's hello carried.
    node: String,
    /// The rows the connection's last publish held.
    rows: Vec<RegisteredRow>,
}

/// Who holds a published box address: the node, and the box's zone name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AddressHolder {
    /// The node id the holder's hello carried.
    node: String,
    /// The box's canonical zone name.
    name: String,
}

/// The machine's box-address book (design §7.1): every published box
/// address the answerer handed out or a publish claimed, against the node
/// and box that hold it. Allocation is host-global and arbitrated here, so
/// no two nodes' boxes share an address. An address is released when its
/// box goes (the node's release line) and when its node goes (the node's
/// last connection ends); a restarted answerer starts empty and the nodes'
/// re-publishes claim their addresses back, so an address is session-stable
/// and no guest lease ever keys it.
///
/// A released address is quarantined for [`REUSE_QUARANTINE`], the positive
/// answer TTL the zone serves: until it passes, a host resolver may still
/// hold the old name's answer, and a client connecting by it must not reach
/// a different box. Only the box that held it may take it back early.
#[derive(Debug, Default)]
struct AddressBook {
    held: BTreeMap<Ipv4Addr, AddressHolder>,
    /// Released addresses still inside their quarantine: who held each and
    /// when it was released.
    released: BTreeMap<Ipv4Addr, (AddressHolder, Instant)>,
}

/// How long a released box address stays out of allocation: the positive
/// TTL every zone answer carries ([`zone_answer::ANSWER_TTL_SECS`]), the
/// longest a host resolver may keep answering the old name with it.
const REUSE_QUARANTINE: Duration = Duration::from_secs(zone_answer::ANSWER_TTL_SECS as u64);

/// Whether `address` is one the answerer hands a box.
fn in_box_range(address: Ipv4Addr) -> bool {
    let (first, last) = switch::box_loopback_interior();
    first <= address && address <= last
}

impl AddressBook {
    /// [`Self::allocate_at`], now.
    fn allocate(&mut self, node: &str, name: &str) -> Result<Ipv4Addr, String> {
        self.allocate_at(node, name, Instant::now())
    }

    /// The address `name` of `node` holds, or the lowest free one whose
    /// quarantine has passed by `now`, recorded against them. Idempotent
    /// per box; a box re-registered inside its old address's quarantine
    /// gets that address back. When every free address is still
    /// quarantined, the allocation fails naming when the first one frees —
    /// it never hands an address out early.
    fn allocate_at(&mut self, node: &str, name: &str, now: Instant) -> Result<Ipv4Addr, String> {
        if let Some((address, _)) = self
            .held
            .iter()
            .find(|(_, holder)| holder.node == node && holder.name == name)
        {
            return Ok(*address);
        }
        self.released
            .retain(|_, (_, at)| now.saturating_duration_since(*at) < REUSE_QUARANTINE);
        let holder = AddressHolder {
            node: node.to_string(),
            name: name.to_string(),
        };
        let own = self
            .released
            .iter()
            .find(|(_, (was, _))| *was == holder)
            .map(|(address, _)| *address);
        let (first, last) = switch::box_loopback_interior();
        let free = own.or_else(|| {
            (u32::from(first)..=u32::from(last))
                .map(Ipv4Addr::from)
                .find(|address| {
                    !self.held.contains_key(address) && !self.released.contains_key(address)
                })
        });
        let Some(free) = free else {
            let next = self
                .released
                .values()
                .map(|(_, at)| REUSE_QUARANTINE.saturating_sub(now.saturating_duration_since(*at)))
                .min();
            return Err(match next {
                Some(wait) => format!(
                    "every box address in {first}-{last} is held or was released less than \
                     {} s ago (the answer TTL a host resolver may still serve it under); the \
                     next one frees in {} s",
                    REUSE_QUARANTINE.as_secs(),
                    wait.as_secs().max(1)
                ),
                None => {
                    format!("every box address in {first}-{last} is held; none remains to hand out")
                }
            });
        };
        self.released.remove(&free);
        self.held.insert(free, holder);
        Ok(free)
    }

    /// [`Self::claim_at`], now.
    fn claim(&mut self, node: &str, name: &str, address: Ipv4Addr) -> Result<(), String> {
        self.claim_at(node, name, address, Instant::now())
    }

    /// Records `address` against `name` of `node`, as a publish claims it;
    /// refused when another node holds it, or when another box released it
    /// less than the quarantine ago.
    fn claim_at(
        &mut self,
        node: &str,
        name: &str,
        address: Ipv4Addr,
        now: Instant,
    ) -> Result<(), String> {
        if let Some(holder) = self.held.get(&address)
            && holder.node != node
        {
            return Err(format!(
                "another node ({}) holds the address {address}; the answerer hands each \
                 box its own",
                holder.node
            ));
        }
        let holder = AddressHolder {
            node: node.to_string(),
            name: name.to_string(),
        };
        if let Some((was, at)) = self.released.get(&address)
            && now.saturating_duration_since(*at) < REUSE_QUARANTINE
            && *was != holder
        {
            return Err(format!(
                "the address {address} was released less than {} s ago (the answer TTL a \
                 host resolver may still serve it under); it is not reused before then",
                REUSE_QUARANTINE.as_secs()
            ));
        }
        self.released.remove(&address);
        self.held.insert(address, holder);
        Ok(())
    }

    /// [`Self::release_at`], now.
    fn release(&mut self, node: &str, name: &str) -> Option<Ipv4Addr> {
        self.release_at(node, name, Instant::now())
    }

    /// Releases the address `name` of `node` holds, if any, into its
    /// quarantine.
    fn release_at(&mut self, node: &str, name: &str, now: Instant) -> Option<Ipv4Addr> {
        let address = self
            .held
            .iter()
            .find(|(_, holder)| holder.node == node && holder.name == name)
            .map(|(address, _)| *address)?;
        if let Some(holder) = self.held.remove(&address) {
            self.released.insert(address, (holder, now));
        }
        Some(address)
    }

    /// Releases every address `node` holds into its quarantine.
    fn release_node(&mut self, node: &str) {
        let now = Instant::now();
        let gone: Vec<Ipv4Addr> = self
            .held
            .iter()
            .filter(|(_, holder)| holder.node == node)
            .map(|(address, _)| *address)
            .collect();
        for address in gone {
            if let Some(holder) = self.held.remove(&address) {
                self.released.insert(address, (holder, now));
            }
        }
    }
}

/// The canonical zone name of a box a node names by its registry name: the
/// key the address book holds a box's address under, built from
/// [`canonical_box_name`], so every name that folds to the same box shares
/// one address.
fn box_zone_name(name: &str) -> String {
    canonical(&format!(
        "{}.{}",
        canonical_box_name(name),
        zone_answer::ZONE_APEX
    ))
}

/// The one form a box's registry name is compared in wherever it keys the
/// box's published address: the answerer's allocations and releases
/// ([`box_zone_name`]), the box registry's in-flight registrations
/// ([`crate::box_registry::BoxRegistry::begin_registration`]), and its
/// live rows — the row table's name lookups
/// ([`crate::box_registry::BoxRegistry::row_by_name`]), a client
/// registration's name-collision refusal
/// ([`crate::box_registry::AllocationError::NameAlreadyHeld`]), and a
/// client withdrawal's name proof. Names are DNS labels, so the fold is
/// ASCII lower-case: "Web" and "web" are one box to the answerer, and must
/// be one to everything its hold is checked against.
pub(crate) fn canonical_box_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// The rows other VM host daemons published over the channel, keyed by the
/// connection that filed them: a publish is held while its connection
/// lives, replaced by the connection's next line, and retired with the
/// connection's end. Shared between the channel's serving threads (which
/// install and retire) and the answerer (which answers), so a lookup and
/// the channel never see different tables.
#[derive(Debug, Default)]
struct RegisteredTables {
    rows: Mutex<BTreeMap<u64, NodeRows>>,
    /// The box addresses handed out and claimed. Locked after `rows` when
    /// both are held, never before.
    book: Mutex<AddressBook>,
}

/// What one publish left in the tables: the rows the connection now holds,
/// and the rows the answerer refused it with the reasons why — the ack the
/// node waits for is built from the second half, and the first is the
/// answerer's own log of what it now answers.
struct PublishOutcome {
    held: Vec<RegisteredRow>,
    refused: Vec<RefusedRow>,
}

impl RegisteredTables {
    /// No registered tables: a holder whose machine runs one daemon.
    fn new() -> Self {
        Self::default()
    }

    /// Holds `rows` as the publish `connection` of the node `node` filed,
    /// replacing whatever it held before — a re-publish is the whole table
    /// again, so a row that went is gone in the same line — refusing the
    /// rows this publish may not take and naming why, all under the one
    /// lock so two publishes racing over a name are decided by the one
    /// that entered first, which is the first writer the clash rule keeps.
    ///
    /// The refusals are the channel's publish-time half of the rules the
    /// fold re-applies as it answers, applied once as the rows arrive
    /// rather than once per lookup: a name another node holds is the first
    /// publisher's, a name in `reserved` — the answerer's own held names,
    /// and the interim holder's own table's — is not a publish's to take,
    /// and an A address outside the host-answerable range (NET-127) never
    /// reaches the zone at all. Every refusal is *per row*: the publish's
    /// other rows still hold.
    fn install_validated(
        &self,
        connection: u64,
        node: &str,
        rows: Vec<RegisteredRow>,
        reserved: &[String],
    ) -> PublishOutcome {
        let mut held = self.rows.lock().expect(
            "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
        );
        let mut accepted = Vec::with_capacity(rows.len());
        let mut refused = Vec::new();
        // The box addresses this publish's earlier rows claimed: the book
        // refuses another node's address, and this keeps one node's two
        // boxes from sharing one either — the second would overwrite the
        // first's holder record, so its release would free an address the
        // first box still answers at.
        let mut claimed: Vec<(Ipv4Addr, String)> = Vec::new();
        for row in rows {
            let name = canonical(&row.name);
            if reserved.contains(&name) {
                refused.push(RefusedRow {
                    name: row.name,
                    reason: "the answerer holds this name itself".to_string(),
                });
                continue;
            }
            // The node that first holds the name, if any: an earlier
            // connection's row, or this one's own — a re-publish of a name
            // the same node already holds is a replace, not a clash, so a
            // reconnecting node never loses its own names to its own
            // retired connection.
            let holder = held.values().find_map(|held| {
                held.rows
                    .iter()
                    .any(|held_row| canonical(&held_row.name) == name)
                    .then_some(held.node.as_str())
            });
            if let Some(holder) = holder
                && holder != node
            {
                refused.push(RefusedRow {
                    name: row.name,
                    reason: format!(
                        "another node ({holder}) holds this name; the first publisher \
                         keeps it"
                    ),
                });
                continue;
            }
            if let Some(address) = row.address
                && !is_host_answerable(address)
            {
                refused.push(RefusedRow {
                    name: row.name,
                    reason: format!(
                        "the address {address} is outside the host-answerable range \
                         (the reserved local range or the host loopback)"
                    ),
                });
                continue;
            }
            // A box's published address is the answerer's to hand out
            // (design §7.1): one inside the box range that no other node
            // holds is this node's, recorded so no allocation hands it on;
            // any other address of the reserved range is never a box's.
            if let Some(address) = row.address
                && address != Ipv4Addr::LOCALHOST
            {
                if !in_box_range(address) {
                    let (first, last) = switch::box_loopback_interior();
                    refused.push(RefusedRow {
                        name: row.name,
                        reason: format!(
                            "the address {address} is outside the box address range \
                             {first}-{last} the answerer hands out"
                        ),
                    });
                    continue;
                }
                if let Some((_, first)) = claimed
                    .iter()
                    .find(|(held, held_name)| *held == address && *held_name != name)
                {
                    refused.push(RefusedRow {
                        reason: format!(
                            "this publish's box {first} already carries the address \
                             {address}; the answerer hands each box its own"
                        ),
                        name: row.name,
                    });
                    continue;
                }
                if let Err(reason) = self.book().claim(node, &name, address) {
                    refused.push(RefusedRow {
                        name: row.name,
                        reason,
                    });
                    continue;
                }
                claimed.push((address, name));
            }
            accepted.push(row);
        }
        let outcome = PublishOutcome {
            held: accepted,
            refused,
        };
        held.insert(
            connection,
            NodeRows {
                node: node.to_string(),
                rows: outcome.held.clone(),
            },
        );
        outcome
    }

    /// Retires the publish `connection` filed: the connection is over, so
    /// its names answer nothing here anymore. The retired rows come back,
    /// so the retirement's own log line can name them.
    ///
    /// The node's box addresses go with its last connection: a node that
    /// left holds nothing, and its re-publish on reconnect claims them back.
    fn remove(&self, connection: u64) -> Option<NodeRows> {
        let mut rows = self.rows.lock().expect(
            "the registered tables' lock is never held across a panic, so it cannot \
             be poisoned",
        );
        let removed = rows.remove(&connection);
        if let Some(gone) = &removed
            && !rows.values().any(|held| held.node == gone.node)
        {
            self.book().release_node(&gone.node);
        }
        removed
    }

    /// The address book, locked.
    fn book(&self) -> std::sync::MutexGuard<'_, AddressBook> {
        self.book
            .lock()
            .expect("the address book's lock is never held across a panic")
    }

    /// Hands `name` of `node` a box address (see [`AddressBook::allocate`]).
    fn allocate(&self, node: &str, name: &str) -> Result<Ipv4Addr, String> {
        self.book().allocate(node, name)
    }

    /// Releases the box address `name` of `node` holds.
    fn release_address(&self, node: &str, name: &str) -> Option<Ipv4Addr> {
        self.book().release(node, name)
    }

    /// Records the addresses of the hosting node's own rows, so the interim
    /// never hands another node an address one of its own boxes holds.
    fn claim_own(&self, node: &str, rows: &[RegisteredRow]) {
        let mut book = self.book();
        for row in rows {
            if let Some(address) = row.address
                && in_box_range(address)
            {
                let _ = book.claim(node, &canonical(&row.name), address);
            }
        }
    }

    /// Every published row with the connection that filed it, flattened
    /// across them in connection order — the earlier connection is the
    /// earlier writer, which is the order the answerer's clash rule keeps
    /// names in. The connection rides along so a refused row can be logged
    /// naming the source that holds the name and the one that lost it.
    fn rows(&self) -> Vec<(u64, RegisteredRow)> {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .iter()
            .flat_map(|(connection, held)| held.rows.iter().map(|row| (*connection, row.clone())))
            .collect()
    }

    /// Whether any publish is held — the installed service's own node row's
    /// liveness: the node's shared name answers while some node is
    /// connected, and nothing holds it when none is.
    fn is_empty(&self) -> bool {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .is_empty()
    }

    /// Holds `rows` for `connection` unvalidated — the shape a publish
    /// leaves in the tables once the serving side has accepted it. The
    /// answerer's answer-time gates (the fold's clash refusal and address
    /// re-gate) are still exercised on rows installed this way, which is
    /// why this is here: the fold must hold even against a publish-time
    /// gate that somehow let a row through.
    #[cfg(test)]
    fn install(&self, connection: u64, rows: Vec<RegisteredRow>) {
        self.rows
            .lock()
            .expect(
                "the registered tables' lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .insert(
                connection,
                NodeRows {
                    node: "a test node".to_string(),
                    rows,
                },
            );
    }
}

// ── the answerer ──────────────────────────────────────────────────────────────

/// The host answerer: this daemon's own host-authored table, merged with the
/// rows other VM host daemons published over the channel, behind the
/// shared answer decision. Built once when the port is held and served for
/// the holder's lifetime ([`serve`]).
struct HostAnswerer {
    /// This daemon's own table (NET-138): the registry `run` fills. The
    /// installed service's holds nothing — its own row is [`HOST_NAME`],
    /// and the node's shared one — and answers only what nodes publish.
    own: BoxRegistry,
    /// The rows other VM host daemons published to this answerer.
    registered: Arc<RegisteredTables>,
    /// The zone's SOA, carried by every negative (NET-124), built once.
    soa: Record,
    /// Whether this answerer holds the node's shared name itself: the
    /// installed service does (no table of its own carries it, and every
    /// node excludes it from its publishes — every VM's node row is the
    /// same name); the interim holder does not, because its own table
    /// holds its own node row.
    holds_node_row: bool,
    /// The refused name clashes a warn has already named: one warn per clash,
    /// not one per lookup, and a clash that clears is warnable again if it
    /// comes back (see [`Self::zone_view`]).
    warned: Mutex<BTreeSet<String>>,
}

impl HostAnswerer {
    /// An answerer over `own`, answering the registered `rows` beside it.
    fn new(own: BoxRegistry, registered: Arc<RegisteredTables>) -> Self {
        Self {
            own,
            registered,
            soa: zone_soa(),
            holds_node_row: false,
            warned: Mutex::new(BTreeSet::new()),
        }
    }

    /// The answerer of the installed host service: an empty table of its
    /// own — a service holds no boxes; the nodes publish their rows to it —
    /// with the host's own name and the node's shared name held by the
    /// answerer itself.
    fn for_service(registered: Arc<RegisteredTables>) -> Self {
        Self {
            own: BoxRegistry::new(switch::DEFAULT_SUBNET),
            registered,
            soa: zone_soa(),
            holds_node_row: true,
            warned: Mutex::new(BTreeSet::new()),
        }
    }

    /// The reply bytes for one datagram, or `None` to send nothing.
    ///
    /// `None` is a decision, not a failure: a source that did not originate
    /// on this machine gets nothing at all (NET-006), and so does a datagram
    /// that is not a standard query — no question section to answer, no id
    /// to echo an error to, and a response reflected back at a sender is a
    /// reflection loop, not an answer. This is the answerer's whole
    /// contract as a pure function of `(source, datagram)`, so the machine
    /// rule and every answer class are testable without a socket.
    fn respond(&self, peer: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
        let request = match Message::from_vec(datagram) {
            Ok(request) => request,
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %peer,
                    %error,
                    "dropping an unparseable box-zone datagram"
                );
                return None;
            }
        };
        if request.metadata.message_type != MessageType::Query {
            return None;
        }
        let query = request.queries.first().cloned()?;
        let qname = query.name().clone();
        let qtype = query.query_type();
        let asked = qname.to_lowercase().to_string();
        let asked = asked.strip_suffix('.').unwrap_or(&asked);

        // The lookup and the view, both resolved from this answerer's own
        // halves, then the shared decision over them: where the datagram
        // came from and what the tables hold for the name are this module's
        // to say; which answer class that lookup gets is the core's.
        let lookup = zone_answer::Lookup {
            name: asked.to_string(),
            record: if qtype == RecordType::A {
                zone_answer::RecordType::A
            } else {
                zone_answer::RecordType::Other
            },
            origin: origin_for(peer),
        };
        let view = self.zone_view();
        match zone_answer::decide(&lookup, &view) {
            // Off-host: no reply, one warn line (the only per-lookup warn
            // there is; every answered lookup gets its own debug line below).
            zone_answer::Verdict::Silent => {
                tracing::warn!(
                    component = COMPONENT,
                    %peer,
                    name = asked,
                    query_type = ?qtype,
                    "refused an off-host box-zone lookup; the zone answers only this machine"
                );
                None
            }
            // Not a standard query: answered, with the code that says so — but
            // only where the decision answers at all: an off-host datagram
            // already got its silence above, whatever it carried.
            _ if request.metadata.op_code != OpCode::Query => {
                let reply = Message::error_msg(
                    request.metadata.id,
                    request.metadata.op_code,
                    ResponseCode::NotImp,
                );
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "notimp",
                    "answered a box-zone lookup"
                );
                reply.to_vec().ok()
            }
            // Out of zone: this answerer is authoritative for the box zone
            // and nothing else, so a name that strayed in (a too-broad
            // resolver routing domain) is REFUSED — visibly, so the
            // misconfiguration names itself — with no authority section.
            zone_answer::Verdict::Refused => {
                let reply = self.reply(&request, query, ResponseCode::Refused, None, false);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "refused",
                    "answered an out-of-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Nodata => {
                let reply = self.reply(&request, query, ResponseCode::NoError, None, true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "nodata",
                    "answered a box-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Nxdomain => {
                let reply = self.reply(&request, query, ResponseCode::NXDomain, None, true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "nxdomain",
                    "answered a box-zone lookup"
                );
                reply
            }
            zone_answer::Verdict::Address(address) => {
                let record =
                    Record::from_rdata(qname, zone_answer::ANSWER_TTL_SECS, RData::A(A(address)));
                let reply = self.reply(&request, query, ResponseCode::NoError, Some(record), true);
                tracing::debug!(
                    component = COMPONENT,
                    name = asked,
                    query_type = ?qtype,
                    answer = "a",
                    "answered a box-zone lookup"
                );
                reply
            }
        }
    }

    /// The zone view this answerer answers from: this daemon's own
    /// host-authored table (NET-138) — filed first, so a name both tables
    /// hold is answered by this host's own row — the host's own name beside
    /// it ([`HOST_NAME`], held by the answerer itself), and the rows other
    /// VM host daemons registered over the channel folded in on top, the
    /// registered address re-gated so no registration can put an address
    /// in the zone the host may not be told (NET-127).
    ///
    /// A name two sources both hold is **not** folded twice: the first
    /// writer keeps it and the later one is refused, so a clashing name's
    /// answer is one fact, decided by the fold's order — this host's own
    /// table, then the registrations in the order their connections filed
    /// — and never by which row arrived last. The shared decision's
    /// [`ZoneView::hold`] replaces, which is the behaviour a builder wants
    /// over rows it knows are its own; here the rows come from daemons
    /// this one does not control, so the fold refuses instead. Each
    /// refusal is logged once per clash, at warn, naming the name and both
    /// its sources — the keeper and the refused writer — because a name
    /// two daemons both published is an operator's problem to see, not a
    /// fact to settle by accident of arrival.
    fn zone_view(&self) -> ZoneView {
        let mut view = self.own.zone_view();
        // The source each folded name came from: the keeper a later writer
        // is refused against, and the source the warn names.
        let mut held: BTreeMap<String, String> = view
            .rows()
            .map(|(name, _)| (name.to_string(), OWN_TABLE.to_string()))
            .collect();
        // The host's own name (NET-003's host half): `host.min.internal` at
        // the host loopback, held by the answerer itself, because it is the
        // host's name, not a namespace any table publishes, and the shared
        // decision holds no special case for it. Held after the own table,
        // so a box named `host` cannot take the host's name — the row the
        // answerer answers is the host's — and before the fold, so a
        // registration for it from any node is refused like every name the
        // answerer holds first.
        held.insert(HOST_NAME.to_string(), HOST_ROW.to_string());
        view.hold(
            HOST_NAME,
            ZoneRow {
                address: Some(Ipv4Addr::LOCALHOST),
                live: true,
            },
        );
        // The node's own shared name, when this answerer is the installed
        // service: no table of its own publishes it — every node excludes
        // it from its publishes, because every VM's node row is the same
        // name — so the service holds it itself, at the shared loopback
        // address the node's namespace serves from, live while any node
        // is connected and held by nothing once none is. The interim
        // holder holds no such row: its own table carries its own.
        if self.holds_node_row {
            let node_name = crate::box_registry::node_zone_name();
            held.insert(node_name.clone(), THE_SERVICE_NODE_ROW.to_string());
            view.hold(
                node_name,
                ZoneRow {
                    address: Some(Ipv4Addr::LOCALHOST),
                    live: !self.registered.is_empty(),
                },
            );
        }
        let mut refused: BTreeSet<String> = BTreeSet::new();
        for (connection, row) in self.registered.rows() {
            let name = canonical(&row.name);
            if let Some(kept_by) = held.get(&name) {
                refused.insert(name.clone());
                // One warn per standing clash, not one per lookup that
                // meets it: the set keeps the clashes already named, and a
                // clash that cleared is forgotten below so a returning one
                // warns again. `insert` returns whether this pass is the
                // first to see the clash, and that pass is the one that
                // warns.
                if self
                    .warned
                    .lock()
                    .expect(
                        "the clash set's lock is never held across a panic, so it cannot \
                         be poisoned",
                    )
                    .insert(name.clone())
                {
                    tracing::warn!(
                        component = COMPONENT,
                        name = %name,
                        kept_by = %kept_by,
                        refused = %registration(connection),
                        "refused a registered zone row for a name another source holds; \
                         the first writer keeps the name, the later one answers nothing \
                         here"
                    );
                }
                continue;
            }
            held.insert(name.clone(), registration(connection));
            view.hold(
                name,
                ZoneRow {
                    address: row.address.filter(|address| is_host_answerable(*address)),
                    live: row.live,
                },
            );
        }
        // A clash that cleared is warnable again if it comes back.
        self.warned
            .lock()
            .expect(
                "the clash set's lock is never held across a panic, so it cannot \
                 be poisoned",
            )
            .retain(|name| refused.contains(name));
        view
    }

    /// The reply bytes for one answered lookup: the envelope every
    /// verdict's reply shares — the query echoed, the rcode named, and the
    /// answer record in the answer section when there is one —
    /// authoritative for the zone and for nothing else (the REFUSED reply
    /// is not, so it never cites our SOA over someone else's namespace).
    /// The negatives the zone certifies are its own — an authoritative
    /// reply with no answer records, NODATA and NXDOMAIN — and every one of
    /// them carries the zone's SOA in the authority section (NET-124): the
    /// record the host resolver needs to cache the negative at all.
    fn reply(
        &self,
        request: &Message,
        query: hickory_proto::op::Query,
        rcode: ResponseCode,
        answer: Option<Record>,
        authoritative: bool,
    ) -> Option<Vec<u8>> {
        let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
        reply.metadata = Metadata::response_from_request(&request.metadata);
        reply.metadata.authoritative = authoritative;
        reply.metadata.response_code = rcode;
        reply.add_query(query);
        if let Some(record) = answer {
            reply.add_answer(record);
        }
        if authoritative && reply.answers.is_empty() {
            reply.add_authority(self.soa.clone());
        }
        reply.to_vec().ok()
    }
}

/// The source a name this host's own table holds is named by in the clash
/// warn — this host-authored table, the fold's first writer.
const OWN_TABLE: &str = "this host's own table";

/// The host's own name under the zone, as the answerer holds it (NET-003's
/// host half): the name a lookup of the host itself gets, at the host
/// loopback. Not a namespace any table publishes, and the shared decision
/// holds no special case for it, so the row is the answerer's to hold — and
/// the one the host-side facts read: the CLI's liveness query (the A query
/// for this name at the reported port that proves the answerer serves) and
/// the session e2e's dig both read it. A registration for it from any node
/// is refused, like every name the answerer holds first.
///
/// Public so the CLI's query asks for the name this answerer holds — one
/// definition, so the question and the answer cannot drift apart. The name
/// itself is the sessions zone's host row, the one spelling every registry
/// reads.
pub const HOST_NAME: &str = zone_answer::HOST_ROW_NAME;

/// The source the answerer's own [`HOST_NAME`] row keeps its name under in
/// the fold: the keeper a refused registration's warn names.
const HOST_ROW: &str = "the host's own row";

/// The source the installed service's node row keeps the node's shared
/// name under in the fold (see [`HostAnswerer::for_service`]).
const THE_SERVICE_NODE_ROW: &str = "the service's own node row";

/// The source a name the registration `connection` filed is named by in
/// the clash warn: which co-resident daemon's connection it rode, the only
/// handle the holder has on a registrant that is not its own process.
fn registration(connection: u64) -> String {
    format!("zone registration {connection}")
}

/// The canonical form of a registered row's name, mirroring the shared
/// decision's own normalization (lower-case, no root dot) — the one form the
/// view holds names in, so the fold's clash rule compares in it and no
/// registrant can slip a case variant of a held name past the rule and take
/// a name another source keeps.
fn canonical(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

/// Where a datagram from `peer` originated (NET-006): the listener binds
/// the host loopback, so only loopback peers reach it at all — the source
/// is still checked per datagram, so a misbound socket can never serve the
/// zone to the network.
fn origin_for(peer: SocketAddr) -> zone_answer::Origin {
    let on_machine = match peer.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    };
    if on_machine {
        zone_answer::Origin::OnMachine
    } else {
        zone_answer::Origin::OffMachine
    }
}

/// The zone's SOA record, built once per answerer: the record every
/// negative answer carries in its authority section (NET-124), so the host
/// resolver can cache it — RFC 2308's negative TTL is this record's TTL
/// capped by its `minimum`. The zone has no secondaries, so every field
/// but `minimum` is inert; all of them carry the shared decision's TTL
/// ceiling so no number the answerer emits exceeds NET-126's bound.
fn zone_soa() -> Record {
    let apex =
        Name::from_utf8(format!("{}.", zone_answer::ZONE_APEX)).expect("the zone apex parses");
    let mname =
        Name::from_utf8(format!("ns.{}.", zone_answer::ZONE_APEX)).expect("the SOA mname parses");
    let rname = Name::from_utf8(format!("hostmaster.{}.", zone_answer::ZONE_APEX))
        .expect("the SOA rname parses");
    // `SOA` is `#[non_exhaustive]`, so the constructor is the only way in.
    let soa = SOA::new(
        mname,
        rname,
        1,
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS as i32,
        zone_answer::ANSWER_TTL_SECS,
    );
    Record::from_rdata(apex, zone_answer::ANSWER_TTL_SECS, RData::SOA(soa))
}

// ── the channel's line codec ──────────────────────────────────────────────────

/// Read one line (terminated by `\n`) from one side of the channel,
/// resuming across read timeouts: the bytes read so far stay in `partial`
/// when the read times out, so a caller that polls its connection between
/// timeout slices (the serving loops' stop check) retries without losing
/// a line the timeout split mid-write. A connection that closes before
/// sending a line reads as no request; a line past [`MAX_REQUEST_LINE`]
/// is refused. Bounded by the caller's read timeout, whatever it is: the
/// serving side bounds the hello only, and everything after it polls.
#[expect(
    clippy::indexing_slicing,
    reason = "cut at `read`, the byte count `read()` reported, or at `newline`, an index `position` found inside `buf[..read]`"
)]
fn read_line_resumable(
    stream: &mut UnixStream,
    partial: &mut Vec<u8>,
) -> io::Result<Option<String>> {
    // A line that finished inside the last poll slice is still waiting in
    // `partial`; answer it before reading more.
    if let Some(newline) = partial.iter().position(|byte| *byte == b'\n') {
        let line: Vec<u8> = partial.drain(..newline).collect();
        // The newline itself goes with it: drain stopped before it, so the
        // first byte left is it.
        partial.remove(0);
        return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
    }
    let mut buf = [0u8; 1024];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return if partial.is_empty() {
                Ok(None)
            } else {
                // A partial line at EOF — a peer that died mid-write.
                // Still answerable with a refusal, so hand what arrived
                // back rather than hanging the slot on a timeout.
                Ok(Some(String::from_utf8_lossy(partial).into_owned()))
            };
        }
        if let Some(newline) = buf[..read].iter().position(|byte| *byte == b'\n') {
            partial.extend_from_slice(&buf[..newline]);
            let line = std::mem::take(partial);
            return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
        }
        partial.extend_from_slice(&buf[..read]);
        if partial.len() > MAX_REQUEST_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("channel line exceeded {MAX_REQUEST_LINE} bytes without a newline"),
            ));
        }
    }
}

/// One bounded read of a reply line: the whole line inside the read
/// timeout the caller set, or the error that says it did not come. A
/// reply is a single write on the other side, so a fresh buffer per read
/// is all a reply ever needs.
/// How long the uid gate waits for a refused peer's hello before it
/// answers: the hello is read only so the reply is not written into a
/// connection the peer is still writing to, never to act on it.
const FOREIGN_PEER_HELLO_WAIT: Duration = Duration::from_secs(1);

/// Answers a peer the uid gate refused with a one-line reason, so the
/// operator behind it reads why rather than a bare closed channel: the
/// service is one operator's (design §7.1 keeps multi-user hosts out of
/// the profile), and another operator's daemons are turned away here. Its
/// hello is drained unread, on a thread of its own, so a foreign peer that
/// never writes cannot stall the gate's accept loop.
fn refuse_foreign_peer(mut stream: UnixStream, peer_uid: u32, service_uid: u32) {
    // The channel is world-connectable (its mode grants the connect; this
    // gate decides), so the refusals in flight are capped: past the cap a
    // foreign peer is closed bare, and no peer can grow this service's
    // threads or fds by connecting.
    if FOREIGN_REFUSALS_IN_FLIGHT.fetch_add(1, Ordering::SeqCst) >= FOREIGN_REFUSALS_MAX {
        FOREIGN_REFUSALS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("minvmd-zone-refuse".to_string())
        .spawn(move || {
            let _in_flight = RefusalSlot;
            let _ = stream.set_read_timeout(Some(FOREIGN_PEER_HELLO_WAIT));
            let _ = read_reply_line(&mut stream);
            let reply = RegistrationReply::refused(format!(
                "the host answerer service serves uid {service_uid}; this operator \
                 (uid {peer_uid}) is refused: multi-operator hosts are not supported"
            ));
            if let Err(error) = write_reply(&mut stream, &reply) {
                tracing::debug!(component = COMPONENT, %error, "foreign peer refusal failed");
            }
        });
    if let Err(error) = spawned {
        // The closure never ran, so its slot is released here.
        FOREIGN_REFUSALS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
        tracing::debug!(component = COMPONENT, %error, "could not answer a foreign peer");
    }
}

/// The most foreign-peer refusals answered at once ([`refuse_foreign_peer`]).
const FOREIGN_REFUSALS_MAX: usize = 4;

/// The foreign-peer refusals answering now.
static FOREIGN_REFUSALS_IN_FLIGHT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// One refusal's hold on [`FOREIGN_REFUSALS_IN_FLIGHT`], released when the
/// refusal's thread ends however it ends.
struct RefusalSlot;

impl Drop for RefusalSlot {
    fn drop(&mut self) {
        FOREIGN_REFUSALS_IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

fn read_reply_line(stream: &mut UnixStream) -> io::Result<Option<String>> {
    let mut partial = Vec::new();
    read_line_resumable(stream, &mut partial)
}

/// Parses one hello line. A line that does not parse is refused, not
/// fatal: the serving side answers with the reason and drops the
/// connection.
fn parse_hello(line: &str) -> Result<Hello, String> {
    serde_json_lenient::from_str(line).map_err(|error| error.to_string())
}

/// Parses one line a node sends after its hello, the same way
/// ([`parse_hello`]).
fn parse_node_line(line: &str) -> Result<NodeLine, String> {
    serde_json_lenient::from_str(line).map_err(|error| error.to_string())
}

/// Writes one line of the channel's wire: `message` serialized, one
/// `\n`. Every message on the channel is a single line, so the read on
/// the other side answers a whole message per call.
fn write_line<T: ?Sized + Serialize>(stream: &mut UnixStream, message: &T) -> io::Result<()> {
    let mut line = serde_json_lenient::to_string(message).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("channel line did not serialize: {error}"),
        )
    })?;
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    stream.flush()
}

/// Writes one reply line ([`write_line`], the reply's spelling).
fn write_reply(stream: &mut UnixStream, reply: &RegistrationReply) -> io::Result<()> {
    write_line(stream, reply)
}

// ── the channel's serving side ───────────────────────────────────────────────

/// The peer's uid, the kernel's own answer for who holds the other end of
/// `stream` — the channel's trust gate: a publish is the operator's, so a
/// connection whose peer is not the uid this answerer serves is refused
/// before a byte of it is read. The credential is decided at connect
/// time, so nothing the peer writes can influence what this reads.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `size_of::<ucred>()` bytes into
    // `cred`, whose length is passed alongside it; the fd is the stream's
    // own and stays valid for the borrow's life.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Off Linux the kernel offers the same credential fact for a connected
/// unix socket through `LOCAL_PEERCRED` (the BSD/macOS spelling of
/// SO_PEERCRED): the kernel fills an `xucred` with the peer's uid, decided
/// at connect time, so nothing the peer writes can influence what this
/// reads — the same gate with the same answer ([`peer_uid`]'s Linux arm).
#[cfg(not(target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::xucred {
        cr_version: 0,
        cr_uid: 0,
        cr_ngroups: 0,
        cr_groups: [0; 16],
    };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `size_of::<xucred>()` bytes into
    // `cred`, whose length is passed alongside it; the fd is the stream's
    // own and stays valid for the borrow's life.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.cr_uid)
}

/// The names no publish may take, the answerer's own: the host's own name
/// and the node's shared one ([`HostAnswerer::for_service`] holds both
/// itself; the interim holder's own table holds its own node row, which
/// reserving it too changes nothing but keeps the set one rule), and — for
/// the interim holder, which has a table of its own — every name that
/// table holds, so no node's publish can take a name this host authored.
/// Computed per publish line, so a table that changed between two
/// publishes is honoured without a second copy of the fold's bookkeeping.
fn reserved_names(own: Option<&Arc<BoxRegistry>>) -> Vec<String> {
    let mut reserved = vec![HOST_NAME.to_string(), crate::box_registry::node_zone_name()];
    if let Some(own) = own {
        reserved.extend(own.zone_view().rows().map(|(name, _)| name.to_string()));
    }
    reserved
}

/// Binds the answerer channel's listener beside the interim holder's socket
/// and serves publishes on a dedicated thread: one connection per
/// co-resident VM host daemon, each connection's rows held while the
/// connection lives. The bind happens on the calling thread so its failure
/// surfaces where the answerer is started ([`acquire_loop_at`] warns and
/// serves on); the socket gets the bridge socket's posture — path-length
/// check, a 0700 parent dir, a stale socket removed, 0600 on the socket —
/// so only the same user may connect, the same trust the control socket
/// rests on, with the uid gate ([`peer_uid`]) as the wire's own check of
/// it.
fn hold_channel(
    sock: &Path,
    registered: Arc<RegisteredTables>,
    own: Option<Arc<BoxRegistry>>,
    expected_uid: u32,
) -> io::Result<Arc<AtomicBool>> {
    crate::sock::check_uds_path_len(sock)?;
    prepare_interim_dir(sock)?;
    crate::sock::remove_stale_socket(sock)?;
    let listener = UnixListener::bind(sock)?;
    crate::sock::enforce_socket_permissions(sock)?;
    // The interim holder's channel serves until a release stops it (the
    // returned flag) or the daemon exits.
    let stop = Arc::new(AtomicBool::new(false));
    let serving = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("minvmd-zone-channel".to_string())
        .spawn(move || {
            serve_channel(
                listener,
                registered,
                expected_uid,
                own,
                DAEMON_HOLDER,
                serving,
            );
        })
        .map(|_| stop)
}

/// Serves the answerer channel on `listener`: one thread per connection,
/// each gated on the peer's uid before a byte of it is read, hello'd with
/// its node id and protocol version, then publishing rows until the
/// connection ends. `expected_uid` is the uid this answerer serves — the
/// operator's, whoever the unit runs the service as; `holder` is how a
/// hello's ack names this answerer, the installed service or the interim
/// holder daemon, the fact the node's start line repeats; `stop` retires
/// the loop — the interim's is never set, and the restart proof's is the
/// one handle that cleanly stops a serving answerer's threads.
fn serve_channel(
    listener: UnixListener,
    registered: Arc<RegisteredTables>,
    expected_uid: u32,
    own: Option<Arc<BoxRegistry>>,
    holder: &'static str,
    stop: Arc<AtomicBool>,
) {
    // The accept loop is a poll, not a blocking accept, so a stop is
    // honoured within one slice however idle the channel is.
    if let Err(error) = listener.set_nonblocking(true) {
        tracing::warn!(
            component = COMPONENT,
            %error,
            "could not put the answerer channel into poll mode; no node's rows can \
             be held here"
        );
        return;
    }
    let mut next: u64 = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // The uid gate, before any byte of the peer is read: a
                // foreign process is refused on what it is, not on what
                // it says, and the refusal is a warn naming its uid —
                // the one a misconfigured unit's service user answers at
                // a glance.
                match peer_uid(&stream) {
                    Ok(uid) if uid == expected_uid => {
                        let connection = next;
                        next += 1;
                        let registered = Arc::clone(&registered);
                        let own = own.clone();
                        let stop = Arc::clone(&stop);
                        let spawned = std::thread::Builder::new()
                            .name("minvmd-zone-publish".to_string())
                            .spawn(move || {
                                serve_registration(
                                    connection, stream, registered, own, holder, stop,
                                )
                            });
                        if let Err(error) = spawned {
                            tracing::warn!(
                                component = COMPONENT,
                                %error,
                                "could not serve a node's publishes; that node's names \
                                 will not answer here"
                            );
                        }
                    }
                    Ok(uid) => {
                        tracing::warn!(
                            component = COMPONENT,
                            peer_uid = uid,
                            service_uid = expected_uid,
                            "refused an answerer channel connection from a foreign uid; \
                             only the uid this answerer serves may publish rows"
                        );
                        refuse_foreign_peer(stream, uid, expected_uid);
                    }
                    Err(error) => {
                        tracing::debug!(
                            component = COMPONENT,
                            %error,
                            "could not read a channel peer's uid"
                        );
                    }
                }
            }
            Err(error) => {
                // A poll slice with no connection in it is the idle loop's
                // own shape, not a failure worth a line at any level.
                if error.kind() != io::ErrorKind::WouldBlock {
                    tracing::debug!(
                        component = COMPONENT,
                        %error,
                        "answerer channel accept failed"
                    );
                }
                std::thread::sleep(CONNECTION_POLL);
            }
        }
    }
}

/// Serves one node's connection: the hello first — bounded, because a
/// connection that never speaks is a stray connect, not a node — then the
/// publishes, each replacing the connection's rows, until the connection
/// ends. The reads between publishes are polls ([`CONNECTION_POLL`], the
/// stop handle's slice), resuming across them, so a harness can retire
/// the loop without stranding a thread per connection; a node's exit —
/// the one event that retires its rows — is the read's own EOF.
fn serve_registration(
    connection: u64,
    mut stream: UnixStream,
    registered: Arc<RegisteredTables>,
    own: Option<Arc<BoxRegistry>>,
    holder: &'static str,
    stop: Arc<AtomicBool>,
) {
    if let Err(error) = stream.set_read_timeout(Some(HELLO_READ_TIMEOUT)) {
        tracing::debug!(
            component = COMPONENT,
            %error,
            "a channel connection could not set its read bound"
        );
        return;
    }
    let hello = match read_reply_line(&mut stream) {
        Ok(Some(line)) => line,
        Ok(None) => return,
        Err(error) => {
            tracing::debug!(
                component = COMPONENT,
                %error,
                "a channel connection went before it said hello"
            );
            return;
        }
    };
    // The hello is the gate the whole connection rests on. The protocol
    // version must match — a node running a different release of the wire
    // than this answerer is refused outright, so the error surfaces at the
    // node and the CLI's step probe re-runs the privileged install.
    let node = match parse_hello(&hello) {
        Ok(hello) if hello.version == CHANNEL_PROTOCOL_VERSION => hello.node,
        Ok(hello) => {
            let reply = RegistrationReply::refused(format!(
                "this answerer speaks channel protocol {CHANNEL_PROTOCOL_VERSION}; the \
                 node said {}",
                hello.version
            ));
            if let Err(error) = write_reply(&mut stream, &reply) {
                tracing::debug!(component = COMPONENT, %error, "channel hello reply failed");
            }
            tracing::warn!(
                component = COMPONENT,
                node = %hello.node,
                said = hello.version,
                speaks = CHANNEL_PROTOCOL_VERSION,
                "refused a node speaking a different answerer channel protocol; \
                 re-running the privileged step re-installs the answerer it speaks"
            );
            return;
        }
        Err(error) => {
            let reply = RegistrationReply::refused(error);
            if let Err(error) = write_reply(&mut stream, &reply) {
                tracing::debug!(component = COMPONENT, %error, "channel hello reply failed");
            }
            return;
        }
    };
    if let Err(error) = write_reply(&mut stream, &RegistrationReply::hello(holder)) {
        tracing::debug!(component = COMPONENT, %error, "channel hello reply failed");
        return;
    }
    // One info line per node connection — the observability contract's —
    // naming the machine that connected.
    tracing::info!(
        component = COMPONENT,
        node = %node,
        "a node connected to the zone answerer channel"
    );
    let mut partial = Vec::new();
    if let Err(error) = stream.set_read_timeout(Some(CONNECTION_POLL)) {
        tracing::debug!(
            component = COMPONENT,
            %error,
            "a channel connection could not arm its poll"
        );
        return;
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match read_line_resumable(&mut stream, &mut partial) {
            Ok(Some(line)) => {
                if !accept_publish(
                    &mut stream,
                    connection,
                    &node,
                    &line,
                    &registered,
                    own.as_ref(),
                ) {
                    break;
                }
            }
            // The node's end: the whole withdrawal. A stopped loop retires
            // the rows the same way — a restarted answerer holds nothing
            // until its nodes connect again.
            Ok(None) => break,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "a channel connection's read failed"
                );
                break;
            }
        }
    }
    let withdrawn = registered.remove(connection);
    // One info line per node disconnection, naming the machine that left
    // and the rows that went with it — a node that exits never leaves
    // names answering behind it.
    tracing::info!(
        component = COMPONENT,
        node = %node,
        rows = withdrawn
            .map(|held| held
                .rows
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>()
                .join(", "))
            .unwrap_or_default(),
        "a node disconnected from the zone answerer channel; its rows answer \
         here no more"
    );
}

/// Holds or refuses one publish line, answering it. Returns whether the
/// connection may carry on: a line that does not parse ends it, and its
/// rows go; a publish whose rows were partly refused keeps the rest, and
/// the reply names the refused ones with their reasons.
fn accept_publish(
    stream: &mut UnixStream,
    connection: u64,
    node: &str,
    line: &str,
    registered: &RegisteredTables,
    own: Option<&Arc<BoxRegistry>>,
) -> bool {
    let publish = match parse_node_line(line) {
        Ok(NodeLine::Publish(publish)) => Ok(publish),
        Ok(NodeLine::Allocate(request)) => {
            let reply = match registered.allocate(node, &box_zone_name(&request.allocate)) {
                Ok(address) => {
                    tracing::info!(
                        component = COMPONENT,
                        node = %node,
                        name = %request.allocate,
                        %address,
                        "handed a box its published address"
                    );
                    RegistrationReply::allocated(address)
                }
                Err(reason) => {
                    tracing::warn!(
                        component = COMPONENT,
                        node = %node,
                        name = %request.allocate,
                        %reason,
                        "could not hand a box a published address"
                    );
                    RegistrationReply::refused(reason)
                }
            };
            return reply_or_end(stream, connection, registered, &reply);
        }
        Ok(NodeLine::Release(request)) => {
            if let Some(address) =
                registered.release_address(node, &box_zone_name(&request.release))
            {
                tracing::info!(
                    component = COMPONENT,
                    node = %node,
                    name = %request.release,
                    %address,
                    "released a gone box's published address"
                );
            }
            return reply_or_end(
                stream,
                connection,
                registered,
                &RegistrationReply::published(Vec::new()),
            );
        }
        Err(error) => Err(error),
    };
    let outcome = match publish {
        Ok(publish) => {
            let outcome =
                registered.install_validated(connection, node, publish.rows, &reserved_names(own));
            // The publish's own line names each row it published and each
            // it refused — the answerer's log says what the zone holds.
            let held: Vec<&str> = outcome.held.iter().map(|row| row.name.as_str()).collect();
            if held.is_empty() {
                tracing::debug!(
                    component = COMPONENT,
                    node = %node,
                    "a node published no rows"
                );
            } else {
                tracing::info!(
                    component = COMPONENT,
                    node = %node,
                    rows = held.join(", "),
                    "a node published its zone rows to the answerer"
                );
            }
            for refused in &outcome.refused {
                tracing::warn!(
                    component = COMPONENT,
                    node = %node,
                    name = %refused.name,
                    reason = %refused.reason,
                    "refused a published zone row"
                );
            }
            outcome
        }
        Err(error) => {
            let outcome = write_reply(stream, &RegistrationReply::refused(error));
            if let Err(error) = outcome {
                tracing::debug!(component = COMPONENT, %error, "channel publish reply failed");
            }
            registered.remove(connection);
            return false;
        }
    };
    match write_reply(stream, &RegistrationReply::published(outcome.refused)) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(component = COMPONENT, %error, "channel publish reply failed");
            registered.remove(connection);
            false
        }
    }
}

/// Writes `reply`, ending the connection (and retiring its rows) when the
/// write fails. Returns whether the connection may carry on.
fn reply_or_end(
    stream: &mut UnixStream,
    connection: u64,
    registered: &RegisteredTables,
    reply: &RegistrationReply,
) -> bool {
    match write_reply(stream, reply) {
        Ok(()) => true,
        Err(error) => {
            tracing::debug!(component = COMPONENT, %error, "channel reply failed");
            registered.remove(connection);
            false
        }
    }
}

// ── the node: the publish's held connection ───────────────────────────────────

/// One node's publish, held by the connection it arrived on: dropping this
/// retires the rows — the connection's end is the whole withdrawal, so a
/// daemon that exits never leaves names answering behind it — and
/// [`send`](Self::send) re-publishes over the same connection, idempotent:
/// the same table again replaces the same rows and changes nothing.
struct Registration {
    /// The held connection: this publish's lifetime.
    stream: UnixStream,
}

/// What a node's first publish learned: the held connection, which kind of
/// answerer holds the port (as its hello ack named it — the installed
/// service, or the interim holder daemon; the fact the node's own start
/// line repeats), and the rows the answerer refused.
struct Published {
    /// The held connection: this publish's lifetime.
    registration: Registration,
    /// Which kind of answerer the rows went to.
    holder: String,
    /// The rows the answerer refused, with its reasons.
    refused: Vec<RefusedRow>,
}

impl Registration {
    /// Re-publishes `rows` over the held connection, waiting for the
    /// answerer's ack: a publish that did not land is not held, and the
    /// error tells the caller to connect again. The refused rows come
    /// back with the ack, so the caller can warn about a name it lost —
    /// and about an address the host may not be told — when it happens,
    /// not at the first lookup that finds the row absent.
    fn send(&mut self, rows: Vec<RegisteredRow>) -> io::Result<Vec<RefusedRow>> {
        let reply = self.request(&PublishRequest { rows })?;
        if !reply.ok {
            return Err(io::Error::new(
                // PermissionDenied, not ConnectionRefused: the answerer is
                // there and answered no — ConnectionRefused is reserved for
                // the connect itself, the marker of a channel socket file
                // with no listener behind it.
                io::ErrorKind::PermissionDenied,
                reply
                    .error
                    .unwrap_or_else(|| "the answerer refused the publish".to_string()),
            ));
        }
        Ok(reply.refused)
    }

    /// Asks the answerer for box `name`'s published address over the held
    /// connection. The outer error is the connection's (the caller
    /// reconnects); the inner one is the answerer's refusal.
    fn allocate(&mut self, name: &str) -> io::Result<Result<Ipv4Addr, String>> {
        let reply = self.request(&AllocateRequest {
            allocate: name.to_string(),
        })?;
        Ok(if reply.ok {
            reply
                .address
                .ok_or_else(|| "the answerer acknowledged the request with no address".to_string())
        } else {
            Err(reply
                .error
                .unwrap_or_else(|| "the answerer refused the request".to_string()))
        })
    }

    /// Releases box `name`'s published address over the held connection.
    fn release_address(&mut self, name: &str) -> io::Result<()> {
        self.request(&ReleaseAddressRequest {
            release: name.to_string(),
        })
        .map(|_| ())
    }

    /// One request line and its reply, bounded like every reply the node
    /// waits for.
    fn request<T: Serialize>(&mut self, line: &T) -> io::Result<RegistrationReply> {
        let _ = self.stream.set_read_timeout(Some(CHANNEL_REPLY_TIMEOUT));
        write_line(&mut self.stream, line)?;
        let reply_line = read_reply_line(&mut self.stream)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the answerer closed the channel",
            )
        })?;
        serde_json_lenient::from_str(reply_line.trim()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the answerer's reply did not parse: {error}"),
            )
        })
    }

    /// Whether the answerer's end of the connection is still there: a peek
    /// of one byte, never consuming — nothing the peek sees is lost, and a
    /// reply the next publish waits for is still its next read's. The peek
    /// carries `MSG_DONTWAIT`, so it returns at once however idle the
    /// stream is; the caller's own wait bounds the slices between peeks.
    fn answerer_alive(&self) -> io::Result<bool> {
        let mut probe = 0u8;
        // SAFETY: recv writes at most one byte into `probe`, whose length is
        // passed alongside it; the fd is the stream's own and stays valid
        // for the borrow's life. MSG_PEEK never consumes, MSG_DONTWAIT never
        // blocks.
        let seen = unsafe {
            libc::recv(
                self.stream.as_raw_fd(),
                std::ptr::addr_of_mut!(probe).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if seen < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::TimedOut
            {
                // Nothing waiting: the answerer's end has said nothing —
                // which a live one that has nothing to say is exactly how.
                return Ok(true);
            }
            return Err(error);
        }
        // The answerer's end closed (zero bytes): a service that restarted,
        // or an interim holder that went. The rows this connection held are
        // gone with it; the next pass reconnects and re-publishes. Any
        // buffered byte at all means the end is still there.
        Ok(seen != 0)
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // Closing the connection is the whole withdrawal: the answerer
        // retires this publish's rows when its read ends.
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// One node's first publish: connect to the answerer channel, say the
/// hello — the node's id, the protocol version this copy speaks — wait
/// for the answerer's ack, then publish `rows` and wait for the ack that
/// says they are held. A connect is what starts a socket-activated
/// answerer, so this is the first thing a daemon does on the channel. Two
/// of the ways it can fail — a socket path absent, and a connect refused
/// (the socket file of a dead holder with no listener behind it) — mean
/// the channel is nobody's, and the acquisition loop hosts; every other
/// way (a hello that never gets its ack or gets it refused) is a distinct
/// error the loop surfaces, never a reason to host.
fn connect_and_publish(sock: &Path, node: &str, rows: Vec<RegisteredRow>) -> io::Result<Published> {
    let mut registration = Registration {
        stream: UnixStream::connect(sock)?,
    };
    // The hello and its reply are bounded like a publish's: a service
    // manager starts a socket-activated answerer at the connect, so the
    // bound only has to cover the start, and an answerer that never
    // answers inside it is broken, not busy.
    let _ = registration
        .stream
        .set_read_timeout(Some(CHANNEL_REPLY_TIMEOUT));
    write_line(
        &mut registration.stream,
        &Hello {
            node: node.to_string(),
            version: CHANNEL_PROTOCOL_VERSION,
        },
    )?;
    let reply_line = read_reply_line(&mut registration.stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the answerer closed the channel before it answered the hello",
        )
    })?;
    let reply: RegistrationReply =
        serde_json_lenient::from_str(reply_line.trim()).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the answerer's hello reply did not parse: {error}"),
            )
        })?;
    if !reply.ok {
        return Err(io::Error::new(
            // PermissionDenied, not ConnectionRefused: the answerer accepted
            // the connect and answered no, so the channel is alive and
            // somebody's — ConnectionRefused stays the connect's own kind,
            // the marker of a socket file with no listener behind it.
            io::ErrorKind::PermissionDenied,
            reply
                .error
                .unwrap_or_else(|| "the answerer refused the hello".to_string()),
        ));
    }
    let holder = reply.holder.unwrap_or_else(|| DAEMON_HOLDER.to_string());
    let refused = registration.send(rows)?;
    Ok(Published {
        registration,
        holder,
        refused,
    })
}

/// The zone rows of `registry`'s table, as the publish wire carries them:
/// the same view the holder's own answers come from, encoded — one row per
/// published namespace, its name under the zone, its host-answerable
/// address, and its liveness — minus the node namespace's row, which never
/// travels the channel: every VM host daemon's table holds the same name
/// (`minimald.min.internal`), so the answerer answers it itself — the
/// interim holder from its own table, the installed service from its own
/// held row — and a second VM's publish of it would only be refused as a
/// clash, the by-construction refusal this exclusion takes out. The host's
/// own name is in no table's view (the answerer holds it itself), so
/// nothing else needs excluding here.
fn zone_rows(registry: &BoxRegistry) -> Vec<RegisteredRow> {
    let node = crate::box_registry::node_zone_name();
    registry
        .zone_view()
        .rows()
        .filter(|(name, _)| **name != node)
        .map(|(name, row)| RegisteredRow {
            name: name.to_string(),
            address: row.address,
            live: row.live,
        })
        .collect()
}

// ── the start ────────────────────────────────────────────────────────────────

/// The answerer's state as the control socket's status read serves it
/// (NET-138's interim surfaced at session start and on `min ls`): what the
/// acquisition loop last decided the machine's answerer is — this daemon
/// holding the port, another VM host daemon holding it with this table's
/// rows registered with it, or the port held by a process with no channel —
/// written by the loop at every pass and read where the CLI asks for it.
///
/// The status says where to look and who holds the port; whether the
/// answerer is *live* at the named port is the client's own A query for
/// `host.min.internal` to prove — the row the answerer itself holds —
/// because a host fact the host's client reads itself is the only one
/// inside the escape boundary's trust. The state before the loop's first
/// pass is [`ZoneAnswererStatus::Starting`]: the daemon has not said which
/// it is, and a read that lands there prints nothing, the arm that cannot
/// misreport.
#[derive(Debug, Clone)]
pub struct AnswererStatus(Arc<AnswererShared>);

/// What the acquisition and the control socket share: the status cell, and
/// the handover's door — whether this daemon hosts the interim (the only
/// state a release or a cancel can act on), and the sender the acquisition
/// listens on for both.
#[derive(Debug)]
struct AnswererShared {
    status: Mutex<ZoneAnswererStatus>,
    hosting: AtomicBool,
    commands: Mutex<Option<std::sync::mpsc::Sender<HandoverCommand>>>,
}

/// One handover request, carrying where its answer goes.
#[derive(Debug)]
enum HandoverCommand {
    /// Stop the interim and free the port; wait for the service's channel.
    Release(std::sync::mpsc::Sender<ReleaseReply>),
    /// Re-bind the interim at once.
    Cancel(std::sync::mpsc::Sender<ReleaseReply>),
    /// Hand box `name` its published address, from whichever answerer this
    /// daemon reaches: its own book while it hosts the interim, the
    /// answerer's over the channel otherwise.
    Allocate {
        /// The box's registry name.
        name: String,
        /// Where the address (or the refusal) goes.
        reply: std::sync::mpsc::Sender<Result<Ipv4Addr, String>>,
    },
    /// Release box `name`'s published address.
    ReleaseAddress {
        /// The box's registry name.
        name: String,
    },
}

/// Answers a command the current state cannot serve: an allocation is
/// refused with `why`, a handover request is a no-op, a release has
/// nothing to release.
fn refuse_command(command: HandoverCommand, why: &str) {
    match command {
        HandoverCommand::Release(reply) | HandoverCommand::Cancel(reply) => {
            let _ = reply.send(ReleaseReply::no_op(
                "this VM host daemon hosts no interim answerer",
            ));
        }
        HandoverCommand::Allocate { reply, .. } => {
            let _ = reply.send(Err(why.to_string()));
        }
        HandoverCommand::ReleaseAddress { .. } => {}
    }
}

/// Waits `bound` for a table ping while refusing every command that
/// arrives with `why`: the acquisition's wait in a state with no answerer
/// to allocate from, so a registration hears the reason at once rather
/// than at its own timeout.
fn wait_refusing(
    pings: &std::sync::mpsc::Receiver<()>,
    commands: &std::sync::mpsc::Receiver<HandoverCommand>,
    bound: Duration,
    why: &str,
) {
    let deadline = Instant::now() + bound;
    loop {
        while let Ok(command) = commands.try_recv() {
            refuse_command(command, why);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        match pings.recv_timeout(remaining.min(CONNECTION_POLL)) {
            Ok(()) => return,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(remaining.min(CONNECTION_POLL));
            }
        }
    }
}

/// The process holding UDP `127.0.0.1:port`, as its pid and executable,
/// when the host lets this process see it: on Linux by the socket's inode
/// in `/proc/net/udp` and the fd that names it, on macOS by `lsof`. `None`
/// when it is not knowable (another user's process, no `lsof`).
fn hook_port_holder(port: u16) -> Option<(u32, String)> {
    #[cfg(target_os = "linux")]
    {
        let wanted = [
            format!("0100007F:{port:04X}"),
            format!("00000000:{port:04X}"),
        ];
        let table = std::fs::read_to_string("/proc/net/udp").ok()?;
        let inode = table.lines().skip(1).find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() > 9 && wanted.iter().any(|want| fields[1] == want))
                .then(|| fields[9].to_string())
        })?;
        let target = format!("socket:[{inode}]");
        for entry in std::fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            if fds.flatten().any(|fd| {
                std::fs::read_link(fd.path()).is_ok_and(|link| link.as_os_str() == target.as_str())
            }) {
                let exe = std::fs::read_link(entry.path().join("exe")).map_or_else(
                    |_| "an unreadable executable".to_string(),
                    |exe| exe.display().to_string(),
                );
                return Some((pid, exe));
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("/usr/sbin/lsof")
            .args(["-nP", "-t", &format!("-iUDP@127.0.0.1:{port}")])
            .output()
            .ok()?;
        let pid: u32 = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()?;
        let comm = std::process::Command::new("/bin/ps")
            .args(["-o", "comm=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let exe = String::from_utf8_lossy(&comm.stdout).trim().to_string();
        Some((
            pid,
            if exe.is_empty() {
                "an unnamed executable".to_string()
            } else {
                exe
            },
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = port;
        None
    }
}

/// The error a node with no answerer channel and the hook port held
/// surfaces, and every box registration fails with: the port, the holder
/// when known, and the remedy for its kind.
fn channelless_holder_error(port: u16, holder: Option<(u32, String)>) -> String {
    let native = holder.as_ref().is_some_and(|(_, exe)| {
        Path::new(exe)
            .file_name()
            .is_some_and(|name| name == "minimald")
    });
    let who = holder.map_or_else(
        || "a process this daemon cannot identify".to_string(),
        |(pid, exe)| format!("pid {pid} ({exe})"),
    );
    if native {
        format!(
            "the zone answerer's hook port 127.0.0.1:{port} is held by a native minimald, \
             {who}, with no answerer channel, so no box can be handed an address: install \
             the answerer service (min session start prints the command); native daemons \
             publish into it once T90 lands"
        )
    } else {
        format!(
            "the zone answerer's hook port 127.0.0.1:{port} is held by {who}, which has no \
             answerer channel, so no box can be handed an address: free port {port} or set \
             the hook port"
        )
    }
}

/// Why a box cannot be handed an address while this daemon reaches no
/// answerer.
const NO_ANSWERER: &str = "this VM host daemon reaches no zone answerer to hand the box an \
                           address (see the zone-answerer lines in its log); box addresses \
                           are allocated host-wide by the answerer, never by the node";

/// The answer to a release or a cancel: whether it changed anything, and
/// the sentence the daemon logged for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseReply {
    /// Whether the request changed anything.
    pub acted: bool,
    /// What the daemon did.
    pub detail: String,
}

impl ReleaseReply {
    fn acted(detail: impl Into<String>) -> Self {
        Self {
            acted: true,
            detail: detail.into(),
        }
    }

    fn no_op(detail: impl Into<String>) -> Self {
        Self {
            acted: false,
            detail: detail.into(),
        }
    }
}

impl AnswererStatus {
    /// A status whose acquisition loop has not run yet.
    #[must_use]
    pub fn starting() -> Self {
        Self(Arc::new(AnswererShared {
            status: Mutex::new(ZoneAnswererStatus::Starting),
            hosting: AtomicBool::new(false),
            commands: Mutex::new(None),
        }))
    }

    /// The state the acquisition loop last wrote.
    #[must_use]
    pub fn get(&self) -> ZoneAnswererStatus {
        self.0
            .status
            .lock()
            .expect("the answerer status lock is never held across a panic")
            .clone()
    }

    /// The acquisition loop's own writer: called at every pass, with the
    /// state that pass left the machine's answerer in.
    pub(crate) fn set(&self, status: ZoneAnswererStatus) {
        *self
            .0
            .status
            .lock()
            .expect("the answerer status lock is never held across a panic") = status;
    }

    /// Marks whether this daemon hosts the interim (or is inside a release
    /// window it may re-bind from).
    fn set_hosting(&self, hosting: bool) {
        self.0.hosting.store(hosting, Ordering::SeqCst);
    }

    /// The acquisition's end of the handover door: every release and cancel
    /// from now on reaches the returned receiver.
    fn attach_commands(&self) -> std::sync::mpsc::Receiver<HandoverCommand> {
        let (sender, receiver) = std::sync::mpsc::channel();
        *self
            .0
            .commands
            .lock()
            .expect("the answerer command lock is never held across a panic") = Some(sender);
        receiver
    }

    /// Asks the acquisition to release its interim answerer (NET-122's
    /// handover): answered once the port is free, or as a no-op by a
    /// daemon that hosts no interim.
    #[must_use]
    pub fn release(&self) -> ReleaseReply {
        self.ask(HandoverCommand::Release, "nothing to release")
    }

    /// Asks the acquisition to cancel a release and re-bind its interim at
    /// once; a no-op where no release is pending.
    #[must_use]
    pub fn release_cancel(&self) -> ReleaseReply {
        self.ask(HandoverCommand::Cancel, "nothing to re-bind")
    }

    /// Asks the machine's answerer for box `name`'s published address
    /// (design §7.1): allocation is host-global, arbitrated by the answerer
    /// this daemon reaches, so co-resident nodes never self-assign.
    ///
    /// # Errors
    ///
    /// The reason no address was handed out: no answerer reachable, the
    /// range exhausted, or no answer in time.
    pub fn allocate(&self, name: &str) -> Result<Ipv4Addr, String> {
        let Some(sender) = self.sender() else {
            return Err(NO_ANSWERER.to_string());
        };
        let (reply_to, reply) = std::sync::mpsc::channel();
        if sender
            .send(HandoverCommand::Allocate {
                name: name.to_string(),
                reply: reply_to,
            })
            .is_err()
        {
            return Err(NO_ANSWERER.to_string());
        }
        // Bounded past the handover window an allocation may wait out.
        reply
            .recv_timeout(RELEASE_WINDOW + RELEASE_REPLY_TIMEOUT)
            .unwrap_or_else(|_| {
                Err("the zone answerer did not hand out an address in time".to_string())
            })
    }

    /// Releases box `name`'s published address: the box is gone.
    pub fn release_address(&self, name: &str) {
        if let Some(sender) = self.sender() {
            let _ = sender.send(HandoverCommand::ReleaseAddress {
                name: name.to_string(),
            });
        }
    }

    fn sender(&self) -> Option<std::sync::mpsc::Sender<HandoverCommand>> {
        self.0
            .commands
            .lock()
            .expect("the answerer command lock is never held across a panic")
            .clone()
    }

    /// A status whose allocations a test thread answers from its own book,
    /// as node `node` — the stand-in for the acquisition loop in tests that
    /// register boxes without one.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn allocating_for_tests(node: &str) -> Self {
        Self::allocating_for_tests_with(node, || None, |_, _| {})
    }

    /// [`Self::allocating_for_tests`] that asks `hold_reply` after each
    /// allocation, and runs `on_release` with the box's name and the address
    /// it freed, if it held one, after each release. When `hold_reply`
    /// hands back a gate, the allocation's reply is held until the gate
    /// opens (a send or a drop) while the book goes on serving: a slow
    /// answerer's late reply, the address already recorded against the box.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn allocating_for_tests_with(
        node: &str,
        mut hold_reply: impl FnMut() -> Option<std::sync::mpsc::Receiver<()>> + Send + 'static,
        mut on_release: impl FnMut(&str, Option<Ipv4Addr>) + Send + 'static,
    ) -> Self {
        let status = Self::starting();
        let commands = status.attach_commands();
        let node = node.to_string();
        std::thread::spawn(move || {
            let mut book = AddressBook::default();
            while let Ok(command) = commands.recv() {
                match command {
                    HandoverCommand::Allocate { name, reply } => {
                        let answer = book.allocate(&node, &box_zone_name(&name));
                        match hold_reply() {
                            Some(gate) => {
                                std::thread::spawn(move || {
                                    let _ = gate.recv();
                                    let _ = reply.send(answer);
                                });
                            }
                            None => {
                                let _ = reply.send(answer);
                            }
                        }
                    }
                    HandoverCommand::ReleaseAddress { name } => {
                        let released = book.release(&node, &box_zone_name(&name));
                        on_release(&name, released);
                    }
                    other => refuse_command(other, NO_ANSWERER),
                }
            }
        });
        status
    }

    fn ask(
        &self,
        command: fn(std::sync::mpsc::Sender<ReleaseReply>) -> HandoverCommand,
        nothing: &str,
    ) -> ReleaseReply {
        if !self.0.hosting.load(Ordering::SeqCst) {
            return ReleaseReply::no_op(format!(
                "this VM host daemon hosts no interim answerer; {nothing}"
            ));
        }
        let sender = self
            .0
            .commands
            .lock()
            .expect("the answerer command lock is never held across a panic")
            .clone();
        let Some(sender) = sender else {
            return ReleaseReply::no_op(format!(
                "this VM host daemon's answerer is not running; {nothing}"
            ));
        };
        let (reply_to, reply) = std::sync::mpsc::channel();
        if sender.send(command(reply_to)).is_err() {
            return ReleaseReply::no_op(format!(
                "this VM host daemon's answerer is not running; {nothing}"
            ));
        }
        reply
            .recv_timeout(RELEASE_REPLY_TIMEOUT)
            .unwrap_or_else(|_| {
                ReleaseReply::no_op("the zone answerer did not answer the request in time")
            })
    }
}

/// Starts the host answerer: this daemon's publish-or-host acquisition, for
/// the daemon's lifetime. The acquisition connects to the answerer channel
/// first and publishes this table's zone rows to whichever answerer holds
/// the port — the installed host service, or the interim holder daemon —
/// and only hosts the answerer itself when no channel socket exists and
/// the port is free. Every pass the acquisition takes writes the state it
/// left the machine in to `status`, the one place the control socket's
/// status read serves it from. One background thread, for the daemon's
/// lifetime, the way the control socket serves; a thread the host could
/// not spare is the only failure returned, because an answerer somebody
/// else holds is the normal multi-VM case, not an error to fail a boot
/// over.
///
/// # Errors
///
/// Returns the OS error when the thread cannot be spawned.
pub fn spawn(
    registry: BoxRegistry,
    port: u16,
    status: AnswererStatus,
) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("minvmd-zone-answerer".to_string())
        .spawn(move || acquire_loop(registry, port, status))
}

/// Acquires the machine's answerer — by publishing to it or by hosting it —
/// for this daemon's lifetime.
fn acquire_loop(registry: BoxRegistry, port: u16, status: AnswererStatus) {
    let paths = ChannelPaths {
        global: resolve_channel_sock(),
        interim: interim_channel_sock(),
        marker: resolve_install_marker(),
        release_window: RELEASE_WINDOW,
    };
    acquire(registry, port, &paths, &node_id(), &status);
}

/// The acquisition over one channel, for the tests that drive it on a
/// temporary channel: `channel` is the interim's, and no service is
/// installed (the marker and the global channel are paths nothing holds),
/// so the decision is the interim's publish-or-host alone.
/// Makes the dir a test's interim channel sits in mode 0700, the per-user
/// run dir's mode [`prepare_interim_dir`] requires.
#[cfg(test)]
fn private_test_dir(sock: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(dir) = sock.parent() {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
}

#[cfg(test)]
fn acquire_loop_at(registry: BoxRegistry, port: u16, channel: PathBuf, status: AnswererStatus) {
    // The interim's dir must be the operator's alone; a test's temp dir is
    // created with the umask's mode, so make it private as the per-user run
    // dir is.
    private_test_dir(&channel);
    let paths = ChannelPaths {
        global: channel.with_file_name("no-global-channel.sock"),
        marker: channel.with_file_name("no-install-marker"),
        interim: channel,
        release_window: RELEASE_WINDOW,
    };
    acquire(registry, port, &paths, crate::state::vm_name(), &status);
}

/// What woke the acquisition's wait ([`wait_for_wake`]): a table change (a
/// row that must be re-published), the held connection's end (the
/// answerer's side went), or the cadence bound.
enum Wake {
    /// The registry pinged: the table changed.
    Table,
    /// The held connection's end closed.
    Loss,
    /// The cadence bound ran out.
    Cadence,
    /// A command arrived for the held connection to serve.
    Command(HandoverCommand),
}

/// Waits for the next wake after a publish lands: the registry's table
/// change ping, the held connection's end, or the [`PORT_RECHECK`] bound.
/// The connection's end is peeked — never consuming, so a reply the next
/// publish waits for stays its next read's — once per slice, because two
/// blocking reads cannot be selected on std and the table ping holds the
/// wait; the peek is the whole point, though: an answerer that goes is
/// known at the slice, not at the next cadence, which is what keeps a
/// service restart a short absence window.
fn wait_for_wake(
    pings: &mut std::sync::mpsc::Receiver<()>,
    commands: &std::sync::mpsc::Receiver<HandoverCommand>,
    held: Option<&Registration>,
    bound: Duration,
) -> Wake {
    let deadline = Instant::now() + bound;
    loop {
        if let Ok(command) = commands.try_recv() {
            return Wake::Command(command);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Wake::Cadence;
        }
        match pings.recv_timeout(remaining.min(CONNECTION_POLL)) {
            Ok(()) => return Wake::Table,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Wake::Cadence,
        }
        if let Some(held) = held
            && matches!(held.answerer_alive(), Ok(false) | Err(_))
        {
            return Wake::Loss;
        }
    }
}

/// Waits for the next wake after a publish landed, keeping the connection
/// when it survived it: a table change or the cadence keeps it; its end
/// drops it — entering an error episode, since this table's rows answer
/// nothing from the moment the answerer's side closes until the next pass
/// reconnects — and the caller reconnects next pass.
fn wait_out_wake(
    pings: &mut std::sync::mpsc::Receiver<()>,
    commands: &std::sync::mpsc::Receiver<HandoverCommand>,
    mut registration: Registration,
    status: &AnswererStatus,
    port: u16,
    erroring: &mut bool,
) -> Option<Registration> {
    loop {
        match wait_for_wake(pings, commands, Some(&registration), PORT_RECHECK) {
            Wake::Table | Wake::Cadence => return Some(registration),
            Wake::Command(command) => {
                if !serve_over_channel(&mut registration, command) {
                    surface_error(
                        status,
                        port,
                        erroring,
                        "the answerer channel failed while serving a box address request",
                    );
                    return None;
                }
            }
            Wake::Loss => {
                surface_error(
                    status,
                    port,
                    erroring,
                    "the answerer's end of the channel closed (a service restart, or the \
                     interim holder's exit)",
                );
                return None;
            }
        }
    }
}

/// Serves one command over the held connection: an allocation or a
/// release goes to the answerer that holds the port; a handover request
/// is a no-op for a daemon that hosts nothing. Returns whether the
/// connection survived.
fn serve_over_channel(registration: &mut Registration, command: HandoverCommand) -> bool {
    match command {
        HandoverCommand::Allocate { name, reply } => match registration.allocate(&name) {
            Ok(result) => {
                let _ = reply.send(result);
                true
            }
            Err(error) => {
                let _ = reply.send(Err(format!(
                    "the answerer channel failed during the request: {error}"
                )));
                false
            }
        },
        HandoverCommand::ReleaseAddress { name } => registration.release_address(&name).is_ok(),
        other => {
            refuse_command(other, NO_ANSWERER);
            true
        }
    }
}

/// Enters an error episode: the status names the port as held with nothing
/// answering this table's names, the first entry into an episode warns with
/// `why`, and the passes inside it stay at debug — until a publish lands
/// again, which re-arms the warn (the caller resets `erroring`), so an
/// unrelated later failure warns on its own.
fn surface_error(status: &AnswererStatus, port: u16, erroring: &mut bool, why: &str) {
    status.set(ZoneAnswererStatus::PortHeldNoChannel { port });
    if *erroring {
        tracing::debug!(
            component = COMPONENT,
            "the zone answerer still answers nothing for this VM: {why}"
        );
    } else {
        *erroring = true;
        tracing::warn!(
            component = COMPONENT,
            port,
            "this VM's box names are not answered on the host: {why}"
        );
    }
}

/// Warns the rows an answerer refused this table's publish, each with its
/// reason: a name this table lost to the node that first published it, or
/// an address the host may not be told — the operator's problem to see at
/// the moment it happens, not at the first lookup that finds the row
/// absent.
fn warn_refused(node: &str, refused: Vec<RefusedRow>) {
    for row in refused {
        tracing::warn!(
            component = COMPONENT,
            node = %node,
            name = %row.name,
            reason = %row.reason,
            "the answerer refused a published zone row"
        );
    }
}

/// The acquisition over named channel paths, so the whole publish-or-host
/// machinery is drivable where the channels are not the machine's own (the
/// tests below run daemons and the installed service's serving loops on
/// temporary channels).
///
/// Whether the service is installed is the install marker's to say, never
/// the channel socket's existence. With the marker present the node
/// publishes to the machine-global channel and nowhere else: a connect is
/// what starts a socket-activated service, so a channel that refuses or
/// times out is an error surfaced at session start, never a reason to host.
/// With the marker absent, a socket at the global path is a leftover and
/// is logged as one; the node then tries the interim's per-user
/// channel — present and answering, it publishes there — and only when that
/// is absent (or a dead holder's corpse) does the port decide: free, this
/// daemon hosts the answerer itself as the recorded interim and holds the
/// interim channel beside it for the operator's other nodes; held by a
/// process with no channel, the error is surfaced. Never both.
///
/// A publish that lands lives for the session: the loop re-publishes the
/// whole table on every change ping — idempotent, so a row that went is
/// gone in the same line — and on the [`PORT_RECHECK`] cadence, and the
/// moment the answerer's end of the connection closes it reconnects with
/// backoff and re-publishes, so a service restart is a short absence
/// window and never a session restart.
fn acquire(
    registry: BoxRegistry,
    port: u16,
    paths: &ChannelPaths,
    node: &str,
    status: &AnswererStatus,
) {
    // Subscribed before the first connect, so no change lands unpinged in
    // the window before the answerer is decided.
    let mut pings = registry.subscribe_table_pings();
    let commands = status.attach_commands();
    let mut held: Option<Registration> = None;
    // The once-only start info line: the first publish that lands says
    // which answerer the rows went to, whatever the passes before it
    // warned.
    let mut published_once = false;
    // Whether the loop is inside an error episode ([`surface_error`]).
    let mut erroring = false;
    // Whether a leftover socket file has been said already: a corpse logs
    // once, not per pass of a collision episode.
    let mut stale_once = false;
    let mut stale_global_once = false;
    // The backoff between attempts on a channel that is present but not
    // answering, doubling to the re-check cadence.
    let mut retry = CHANNEL_RETRY;
    // The status a held connection reports: which answerer took the rows,
    // as the last publish's hello ack named it.
    let mut held_status = ZoneAnswererStatus::Registered { port };
    loop {
        // ── the publish arm, a held connection: re-publish the whole
        // table, idempotent. A send that fails is the connection's end —
        // the next pass reconnects, immediately, because a restarted
        // answerer is most likely back.
        if let Some(mut registration) = held.take() {
            match registration.send(zone_rows(&registry)) {
                Ok(refused) => {
                    erroring = false;
                    status.set(held_status.clone());
                    warn_refused(node, refused);
                    held = wait_out_wake(
                        &mut pings,
                        &commands,
                        registration,
                        status,
                        port,
                        &mut erroring,
                    );
                }
                Err(error) => {
                    surface_error(
                        status,
                        port,
                        &mut erroring,
                        &format!("the answerer channel connection failed: {error}"),
                    );
                }
            }
            continue;
        }
        // ── the publish arm, fresh. The installed service first, decided by
        // its marker: its channel or nothing.
        let installed = paths.marker.exists();
        let channel = if installed {
            &paths.global
        } else {
            if !stale_global_once && std::fs::symlink_metadata(&paths.global).is_ok() {
                stale_global_once = true;
                tracing::info!(
                    component = COMPONENT,
                    channel = %paths.global.display(),
                    marker = %paths.marker.display(),
                    "a socket sits at the machine-global answerer channel path but no \
                     answerer service is installed (no install marker); treating the \
                     path as absent"
                );
            }
            &paths.interim
        };
        match connect_and_publish(channel, node, zone_rows(&registry)) {
            Ok(published) => {
                retry = CHANNEL_RETRY;
                erroring = false;
                held_status = registered_status(&published.holder, port);
                status.set(held_status.clone());
                warn_refused(node, published.refused);
                if !published_once {
                    published_once = true;
                    announce_publish(&published.holder, port, channel, node);
                }
                held = wait_out_wake(
                    &mut pings,
                    &commands,
                    published.registration,
                    status,
                    port,
                    &mut erroring,
                );
                continue;
            }
            // The service is installed and its channel did not answer: an
            // error, never a reason to host.
            Err(error) if installed => {
                surface_error(
                    status,
                    port,
                    &mut erroring,
                    &format!(
                        "the answerer service is installed ({}) but its channel {} did not \
                         answer: {error}",
                        paths.marker.display(),
                        paths.global.display()
                    ),
                );
                wait_refusing(&pings, &commands, retry, NO_ANSWERER);
                retry = (retry * 2).min(PORT_RECHECK);
                continue;
            }
            // The interim channel's path is absent: the answerer is
            // nobody's, and the host arm below decides this daemon's.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            // A refused connect names a corpse: a socket file with no
            // listener behind it, the leftover of an interim holder that
            // died. The host arm takes the machine's answerer and replaces
            // the leftover when it binds the channel.
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                if !stale_once {
                    stale_once = true;
                    tracing::info!(
                        component = COMPONENT,
                        channel = %channel.display(),
                        "the answerer channel socket file is a dead holder's leftover: \
                         nothing listens behind it, so this VM's host daemon takes the \
                         zone answerer from here"
                    );
                }
            }
            // A live interim channel that refuses or times out is an error,
            // never a reason to host. Retried with backoff.
            Err(error) => {
                surface_error(
                    status,
                    port,
                    &mut erroring,
                    &format!("the answerer channel is present but did not answer: {error}"),
                );
                wait_refusing(&pings, &commands, retry, NO_ANSWERER);
                retry = (retry * 2).min(PORT_RECHECK);
                continue;
            }
        }
        // ── the host arm: no service, no interim channel — this daemon
        // hosts the answerer itself, when the port is free.
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(socket) => {
                if let Some(published) =
                    host_interim(&registry, port, paths, node, status, &commands, socket)
                {
                    // A release handed the port to the service and the
                    // publish landed there: from now on this daemon is a
                    // channel client. Pings filed while it hosted are moot —
                    // the publish just carried the whole table.
                    while pings.try_recv().is_ok() {}
                    erroring = false;
                    retry = CHANNEL_RETRY;
                    held_status = registered_status(&published.holder, port);
                    status.set(held_status.clone());
                    warn_refused(node, published.refused);
                    held = wait_out_wake(
                        &mut pings,
                        &commands,
                        published.registration,
                        status,
                        port,
                        &mut erroring,
                    );
                }
            }
            // No answerer channel and the hook port held: the holder is no
            // node of this operator's (those publish over the per-user
            // interim channel), so nothing here can answer or allocate. A
            // loud error naming the port, the holder and the remedy — every
            // box registration fails with it until the port frees.
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                let why = channelless_holder_error(port, hook_port_holder(port));
                surface_error(status, port, &mut erroring, &why);
                wait_refusing(&pings, &commands, PORT_RECHECK, &why);
            }
            Err(error) => {
                let why = format!(
                    "could not bind the zone answerer's hook port 127.0.0.1:{port}: {error}; \
                     free port {port} or set the hook port"
                );
                surface_error(status, port, &mut erroring, &why);
                wait_refusing(&pings, &commands, PORT_RECHECK, &why);
            }
        }
    }
}

/// The status a node that published its rows reports, by the holder its
/// hello ack named: the manager-held service, or another VM host daemon
/// hosting the single-operator interim.
fn registered_status(holder: &str, port: u16) -> ZoneAnswererStatus {
    if holder == SERVICE_HOLDER {
        ZoneAnswererStatus::ManagerHeld { port }
    } else {
        ZoneAnswererStatus::Registered { port }
    }
}

/// The one info line at a node's first publish, the diagnostics contract's:
/// publish-or-host, the hook port, the channel path — and which answerer
/// holds the port, as its hello ack named it.
fn announce_publish(holder: &str, port: u16, channel: &Path, node: &str) {
    let whose = match holder {
        SERVICE_HOLDER => "the manager-held answerer service",
        _ => "another VM host daemon holding the port (the single-operator interim)",
    };
    tracing::info!(
        component = COMPONENT,
        holder = %holder,
        port,
        node = %node,
        channel = %channel.display(),
        "the zone answerer is held by {whose}; registered this table's zone rows with it \
         over the channel at {} and hosts nothing here",
        channel.display()
    );
}

/// How a release window ended.
enum WindowEnd {
    /// The service's channel took this node's publish.
    Switched(Published),
    /// A cancel arrived: re-bind now, answering it once bound.
    Cancelled(std::sync::mpsc::Sender<ReleaseReply>),
    /// The window ran out with no channel and no cancel.
    TimedOut,
}

/// Hosts the interim answerer on `socket` (NET-138's recorded interim) until
/// a release hands the port to the installed service and this node's
/// publish lands on the service's channel — returned, for the caller to
/// hold as a channel client. Never returns otherwise: a cancelled or timed
/// out release re-binds the interim and keeps hosting, and a re-bind that
/// finds the port taken returns `None` for the caller's next pass to
/// surface.
///
/// The interim holds its per-user channel beside the port, so the
/// operator's other nodes, whatever their state dir, publish into it; a release stops both,
/// removes the channel's socket file, and answers the release once the
/// port is free.
fn host_interim(
    registry: &BoxRegistry,
    port: u16,
    paths: &ChannelPaths,
    node: &str,
    status: &AnswererStatus,
    commands: &std::sync::mpsc::Receiver<HandoverCommand>,
    socket: UdpSocket,
) -> Option<Published> {
    let mut socket = socket;
    let mut rebound: Option<std::sync::mpsc::Sender<ReleaseReply>> = None;
    loop {
        let addr = socket
            .local_addr()
            .map_or_else(|_| format!("127.0.0.1:{port}"), |addr| addr.to_string());
        status.set(ZoneAnswererStatus::Holder { port });
        status.set_hosting(true);
        tracing::info!(
            component = COMPONENT,
            listener = %addr,
            port,
            channel = %paths.interim.display(),
            status = "serving",
            "no answerer service is installed and no interim channel answers; this \
             VM's host daemon holds the host loopback answerer port itself as the \
             single-operator interim: the box zone answers here, from this \
             host-authored table, and this state dir's other nodes publish over \
             the interim channel at {}",
            paths.interim.display()
        );
        // One table of published rows, shared by the answers and the
        // channel that fills them.
        let registered = Arc::new(RegisteredTables::new());
        // This node's own boxes keep their addresses: the book the interim
        // hands addresses from starts with them, so no co-resident node is
        // handed one of them.
        registered.claim_own(node, &zone_rows(registry));
        let answerer = HostAnswerer::new(registry.clone(), Arc::clone(&registered));
        let channel_stop = match hold_channel(
            &paths.interim,
            Arc::clone(&registered),
            Some(Arc::new(registry.clone())),
            // SAFETY: geteuid only reads the process's own uid.
            unsafe { libc::geteuid() },
        ) {
            Ok(stop) => Some(stop),
            Err(error) => {
                tracing::warn!(
                    component = COMPONENT,
                    %error,
                    "could not bind the interim answerer channel socket; other VM host \
                     daemons cannot publish their names to this answerer"
                );
                None
            }
        };
        let serve_stop = Arc::new(AtomicBool::new(false));
        let serving = Arc::clone(&serve_stop);
        let server = std::thread::Builder::new()
            .name("minvmd-zone-answers".to_string())
            .spawn(move || serve_with_stop(socket, answerer, Some(serving)));
        let server = match server {
            Ok(server) => server,
            Err(error) => {
                tracing::warn!(
                    component = COMPONENT,
                    %error,
                    "could not start the interim answerer's serving thread"
                );
                status.set_hosting(false);
                return None;
            }
        };
        if let Some(reply_to) = rebound.take() {
            let _ = reply_to.send(ReleaseReply::acted(format!(
                "re-bound the interim answerer at 127.0.0.1:{port}"
            )));
        }
        // ── hosting: wait for a release.
        let release = loop {
            match commands.recv() {
                Ok(HandoverCommand::Release(reply_to)) => break reply_to,
                Ok(HandoverCommand::Cancel(reply_to)) => {
                    let _ = reply_to.send(ReleaseReply::no_op(
                        "no release is pending; the interim answerer is serving",
                    ));
                }
                // The interim is the answerer: its own boxes are handed
                // addresses from the same book its channel's nodes are.
                Ok(HandoverCommand::Allocate { name, reply }) => {
                    let _ = reply.send(registered.allocate(node, &box_zone_name(&name)));
                }
                Ok(HandoverCommand::ReleaseAddress { name }) => {
                    registered.release_address(node, &box_zone_name(&name));
                }
                // The door closed (the status went with its daemon): serve
                // for the process's life, as the interim always did.
                Err(_) => {
                    let _ = server.join();
                    return None;
                }
            }
        };
        // ── the release: stop answering, free the port, retire the channel.
        serve_stop.store(true, Ordering::SeqCst);
        let _ = server.join();
        if let Some(stop) = channel_stop {
            stop.store(true, Ordering::SeqCst);
        }
        let _ = std::fs::remove_file(&paths.interim);
        status.set(ZoneAnswererStatus::Starting);
        let detail = format!(
            "released the interim answerer: 127.0.0.1:{port} is free; waiting up to {} s \
             for the answerer service's channel at {}",
            paths.release_window.as_secs(),
            paths.global.display()
        );
        tracing::info!(component = COMPONENT, port, "{detail}");
        let _ = release.send(ReleaseReply::acted(detail));
        // ── the window: the service's channel, a cancel, or the bound.
        let deadline = Instant::now() + paths.release_window;
        // Box address requests that arrive mid-handover wait for the
        // service's channel, for the rest of the window, rather than being
        // refused: they are served there once it answers.
        let mut queued: Vec<HandoverCommand> = Vec::new();
        let end = loop {
            match commands.recv_timeout(RELEASE_POLL) {
                Ok(HandoverCommand::Cancel(reply_to)) => break WindowEnd::Cancelled(reply_to),
                Ok(HandoverCommand::Release(reply_to)) => {
                    let _ = reply_to.send(ReleaseReply::no_op(
                        "the interim answerer is already released",
                    ));
                }
                Ok(
                    command @ (HandoverCommand::Allocate { .. }
                    | HandoverCommand::ReleaseAddress { .. }),
                ) => queued.push(command),
                Err(_) => {}
            }
            if paths.marker.exists()
                && let Ok(published) = connect_and_publish(&paths.global, node, zone_rows(registry))
            {
                break WindowEnd::Switched(published);
            }
            if Instant::now() >= deadline {
                break WindowEnd::TimedOut;
            }
        };
        match end {
            WindowEnd::Switched(mut published) => {
                status.set_hosting(false);
                announce_publish(&published.holder, port, &paths.global, node);
                for command in queued {
                    serve_over_channel(&mut published.registration, command);
                }
                return Some(published);
            }
            WindowEnd::Cancelled(reply_to) => {
                tracing::info!(
                    component = COMPONENT,
                    port,
                    "the release was cancelled; re-binding the interim answerer"
                );
                rebound = Some(reply_to);
            }
            WindowEnd::TimedOut => {
                tracing::info!(
                    component = COMPONENT,
                    port,
                    "no answerer service channel came within {} s of the release; \
                     re-binding the interim answerer",
                    paths.release_window.as_secs()
                );
            }
        }
        // The window ended without the service: the queued requests fail,
        // naming why, rather than being served by an interim book that no
        // longer holds the addresses the service's nodes may republish.
        for command in queued {
            refuse_command(
                command,
                "answerer handover did not complete: the answerer service's channel did not \
                 answer within the release window",
            );
        }
        match UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
            Ok(bound) => socket = bound,
            Err(error) => {
                let detail =
                    format!("could not re-bind the interim answerer at 127.0.0.1:{port}: {error}");
                tracing::warn!(component = COMPONENT, port, "{detail}");
                if let Some(reply_to) = rebound.take() {
                    let _ = reply_to.send(ReleaseReply::no_op(detail));
                }
                status.set_hosting(false);
                return None;
            }
        }
    }
}

/// The serving loop both holders share. Without a stop flag it serves
/// forever (the interim's daemon-held lifetime); with one it polls
/// [`CONNECTION_POLL`] between receives, so a service asked to stop stops
/// inside a poll slice instead of blocking in `recv_from` until the next
/// datagram.
fn serve_with_stop(socket: UdpSocket, answerer: HostAnswerer, stop: Option<Arc<AtomicBool>>) {
    if stop.is_some() {
        let _ = socket.set_read_timeout(Some(CONNECTION_POLL));
    }
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        if let Some(stop) = &stop
            && stop.load(Ordering::SeqCst)
        {
            return;
        }
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if let Some(reply) = answerer.respond(peer, &buf[..len])
                    && let Err(error) = socket.send_to(&reply, peer)
                {
                    tracing::debug!(
                        component = COMPONENT,
                        %peer,
                        %error,
                        "could not send a box-zone reply"
                    );
                }
            }
            // A poll wake with the stop still unset is the next turn.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && stop.is_some() =>
            {
                continue;
            }
            Err(error) => {
                tracing::debug!(
                    component = COMPONENT,
                    %error,
                    "box-zone receive failed; continuing"
                );
            }
        }
    }
}

/// Serves the answerer as the installed host service: the listener the
/// service manager holds (the hook port on the host loopback) and the
/// channel socket it holds beside it, both inherited, answering with the
/// shared zone decision from the rows node daemons publish over the
/// channel. Rows live only while their node's connection is up — a service
/// restart holds nothing until the nodes reconnect and re-publish, which
/// they do unprompted, in backoff time.
///
/// The uid gate is the channel's whole security posture: a peer whose uid
/// is not this service's own is refused before a byte of its payload is
/// read ([`serve_channel`]), so only the operator's own daemons — and the
/// tests — can publish.
pub(crate) fn serve_service(
    listener: UdpSocket,
    channel: UnixListener,
    expected_uid: u32,
    stop: Arc<AtomicBool>,
) {
    let registered = Arc::new(RegisteredTables::new());
    let answerer = HostAnswerer::for_service(Arc::clone(&registered));
    // The answers are served on their own thread, so a slow DNS exchange
    // never delays a publish — and the channel is served here, on the
    // calling thread: a service has nothing else to do, and its per-node
    // connect and disconnect lines then come from the one thread a service
    // manager's journal reads them from.
    let answer_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("minvmd-zone-answers".to_string())
        .spawn(move || serve_with_stop(listener, answerer, Some(answer_stop)))
        .expect("the answerer's answers thread should spawn");
    serve_channel(
        channel,
        registered,
        expected_uid,
        None,
        SERVICE_HOLDER,
        stop,
    );
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use hickory_proto::op::Query;
    use tracing_subscriber::fmt::MakeWriter;

    use crate::box_registry::BoxRegistration;

    use super::*;

    /// The answerer's own row is the sessions zone's host row, byte for byte:
    /// the CLI's liveness query reads [`HOST_NAME`], so a spelling that drifts
    /// from the zone fails here rather than as a dead liveness probe.
    #[test]
    fn host_name_is_the_zone_host_row() {
        assert_eq!(HOST_NAME, "host.min.internal");
        assert_eq!(HOST_NAME, zone_answer::HOST_ROW_NAME);
    }

    /// A `MakeWriter` accumulating everything written into a shared buffer, so
    /// a test can assert on the structured fields a `tracing` event emitted —
    /// the same scaffolding the native daemon's answerer tests build, because
    /// the two answerers prove the same log lines.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for CaptureWriter {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the lock is never poisoned: the capture's only other \
                      holder unwraps it too, and a test that panics there \
                      has already failed"
        )]
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl MakeWriter<'_> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// The plan's default subnet: the one the daemon's own registry is
    /// built with, so a test registry's rows sit at the addresses
    /// production's do.
    const SUBNET: switch::SwitchSubnet = switch::DEFAULT_SUBNET;

    /// One query datagram, the wire form the answerer reads: `name` as an
    /// FQDN (root dot included) at `rtype` — the same scaffolding the native
    /// daemon's answerer tests drive, so the two prove the same wire.
    fn encode_query(name: &str, rtype: RecordType) -> Vec<u8> {
        let qname = Name::from_utf8(name).expect("query name parses");
        let mut msg = Message::query();
        msg.add_query(Query::query(qname, rtype));
        msg.to_vec().expect("query encodes")
    }

    /// A registry holding one published box, `web`, at an address from the
    /// reserved local range, beside the node's own namespace — the table the
    /// daemon's start path fills. Returns the registry and the box's
    /// published loopback address, the address its name must answer with.
    fn web_registry() -> (BoxRegistry, Ipv4Addr) {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        let web = Ipv4Addr::new(127, 0, 64, 9);
        registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            web,
        ));
        (registry, web)
    }

    /// The answerer over `own`, with its registered tables filled by
    /// `install` — the rows a co-resident daemon would have filed over the
    /// channel.
    fn answerer_over(own: BoxRegistry, install: impl FnOnce(&RegisteredTables)) -> HostAnswerer {
        let registered = Arc::new(RegisteredTables::new());
        install(&registered);
        HostAnswerer::new(own, registered)
    }

    /// The answerer over `own` alone — the lone-daemon shape, holding the
    /// port and answering from its own table only.
    fn answerer(own: BoxRegistry) -> HostAnswerer {
        answerer_over(own, |_| {})
    }

    /// A source on this machine: a host resolver's datagram, from loopback.
    fn on_host() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353)
    }

    /// Sends `datagram` to `answerer` as if from `peer`, and decodes the
    /// reply it produced, if any.
    fn exchange(answerer: &HostAnswerer, peer: SocketAddr, datagram: &[u8]) -> Option<Message> {
        let reply = answerer.respond(peer, datagram)?;
        Some(Message::from_vec(&reply).expect("the answerer's reply decodes"))
    }

    /// One real query-exchange against the answerer listening on `port`:
    /// a datagram from this machine's loopback, the reply decoded. `None`
    /// when nothing answered inside the read window.
    fn query(port: u16, name: &str, rtype: RecordType) -> Option<Message> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("the probe sets its read timeout");
        socket
            .send_to(&encode_query(name, rtype), (Ipv4Addr::LOCALHOST, port))
            .expect("the probe sends on loopback");
        let mut buf = vec![0u8; MAX_DATAGRAM];
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => Some(Message::from_vec(&buf[..len]).expect("the reply decodes")),
            Err(_) => None,
        }
    }

    /// Waits until `probe` — one `query` attempt per try — returns `Some`,
    /// failing the test on `what` when the deadline passes. The holder's
    /// serve loop and a registrant's EOF are the two genuinely asynchronous
    /// turns these tests wait on; everything else is already decided when
    /// the call that made it so returns.
    fn await_answer(probe: impl Fn() -> Option<Message>, what: &str) -> Message {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(reply) = probe() {
                return reply;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: nothing answered within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until `probe` returns a reply that carries an answer record —
    /// not merely any reply — failing the test on `what` past the deadline.
    /// The wait a freshly restarted answerer makes: it answers its nodes'
    /// names with negatives until the nodes reconnect and re-publish, and
    /// the window between is the restart's whole absence.
    fn await_a_record(probe: impl Fn() -> Option<Message>, what: &str) -> Message {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(reply) = probe()
                && !reply.answers.is_empty()
            {
                return reply;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the name never answered a record within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until `probe` — one status read per try — reports a state the
    /// acquisition has decided, failing the test on `what` when the deadline
    /// passes. The acquisition's first pass is asynchronous from the thread
    /// spawn that starts it; every state after it is already decided when
    /// the call that made it so returns.
    fn await_status(probe: impl Fn() -> ZoneAnswererStatus, what: &str) -> ZoneAnswererStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = probe();
            if status != ZoneAnswererStatus::Starting {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the status never left `starting` within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The A record a reply answered with, when it answered with one.
    fn a_answer(reply: &Message) -> Ipv4Addr {
        let [record] = &reply.answers[..] else {
            panic!("an A answer holds exactly one record");
        };
        assert_eq!(
            record.record_type(),
            RecordType::A,
            "the answer is an A record"
        );
        let RData::A(A(address)) = &record.data else {
            panic!("the answer is an A record");
        };
        *address
    }

    /// The zone's SOA, which every negative reply carries in its authority
    /// section (NET-124) — the record a host resolver needs to cache the
    /// negative at all.
    fn soa_of(reply: &Message) -> &Record {
        let [record] = &reply.authorities[..] else {
            panic!("a negative carries exactly the zone's SOA");
        };
        assert_eq!(record.record_type(), RecordType::SOA);
        assert_eq!(
            record.name,
            Name::from_utf8(format!("{}.", zone_answer::ZONE_APEX)).expect("the apex parses"),
            "the SOA is the zone's own"
        );
        record
    }

    /// One published row, the shape a publish line carries: a zone name, the
    /// address its A lookup gets, and a live namespace behind it.
    fn published_row(name: &str, address: Ipv4Addr) -> RegisteredRow {
        RegisteredRow {
            name: format!("{name}.{}", zone_answer::ZONE_APEX),
            address: Some(address),
            live: true,
        }
    }

    /// A registry holding one published box named `name` at the reserved-range
    /// address whose tail is `tail` — [`web_registry`]'s shape, at a name and
    /// address the caller picks, so two daemons in one test hold rows that
    /// cannot meet.
    fn named_box_registry(name: &str, tail: u8) -> (BoxRegistry, Ipv4Addr) {
        let registry = BoxRegistry::new(SUBNET);
        registry.register_node_namespace(7654);
        let web = Ipv4Addr::new(127, 0, 64, tail);
        registry.register(BoxRegistration::new(
            name,
            Ipv4Addr::new(100, 64, 0, tail),
            web,
        ));
        (registry, web)
    }

    /// The installed service's two sockets, bound by the test the way the
    /// service manager binds them for socket activation: the listener at a
    /// free hook port and the channel beside it, both handed to the service
    /// rather than bound by it. Returns the port, the channel's path, and
    /// the two sockets.
    fn service_sockets(dir: &tempfile::TempDir) -> (u16, PathBuf, UdpSocket, UnixListener) {
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
            .expect("the service's listener binds the hook port");
        let channel_listener = UnixListener::bind(&channel).expect("the service's channel binds");
        (port, channel, listener, channel_listener)
    }

    /// Starts the installed service's serving loops ([`serve_service`]) over
    /// sockets the test holds, as the service manager's activation hands them
    /// over, on its own thread. Returns the stop flag that retires it and
    /// the thread's handle — the pair a restart proof needs to end one run
    /// before starting the next.
    fn start_service(
        listener: UdpSocket,
        channel: UnixListener,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let stop = Arc::new(AtomicBool::new(false));
        let service_stop = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("test-zone-service".to_string())
            .spawn(move || {
                // SAFETY: geteuid only reads the process's own uid.
                let expected_uid = unsafe { libc::geteuid() };
                serve_service(listener, channel, expected_uid, service_stop);
            })
            .expect("the service's thread spawns");
        (stop, handle)
    }

    /// Waits until `probe` reads exactly `wanted`, failing the test on `what`
    /// when the deadline passes — the wait for a state an acquisition has
    /// been through before, which its once-only lines make the re-deciding
    /// one every time.
    fn await_status_is(probe: &AnswererStatus, wanted: ZoneAnswererStatus, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if probe.get() == wanted {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the status never read {wanted:?} within 10 s"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Waits until some captured log line satisfies `matches`, failing the
    /// test on `what` when the deadline passes. A thread's logging races the
    /// fact that made its caller return: the connect line is written before
    /// the ack the caller waits for, but the disconnect line is written
    /// after the withdrawal a negative lookup observes — so the assert
    /// waits, not the reader.
    fn await_log(buf: &CaptureWriter, says: impl Fn(&str) -> bool, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if buf.contents().lines().any(&says) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the log never said it within 10 s, got: {}",
                buf.contents()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The holder answers the zone from the host-authored table (NET-138):
    /// a published box's name answers its published loopback address, the
    /// node's own namespace — a row like any other — answers the shared
    /// loopback address, and the host's own name answers the host loopback
    /// (NET-003's host half), the row the answerer itself holds. The same
    /// decision the native daemon's answerer answers over, from a table
    /// this daemon authored on the host.
    #[test]
    fn host_answerer_answers_zone_from_table() {
        let (registry, web) = web_registry();
        let answerer = answerer(registry);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("a held live name answers an A lookup");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.metadata.authoritative,
            "the zone is authoritative for its own names"
        );
        assert_eq!(
            a_answer(&reply),
            web,
            "the name answers the row's published loopback address"
        );

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("minimald.min.internal.", RecordType::A),
        )
        .expect("the node's own namespace is a held row");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the node row answers the shared loopback address"
        );

        // NET-003's host half, held by the answerer itself: the host's own
        // name answers the host loopback, the row the CLI's liveness query
        // reads at the reported port and the session e2e digs — the proof
        // the answerer serves, not a row any table published.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("host.min.internal.", RecordType::A),
        )
        .expect("the host's own name is a held row");
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(
            reply.metadata.authoritative,
            "the host's own name is the zone's to answer"
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the host's own name answers the host loopback"
        );
    }

    /// A record type other than A is NODATA on a held name (NET-124) — never
    /// NXDOMAIN, which negative-caches the name away, and never an address
    /// the type did not ask for — and the NODATA carries the zone's SOA so
    /// the host resolver can cache it.
    #[test]
    fn host_answerer_non_a_is_nodata() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry);

        for rtype in [RecordType::AAAA, RecordType::HTTPS, RecordType::TXT] {
            let reply = exchange(
                &answerer,
                on_host(),
                &encode_query("web.min.internal.", rtype),
            )
            .expect("a held name answers every type");
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "a {rtype:?} lookup on a held name is NODATA, never NXDOMAIN"
            );
            assert!(
                reply.answers.is_empty(),
                "NODATA carries no {rtype:?} record"
            );
            soa_of(&reply);
        }
    }

    /// An in-zone name nothing holds is NXDOMAIN (NET-125), authoritative
    /// and carrying the zone's SOA — a negative the host resolver can cache.
    #[test]
    fn host_answerer_unknown_name_is_nxdomain() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("gone.min.internal.", RecordType::A),
        )
        .expect("an in-zone lookup is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::NXDomain);
        assert!(
            reply.answers.is_empty(),
            "NXDOMAIN carries no answer record"
        );
        assert!(
            reply.metadata.authoritative,
            "the zone's own negative is authoritative"
        );
        soa_of(&reply);

        // A name outside the zone is none of this answerer's to answer:
        // REFUSED, and no SOA of ours certifying someone else's namespace.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("example.com.", RecordType::A),
        )
        .expect("an out-of-zone lookup is answered");
        assert_eq!(reply.metadata.response_code, ResponseCode::Refused);
        assert!(
            reply.authorities.is_empty(),
            "REFUSED cites no SOA over another namespace"
        );
    }

    /// Every record the answerer emits holds a TTL of at most 15 s
    /// (NET-126) — the A answers, and the SOA its negatives carry, minimum
    /// included, which is the negative's own TTL — and a registered row is
    /// re-gated on arrival: an address the host may not be told answers
    /// NODATA (NET-127), not the address, while one it may answers.
    #[test]
    fn host_answerer_short_ttl_and_local_addresses_only() {
        let (registry, _) = web_registry();
        let answerer = answerer(registry.clone());

        // The TTL ceiling, on every record of a positive answer...
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the held name answers");
        for record in reply.answers.iter().chain(&reply.authorities) {
            assert!(
                record.ttl <= zone_answer::ANSWER_TTL_SECS,
                "{} carries a {}s TTL, past the {}s ceiling",
                record.name,
                record.ttl,
                zone_answer::ANSWER_TTL_SECS
            );
        }

        // ...and on every record of a negative, whose SOA's `minimum` is the
        // negative's own TTL (RFC 2308).
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("gone.min.internal.", RecordType::A),
        )
        .expect("an unknown name is answered");
        let soa = soa_of(&reply);
        assert!(
            soa.ttl <= zone_answer::ANSWER_TTL_SECS,
            "the SOA carries a {}s TTL, past the ceiling",
            soa.ttl
        );
        let RData::SOA(rdata) = &soa.data else {
            panic!("the negative carries the zone's SOA");
        };
        assert!(
            rdata.minimum <= zone_answer::ANSWER_TTL_SECS,
            "the SOA's {}s minimum is the negative's TTL, past the ceiling",
            rdata.minimum
        );

        // The registered rows, as a co-resident daemon would file them: one
        // at an address the host may not be told — a box's switch lease,
        // inside the guest's fabric — and one at an address it may.
        let answerer = answerer_over(registry, |registered| {
            registered.install(
                0,
                vec![
                    RegisteredRow {
                        name: "lease.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(100, 64, 0, 10)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "peer.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 10)),
                        live: true,
                    },
                ],
            );
        });

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("lease.min.internal.", RecordType::A),
        )
        .expect("a registered name is held");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "a name held at an address the host may not be told answers NODATA (NET-127)"
        );
        assert!(
            reply.answers.is_empty(),
            "the registered switch lease never reaches the host's zone"
        );
        soa_of(&reply);

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("peer.min.internal.", RecordType::A),
        )
        .expect("a registered name is held");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "a registered row at a host-answerable address answers it"
        );
    }

    /// A row withdrawn from the table takes its name with it: the name is
    /// held by nothing and answers NXDOMAIN (NET-125) — never a name held
    /// forever, and never an address nothing is answering on.
    #[test]
    fn host_answerer_withdrawn_row_is_nxdomain() {
        let (registry, web) = web_registry();
        let answerer = answerer(registry.clone());

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the published box's name is held");
        assert_eq!(a_answer(&reply), web);

        assert!(
            registry.withdraw(Ipv4Addr::new(100, 64, 0, 9)).is_some(),
            "the box was published at its lease"
        );
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the withdrawn name is still an in-zone lookup");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a withdrawn namespace's name is held by nothing"
        );
        assert!(reply.answers.is_empty());
        soa_of(&reply);
    }

    /// A name two sources both hold is the first writer's: this host's own
    /// table is filed first, so a registered row for a name it already holds
    /// is refused and never overwrites it — the answer stays the host's own
    /// row — and the host's own name is refused from any node the same way,
    /// because the answerer holds it before the fold. The registrant's rows
    /// beside the refused ones still answer.
    #[test]
    fn registered_row_does_not_take_a_held_name() {
        let (registry, web) = web_registry();
        let answerer = answerer_over(registry, |registered| {
            registered.install(
                0,
                vec![
                    RegisteredRow {
                        name: "web.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 99)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "host.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 98)),
                        live: true,
                    },
                    RegisteredRow {
                        name: "peer.min.internal".to_string(),
                        address: Some(Ipv4Addr::new(127, 0, 64, 10)),
                        live: true,
                    },
                ],
            );
        });

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("web.min.internal.", RecordType::A),
        )
        .expect("the clashing name is answered by its keeper");
        assert_eq!(
            a_answer(&reply),
            web,
            "the first writer keeps the name; a registrant does not overwrite it"
        );

        // The host's own name is refused from any node through the channel:
        // the answerer holds it itself (NET-003's host half), and no
        // registration — whatever address it carried — moves it.
        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("host.min.internal.", RecordType::A),
        )
        .expect("the host's own name is answered");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "a registration for the host's own name is refused; the host row keeps it"
        );

        let reply = exchange(
            &answerer,
            on_host(),
            &encode_query("peer.min.internal.", RecordType::A),
        )
        .expect("the registration's other row is held");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "the refusal is per name, not per registration"
        );
    }

    /// Two VM host daemons on one machine: the one that holds the answerer
    /// port answers for both, because the other registers its table's zone
    /// rows with it over the channel — its box names with no row refused,
    /// its node row never sent (every VM's node row is the same name, so
    /// the channel would refuse it by construction) — and the
    /// registration's lifetime is its connection, so a daemon that exits
    /// never leaves names answering behind it. Driven through a real UDP
    /// socket and a real channel socket, the way the two daemons run: the
    /// holder through its own acquisition loop, the registrant through the
    /// registration that loop performs.
    #[test]
    fn second_vm_host_daemon_registers_names_with_holder() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // A free loopback port: reserved only to learn a free number, then
        // released for the holder to bind.
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);

        // The holder: its acquisition loop takes the port, holds the channel
        // beside it, and serves the zone from its own table. Its status cell
        // stays observable here — a clone rides into the thread, this one is
        // asserted on below.
        let (holder_registry, holder_web) = web_registry();
        let holder_channel = channel.clone();
        let holder_status = AnswererStatus::starting();
        let holder_status_probe = holder_status.clone();
        std::thread::Builder::new()
            .name("test-zone-holder".to_string())
            .spawn(move || acquire_loop_at(holder_registry, port, holder_channel, holder_status))
            .expect("the holder's thread spawns");

        // The channel is bound before the serve loop starts, so the first
        // answer implies the registration can land.
        let reply = await_answer(
            || query(port, "web.min.internal.", RecordType::A),
            "the holder never answered its own table",
        );
        assert_eq!(
            a_answer(&reply),
            holder_web,
            "the holder answers its own table's name"
        );

        // The second daemon's table, registered the way its own acquisition
        // loop would: one connection, one registration line, one ack — and
        // the rows are held before the ack is written, so they answer by the
        // time this returns. Its table holds the node row every VM host
        // daemon's does (`minimald.min.internal`), the very row the channel
        // must not carry: one name for every VM means the second VM's
        // registration of it would be refused as a clash by construction —
        // the holder answers its own, and a second VM's box names register
        // with no refusal at all.
        let second = BoxRegistry::new(SUBNET);
        second.register_node_namespace(7654);
        let second_web = Ipv4Addr::new(127, 0, 64, 11);
        second.register(BoxRegistration::new(
            "peer",
            Ipv4Addr::new(100, 64, 0, 11),
            second_web,
        ));
        let rows = zone_rows(&second);
        assert_eq!(
            rows.iter().map(|row| row.name.as_str()).collect::<Vec<_>>(),
            ["peer.min.internal"],
            "the registration carries the second VM's box names and never the \
             node row: every VM's node row is the same name, so the channel \
             would only refuse it"
        );
        // Published as the node the second daemon's own acquisition loop
        // below is (`acquire_loop_at`'s node id): the same node coming
        // back, which may re-take its released address inside the reuse
        // quarantine that keeps it from any other node.
        let published = connect_and_publish(&channel, crate::state::vm_name(), rows.clone())
            .expect("the holder accepts the table");
        assert!(
            published.refused.is_empty(),
            "the holder refuses no row of the second table: {:?}",
            published.refused
        );
        assert_eq!(
            published.holder, DAEMON_HOLDER,
            "the interim holder names itself in the hello ack"
        );
        let registration = published.registration;

        // Both VMs' box names are published and no row is refused: every
        // row the second daemon sent answers through the holder at the
        // address it sent — a refused row would answer with its keeper's
        // address or nothing, and the sent set is the whole second table.
        for row in &rows {
            let reply = query(port, &format!("{}.", row.name), RecordType::A)
                .unwrap_or_else(|| panic!("the holder answers {}", row.name));
            assert_eq!(
                reply.metadata.response_code,
                ResponseCode::NoError,
                "{} registered with the holder",
                row.name
            );
            assert_eq!(
                a_answer(&reply),
                row.address.expect("the sent rows hold addresses"),
                "{} answers at the address the second daemon's table holds for it",
                row.name
            );
        }

        let reply = query(port, "peer.min.internal.", RecordType::A).expect("the holder answers");
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NoError,
            "a registered row answers through the holder"
        );
        assert_eq!(
            a_answer(&reply),
            second_web,
            "the second daemon's name answers at its own address, through the first's socket"
        );

        // The node's name the channel did not carry still answers — the
        // holder's own node row, the one the zone answers host-side; inside
        // the guest the second VM's own DNS layer answers its own.
        let reply = query(port, "minimald.min.internal.", RecordType::A)
            .expect("the node's name is answered by the holder's own row");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the node's name answers the holder's own row host-side"
        );

        // The connection is the registration's lifetime: dropped, the
        // holder retires its rows and the name it held answers NXDOMAIN.
        drop(registration);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let answered = query(port, "peer.min.internal.", RecordType::A)
                .expect("an in-zone lookup is still answered");
            if answered.metadata.response_code == ResponseCode::NXDomain {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the retired registration's name still answers: {:?}",
                answered.metadata.response_code
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // The holder's own table is untouched by the registrant's exit.
        let reply = query(port, "web.min.internal.", RecordType::A).expect("the holder answers");
        assert_eq!(
            a_answer(&reply),
            holder_web,
            "the holder's own table still answers after a registrant exited"
        );

        // The holder's own status cell says what its loop decided the
        // machine's answerer is: this daemon, holding the port — the state
        // the control socket serves to the verbs that surface it.
        assert_eq!(
            holder_status_probe.get(),
            ZoneAnswererStatus::Holder { port },
            "the holder reports itself holding the machine's answerer port"
        );

        // And the second daemon's own acquisition loop — the way `run`
        // starts it, not the manual registration above — reports the state
        // it finds the machine in: another VM host daemon holds the port and
        // this table's rows answer through it. Its own registration keeps
        // the second VM's box name answering after the manual one exited,
        // which is the re-registration the loop's change pings ride.
        let second_channel = channel.clone();
        let second_status = AnswererStatus::starting();
        let second_status_probe = second_status.clone();
        std::thread::Builder::new()
            .name("test-zone-registrant".to_string())
            .spawn(move || acquire_loop_at(second, port, second_channel, second_status))
            .expect("the second daemon's thread spawns");
        assert_eq!(
            await_status(
                || second_status_probe.get(),
                "the second daemon never said what the machine's answerer is"
            ),
            ZoneAnswererStatus::Registered { port },
            "a daemon whose port is held by another VM host daemon reports its \
             rows answering through the holder"
        );
        let reply = query(port, "peer.min.internal.", RecordType::A)
            .expect("the second daemon's own registration answers");
        assert_eq!(
            a_answer(&reply),
            second_web,
            "the second daemon's own registration keeps its box name answering"
        );
    }

    /// A port held by a process with no channel — a native minimald, a
    /// foreign process — is the state the acquisition must name rather than
    /// paper over: the status says the port is held with nothing this VM's
    /// names answer through, which is what the CLI surfaces as "this VM's
    /// names are not answered on the host; the proxy remains the surface".
    #[test]
    fn a_port_held_with_no_channel_reports_it() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        // The channel is never bound: nothing answers a registration, the
        // shape of a native daemon's or a foreign process's hold.
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // The machine's answerer port, held by this test and nothing else.
        let held = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the hold binds loopback");
        let port = held.local_addr().expect("the hold names its port").port();
        let (registry, _) = web_registry();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        std::thread::Builder::new()
            .name("test-zone-answerer-no-channel".to_string())
            .spawn(move || acquire_loop_at(registry, port, channel, status))
            .expect("the answerer's thread spawns");
        assert_eq!(
            await_status(
                || probe.get(),
                "the answerer never said why this VM's names answer nothing"
            ),
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "a port held by a process with no channel is named as exactly that"
        );
    }

    /// The first registration still names its holder at info when an earlier
    /// pass warned: a daemon that boots against a port held by a process with
    /// no channel — a native minimald, a foreign squatter — and later finds a
    /// holder must announce that registration, because the diagnostics
    /// contract's one info line is this daemon's or its listener's, and the
    /// e2e's log greps read the info level. The warn's own once-only gate must
    /// not take the registration's with it. Driven without racing the port
    /// between two daemons: the foreign hold stays for the whole test, and it
    /// is the channel that comes up beside it — the holder's half is all a
    /// registration needs, so the daemon's next pass can only register, never
    /// bind.
    #[test]
    fn a_warned_daemon_announces_its_first_registration() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        // The global default, not the thread-local one the crate's other
        // captures use: the acquisition loop logs from its own thread. The
        // default `fmt` filter is info, so the registration's info line is
        // captured while the re-registration's debug line is not — the level
        // split this test is about.
        tracing::subscriber::set_global_default(subscriber)
            .expect("the capturing subscriber installs once per test process");

        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // A foreign hold on the answerer port — a plain socket, no channel
        // answering beside it — kept for the whole test, so every pass the
        // daemon makes finds the port held.
        let held = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the hold binds loopback");
        let port = held.local_addr().expect("the hold names its port").port();
        let (registry, _) = web_registry();
        // A clone shares the table and its change pings — the way a daemon's
        // other threads reach the one registry its answerer holds — so a
        // registration from here is a table change the loop is pinged for,
        // exactly the way a live daemon's own callers wake it.
        let pinger = registry.clone();
        let daemon_channel = channel.clone();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        std::thread::Builder::new()
            .name("test-zone-answerer-late-holder".to_string())
            .spawn(move || acquire_loop_at(registry, port, daemon_channel, status))
            .expect("the answerer's thread spawns");
        assert_eq!(
            await_status(
                || probe.get(),
                "the answerer never said why this VM's names answer nothing"
            ),
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "the first pass against a hold with no channel warns, exactly once"
        );

        // The holder comes up beside the hold: the channel alone, the half a
        // publish needs, while the foreign socket keeps the port.
        hold_channel(
            &channel,
            Arc::new(RegisteredTables::new()),
            None,
            // SAFETY: geteuid only reads the process's own uid.
            unsafe { libc::geteuid() },
        )
        .expect("the holder's channel binds beside the foreign hold");
        // A table change wakes the loop now, at its ping, rather than at the
        // port-recheck cadence — the way a live daemon's box registration
        // reaches the answerer — so the registration this test is about
        // happens inside the wait below, not the next half minute.
        pinger.register(BoxRegistration::new(
            "late",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::new(127, 0, 64, 11),
        ));

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let decided = probe.get();
            if decided == (ZoneAnswererStatus::Registered { port }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon never registered with the holder that came up \
                 beside the hold (status: {decided:?})"
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // The publish that got through is the first, so it is the info
        // line naming the holder — on a line that names this test's channel,
        // so a co-resident test's own publish cannot speak for it — and
        // not the re-publish's debug line a warn-suppressed first publish
        // would have been left with. Awaited, not read once: the loop
        // writes the Registered status before it logs the announcement,
        // so the status alone does not mean the line has landed.
        let channel_text = channel.to_string_lossy().into_owned();
        await_log(
            &buf,
            |line| {
                line.contains("registered this table's zone rows")
                    && line.contains(channel_text.as_str())
            },
            "the first publish after a warn must still name its holder at info",
        );
    }

    // ── the installed service ───────────────────────────────────────────────

    /// The service the privileged step installs answers both nodes' names
    /// from the one answerer the service manager holds: two nodes, each over
    /// its own channel connection, publish one name each, and both answer
    /// through the one listener — beside the answerer's own held rows, the
    /// host's name and the node's shared one, which no node publishes and
    /// the service holds itself.
    #[test]
    fn answerer_service_answers_rows_from_two_nodes() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, _handle) = start_service(listener, channel_listener);

        // Two nodes on one machine: each connects, says its hello, and
        // publishes its rows over its own connection, the way two VM host
        // daemons publish to the installed service.
        let a = connect_and_publish(
            &channel,
            "vm-a",
            vec![published_row("web-a", Ipv4Addr::new(127, 0, 64, 9))],
        )
        .expect("the service accepts the first node");
        assert_eq!(
            a.holder, SERVICE_HOLDER,
            "the installed service names itself in the hello ack"
        );
        let b = connect_and_publish(
            &channel,
            "vm-b",
            vec![published_row("web-b", Ipv4Addr::new(127, 0, 64, 10))],
        )
        .expect("the service accepts the second node");
        assert_eq!(
            b.holder, SERVICE_HOLDER,
            "the installed service names itself in the hello ack"
        );
        assert!(
            a.refused.is_empty() && b.refused.is_empty(),
            "no row of either node is refused: {:?} / {:?}",
            a.refused,
            b.refused
        );

        // Both nodes' names answer through the one listener, each at the
        // address its node published.
        let reply = await_answer(
            || query(port, "web-a.min.internal.", RecordType::A),
            "the service never answered the first node's name",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 9),
            "the first node's name answers at the address it published"
        );
        let reply = await_answer(
            || query(port, "web-b.min.internal.", RecordType::A),
            "the service never answered the second node's name",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "the second node's name answers at the address it published"
        );

        // The answerer's own held rows answer beside the nodes': the host's
        // own name, and the node's shared one, live while any node is
        // connected.
        let reply = await_answer(
            || query(port, "host.min.internal.", RecordType::A),
            "the service never answered the host's own name",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the host's own name is the service's row, at the host loopback"
        );
        let reply = query(port, "minimald.min.internal.", RecordType::A)
            .expect("the node's shared name answers while a node is connected");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the node's shared name is the service's row, live while nodes are"
        );

        stop.store(true, Ordering::SeqCst);
    }

    /// A helper daemon that finds the hook port held by the installed service
    /// publishes its rows over the channel instead of binding and says so at
    /// start: its status reports its rows answering through the holder, its
    /// box name answers at its own address through the service's listener,
    /// and its start line names the manager-held service and the channel it
    /// published over — the one info line the diagnostics contract asks for.
    #[test]
    fn helper_publishes_when_service_holds_the_port() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, _handle) = start_service(listener, channel_listener);

        // The helper daemon: its acquisition loop exactly as `run` starts
        // it, on a thread whose logging this test captures — the thread-local
        // capture the crate's other tests use, because the acquisition logs
        // from its own thread.
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let (registry, web) = web_registry();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        let daemon_channel = channel.clone();
        std::thread::Builder::new()
            .name("test-zone-helper".to_string())
            .spawn(move || {
                let _guard = tracing::subscriber::set_default(subscriber);
                acquire_loop_at(registry, port, daemon_channel, status);
            })
            .expect("the helper's thread spawns");

        // The helper found the channel and published there: its status says
        // its rows answer through the manager-held service, never that it
        // holds the port.
        assert_eq!(
            await_status(
                || probe.get(),
                "the helper never said what the machine's answerer is"
            ),
            ZoneAnswererStatus::ManagerHeld { port },
            "a daemon whose channel the service holds publishes, and reports the service"
        );

        // Its box name answers through the service's listener, at its own
        // published address.
        let reply = await_answer(
            || query(port, "web.min.internal.", RecordType::A),
            "the helper's name never answered through the service",
        );
        assert_eq!(
            a_answer(&reply),
            web,
            "the helper's name answers at its own address, through the service"
        );

        // And its start line says so: publish-or-host, naming the
        // manager-held service and the channel path.
        let channel_text = channel.to_string_lossy().into_owned();
        await_log(
            &buf,
            |line| {
                line.contains("registered this table's zone rows")
                    && line.contains("the manager-held answerer service")
                    && line.contains(&channel_text)
            },
            "the helper's start line never announced its publish",
        );

        stop.store(true, Ordering::SeqCst);
    }

    /// A channel peer whose uid is not the service's own is refused before a
    /// byte of its payload is read: the connection closes without an ack,
    /// its rows are never held, and the refusal is the one warn line that
    /// names the peer's uid — the line a misconfigured unit's service user
    /// answers at a glance.
    #[test]
    fn answerer_channel_refuses_foreign_uid() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        let listener = UnixListener::bind(&channel).expect("the channel binds");
        let registered = Arc::new(RegisteredTables::new());
        let tables = Arc::clone(&registered);
        // The uid this answerer serves: not this test process's own, so this
        // test's connect is a foreign peer's. The xor flips the low bit, so
        // it can never equal the real one.
        //
        // SAFETY: geteuid only reads the process's own uid.
        let expected_uid = unsafe { libc::geteuid() } ^ 1;

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let stop = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("test-zone-gate".to_string())
            .spawn(move || {
                let _guard = tracing::subscriber::set_default(subscriber);
                serve_channel(
                    listener,
                    registered,
                    expected_uid,
                    None,
                    SERVICE_HOLDER,
                    gate,
                );
            })
            .expect("the gate's thread spawns");

        // The foreign peer's publish is refused, and the refusal names its
        // cause: the uid the service serves, and the peer's own.
        let refused = connect_and_publish(
            &channel,
            "vm-a",
            vec![published_row("web-a", Ipv4Addr::new(127, 0, 64, 9))],
        );
        let Err(refused) = refused else {
            panic!("a channel peer with a foreign uid is refused");
        };
        // SAFETY: geteuid only reads the process's own uid.
        let peer_uid = unsafe { libc::geteuid() };
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied, "{refused}");
        let reason = refused.to_string();
        assert!(
            reason.contains(&format!("serves uid {expected_uid}"))
                && reason.contains(&format!("(uid {peer_uid}) is refused"))
                && reason.contains("multi-operator hosts are not supported"),
            "the refusal names both uids and why: {reason}"
        );

        // And nothing it sent was held: the gate refused the peer before a
        // byte of its payload was read.
        assert!(tables.is_empty(), "the refused peer's rows were never held");

        // The refusal is the warn line naming the peer's uid — the gate's
        // own record of who it turned away.
        //
        // SAFETY: geteuid only reads the process's own uid.
        let own_uid = unsafe { libc::geteuid() };
        await_log(
            &buf,
            |line| {
                line.contains("refused an answerer channel connection from a foreign uid")
                    && line.contains(&format!("peer_uid={own_uid}"))
                    && line.contains(&format!("service_uid={expected_uid}"))
            },
            "the gate never warned about the foreign peer",
        );

        stop.store(true, Ordering::SeqCst);
        handle
            .join()
            .expect("the gate's thread ends when its stop is set");
    }

    #[test]
    fn foreign_refusals_past_the_cap_close_bare() {
        // Every refusal slot taken: the next foreign peer is closed without
        // a thread or a reply, and the count is left as it was.
        FOREIGN_REFUSALS_IN_FLIGHT.store(FOREIGN_REFUSALS_MAX, Ordering::SeqCst);
        let (served, mut peer) = UnixStream::pair().expect("a socket pair");
        refuse_foreign_peer(served, 1001, 1000);
        assert_eq!(
            FOREIGN_REFUSALS_IN_FLIGHT.load(Ordering::SeqCst),
            FOREIGN_REFUSALS_MAX,
            "a refusal past the cap takes no slot"
        );
        let _ = peer.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = String::new();
        let read = std::io::Read::read_to_string(&mut peer, &mut buf).expect("the close is read");
        assert_eq!(read, 0, "past the cap the peer is closed bare: {buf:?}");
        FOREIGN_REFUSALS_IN_FLIGHT.store(0, Ordering::SeqCst);
    }
    /// The installed service holds a node's rows only while the node's
    /// connection is up (NET-124's context, the answerer's half): the
    /// connection's end is the whole withdrawal — the name answers nothing,
    /// and a restart of the service holds nothing until the nodes reconnect
    /// — and the service's own log names the node's connection, its
    /// publish, and the rows that went with its disconnection.
    #[test]
    fn answerer_service_forgets_rows_of_a_gone_node() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);

        // The service's own log captured, so the connect, publish, and
        // disconnect lines the observability contract asks for are the
        // asserts this test reads. The global default, not a thread-local
        // guard: the per-node lines are logged from the channel's
        // per-connection threads, which no thread-local capture reaches.
        // One per test process — nextest runs each test as its own process,
        // the assumption the crate's other global capture makes.
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("the capturing subscriber installs once per test process");
        let (stop, handle) = start_service(listener, channel_listener);

        let published = connect_and_publish(
            &channel,
            "vm-a",
            vec![published_row("gone", Ipv4Addr::new(127, 0, 64, 9))],
        )
        .expect("the service accepts the node");
        assert!(
            published.refused.is_empty(),
            "the node's row is held: {:?}",
            published.refused
        );
        let reply = await_answer(
            || query(port, "gone.min.internal.", RecordType::A),
            "the service never answered the node's name",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 9),
            "the node's name answers while its connection is up"
        );

        // The service's log named the node's connection and its publish —
        // the one info line per connection and per publish.
        await_log(
            &buf,
            |line| {
                line.contains("a node connected to the zone answerer channel")
                    && line.contains("vm-a")
            },
            "the service never logged the node's connection",
        );
        await_log(
            &buf,
            |line| {
                line.contains("a node published its zone rows to the answerer")
                    && line.contains("gone.min.internal")
            },
            "the service never logged the node's publish",
        );

        // The connection's end is the whole withdrawal: the name answers
        // NXDOMAIN, the negative the zone certifies with its SOA.
        drop(published);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let answered = query(port, "gone.min.internal.", RecordType::A)
                .expect("an in-zone lookup is still answered");
            if answered.metadata.response_code == ResponseCode::NXDomain {
                soa_of(&answered);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the gone node's name still answers: {:?}",
                answered.metadata.response_code
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // And the service's log named the disconnection and the rows that
        // went with it.
        await_log(
            &buf,
            |line| {
                line.contains("a node disconnected from the zone answerer channel")
                    && line.contains("gone.min.internal")
            },
            "the service never logged the node's withdrawal",
        );

        // The node's shared name — live while any node is connected, held by
        // the service itself — answers nothing once none is.
        let reply = query(port, "minimald.min.internal.", RecordType::A)
            .expect("the service still answers the node's name with a negative");
        assert!(
            reply.answers.is_empty(),
            "the node's shared name answers nothing once no node is connected"
        );

        stop.store(true, Ordering::SeqCst);
        let _ = handle;
    }

    /// A name belongs to the node that first published it: a second node's
    /// publish of a held name is refused and reported — the ack names the
    /// row and the reason names the node that keeps it — while the rest of
    /// the second node's publish still holds, exactly the per-row refusal
    /// the channel's rules promise.
    #[test]
    fn second_node_publishing_a_held_name_is_refused() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, _handle) = start_service(listener, channel_listener);

        let shared = Ipv4Addr::new(127, 0, 64, 9);
        let a = connect_and_publish(
            &channel,
            "vm-a",
            vec![
                published_row("shared", shared),
                published_row("only-a", Ipv4Addr::new(127, 0, 64, 10)),
            ],
        )
        .expect("the service accepts the first node");
        assert!(
            a.refused.is_empty(),
            "the first publish holds every row: {:?}",
            a.refused
        );

        // The second node publishes the held name beside one of its own: the
        // connection is kept — a refusal is a row's, not a node's — and the
        // ack names the refused row and the node that keeps it.
        let b = connect_and_publish(
            &channel,
            "vm-b",
            vec![
                published_row("shared", Ipv4Addr::new(127, 0, 64, 11)),
                published_row("only-b", Ipv4Addr::new(127, 0, 64, 12)),
            ],
        )
        .expect("the service keeps the second node's connection open");
        let [refused] = &b.refused[..] else {
            panic!("the held name is refused, exactly once: {:?}", b.refused);
        };
        assert_eq!(
            refused.name, "shared.min.internal",
            "the refused row is the held name"
        );
        assert!(
            refused.reason.contains("another node (vm-a)")
                && refused.reason.contains("first publisher"),
            "the refusal names the node that keeps the name: {}",
            refused.reason
        );

        // The first publisher keeps the name, at its own address…
        let reply = await_answer(
            || query(port, "shared.min.internal.", RecordType::A),
            "the held name never answered",
        );
        assert_eq!(
            a_answer(&reply),
            shared,
            "the first publisher keeps the name at its own address"
        );
        // …the refused node's other row still answers — the refusal is per
        // row, so the second node's table holds its own names…
        let reply = await_answer(
            || query(port, "only-b.min.internal.", RecordType::A),
            "the second node's other name never answered",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 12),
            "the second node's other row holds, refused row or no"
        );
        // …and the first node's own rows are untouched.
        let reply = query(port, "only-a.min.internal.", RecordType::A)
            .expect("the first node's other name answers");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 10),
            "the first node's other row is untouched by the refused publish"
        );

        stop.store(true, Ordering::SeqCst);
    }

    /// Every published A address must fall inside the answer rule — the
    /// reserved local range or the host loopback — and is refused otherwise
    /// (NET-127, the publish-time half): a row at a box's switch lease, an
    /// address inside the guest's fabric the host cannot reach, never
    /// reaches the zone, while the same publish's rows at host-answerable
    /// addresses hold.
    #[test]
    fn answerer_refuses_an_address_outside_the_answer_rule() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, _handle) = start_service(listener, channel_listener);

        let published = connect_and_publish(
            &channel,
            "vm-a",
            vec![
                published_row("far", Ipv4Addr::new(100, 64, 0, 9)),
                published_row("near", Ipv4Addr::new(127, 0, 64, 9)),
                published_row("loop", Ipv4Addr::LOCALHOST),
            ],
        )
        .expect("the service keeps the node's connection: the refusal is a row's");
        let [refused] = &published.refused[..] else {
            panic!(
                "the out-of-range row is refused, exactly once: {:?}",
                published.refused
            );
        };
        assert_eq!(
            refused.name, "far.min.internal",
            "the refused row is the out-of-range one"
        );
        assert!(
            refused.reason.contains("outside the host-answerable range"),
            "the refusal names the range rule: {}",
            refused.reason
        );

        // The rows the rule admits answer: one at the reserved local range
        // the address plan publishes boxes at, one at the host loopback.
        let reply = await_answer(
            || query(port, "near.min.internal.", RecordType::A),
            "the reserved-range name never answered",
        );
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::new(127, 0, 64, 9),
            "the reserved-range row holds"
        );
        let reply = query(port, "loop.min.internal.", RecordType::A)
            .expect("the host-loopback name answers");
        assert_eq!(
            a_answer(&reply),
            Ipv4Addr::LOCALHOST,
            "the host-loopback row holds"
        );

        // The refused row never reached the zone: its name answers the
        // negative, NXDOMAIN with the zone's SOA (NET-124).
        let reply = await_answer(
            || query(port, "far.min.internal.", RecordType::A),
            "the refused name never answered its negative",
        );
        assert_eq!(
            reply.metadata.response_code,
            ResponseCode::NXDomain,
            "a name whose only row was refused answers NXDOMAIN"
        );
        soa_of(&reply);

        stop.store(true, Ordering::SeqCst);
    }

    /// A service restart is a short absence window and never a session
    /// restart: two daemons hold their published rows through one, because
    /// the channel connection each holds is reconnected and re-published on
    /// loss, unprompted — and the service manager's restart hands the same
    /// listening sockets to the new run, the way systemd re-activates a
    /// socket-activated service. A restart holds nothing until the nodes
    /// reconnect and re-publish; both names answer again with no session
    /// action.
    #[test]
    fn nodes_republish_after_a_service_restart() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);
        // The manager's sockets: bound here, handed to each run of the
        // service, and never closed by a restart — the socket-activation
        // shape, which is what makes the restart a window and not a rebind.
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
            .expect("the service's listener binds the hook port");
        let channel_listener = UnixListener::bind(&channel).expect("the service's channel binds");

        // The first run of the service, over the manager's sockets, before
        // the daemons that publish to it.
        let (stop, handle) = start_service(
            listener
                .try_clone()
                .expect("the manager re-hands its listener"),
            channel_listener
                .try_clone()
                .expect("the manager re-hands its channel"),
        );

        // Two daemons with rows that cannot meet, their acquisition loops
        // exactly as `run` starts them.
        let (a_registry, a_web) = named_box_registry("web-a", 9);
        let (b_registry, b_web) = named_box_registry("web-b", 10);
        let a_status = AnswererStatus::starting();
        let a_probe = a_status.clone();
        let a_channel = channel.clone();
        std::thread::Builder::new()
            .name("test-zone-daemon-a".to_string())
            .spawn(move || acquire_loop_at(a_registry, port, a_channel, a_status))
            .expect("the first daemon's thread spawns");
        let b_status = AnswererStatus::starting();
        let b_probe = b_status.clone();
        let b_channel = channel.clone();
        std::thread::Builder::new()
            .name("test-zone-daemon-b".to_string())
            .spawn(move || acquire_loop_at(b_registry, port, b_channel, b_status))
            .expect("the second daemon's thread spawns");

        // Both daemons published: their statuses say so, and both names
        // answer through the service.
        assert_eq!(
            await_status(
                || a_probe.get(),
                "the first daemon never said what the machine's answerer is"
            ),
            ZoneAnswererStatus::ManagerHeld { port },
            "the first daemon published to the service"
        );
        assert_eq!(
            await_status(
                || b_probe.get(),
                "the second daemon never said what the machine's answerer is"
            ),
            ZoneAnswererStatus::ManagerHeld { port },
            "the second daemon published to the service"
        );
        let reply = await_answer(
            || query(port, "web-a.min.internal.", RecordType::A),
            "the first daemon's name never answered",
        );
        assert_eq!(
            a_answer(&reply),
            a_web,
            "the first daemon's name answers at its own address"
        );
        let reply = query(port, "web-b.min.internal.", RecordType::A)
            .expect("the second daemon's name answers");
        assert_eq!(
            a_answer(&reply),
            b_web,
            "the second daemon's name answers at its own address"
        );

        // ── the restart: the manager stops the service, then starts it
        // again over the same listening sockets. The new run accepts on the
        // same sockets, so the old run's channel thread must be gone before
        // it does: a stop is honoured within one poll slice, and three of
        // them is far past the whole loop.
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("the service's first run ends");
        std::thread::sleep(CONNECTION_POLL * 3);
        let (stop, handle) = start_service(
            listener
                .try_clone()
                .expect("the manager re-hands its listener"),
            channel_listener
                .try_clone()
                .expect("the manager re-hands its channel"),
        );

        // Both names answer again — with no session action, no daemon
        // restart, nothing but the daemons' own reconnect-and-republish on
        // the connection loss the restart is.
        let reply = await_a_record(
            || query(port, "web-a.min.internal.", RecordType::A),
            "the first daemon never re-published after the restart",
        );
        assert_eq!(
            a_answer(&reply),
            a_web,
            "the first daemon's name answers again, at its own address"
        );
        let reply = await_a_record(
            || query(port, "web-b.min.internal.", RecordType::A),
            "the second daemon never re-published after the restart",
        );
        assert_eq!(
            a_answer(&reply),
            b_web,
            "the second daemon's name answers again, at its own address"
        );
        // The negative the restarted service serves is no longer-lived than
        // the positive: the SOA minimum a host resolver caches a negative by
        // (RFC 2308) is at most the A answer's TTL, so a lookup that landed
        // in the restart's absence window cannot outlive the window in the
        // host resolver's negative cache.
        let positive = reply
            .answers
            .first()
            .expect("the re-published name answers a record")
            .ttl;
        let negative = query(port, "nobody-here.min.internal.", RecordType::A)
            .expect("an unknown name is answered after the restart");
        assert_eq!(negative.metadata.response_code, ResponseCode::NXDomain);
        let soa = soa_of(&negative);
        let RData::SOA(rdata) = &soa.data else {
            panic!("the negative carries the zone's SOA");
        };
        assert!(
            rdata.minimum <= positive && soa.ttl <= positive,
            "the negative TTL (SOA minimum {} s, record {} s) must not outlive the \
             positive TTL ({positive} s)",
            rdata.minimum,
            soa.ttl
        );
        // And both daemons' statuses are back to the published state — the
        // episode the restart opened is over.
        await_status_is(
            &a_probe,
            ZoneAnswererStatus::ManagerHeld { port },
            "the first daemon never re-published its status",
        );
        await_status_is(
            &b_probe,
            ZoneAnswererStatus::ManagerHeld { port },
            "the second daemon never re-published its status",
        );

        stop.store(true, Ordering::SeqCst);
        let _ = handle;
    }

    /// A channel socket path that is present but refuses is an error
    /// surfaced at session start, never a reason to host: the daemon that
    /// finds one does not take the hook port even with it free — a connect
    /// starts a socket-activated service, so an answerer that is installed
    /// and healthy always answers a connect, and one that does not is
    /// broken, not absent. The status names the port held with nothing
    /// answering this table's names, the warn says why, and nothing binds.
    #[test]
    fn present_channel_that_refuses_is_an_error_not_a_host() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // A channel that is alive and says no: it accepts the connect — the
        // connect is what starts a socket-activated answerer — and answers
        // the hello with a refusal, the wire a version-mismatched or
        // misconfigured service answers with. The machine has an answerer
        // whose answer this table is not in; hosting a second one over it
        // would fork the machine's one answerer.
        let listener = UnixListener::bind(&channel).expect("the refusing channel binds");
        let stop = Arc::new(AtomicBool::new(false));
        let gate = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("test-zone-refusing-channel".to_string())
            .spawn(move || {
                for stream in listener.incoming() {
                    if gate.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    // Read the hello, refuse it: one line in, one refusal
                    // line out, whatever this daemon keeps sending.
                    let mut line = String::new();
                    let mut byte = [0u8; 1];
                    while !line.contains('\n') {
                        match stream.read(&mut byte) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => line.push(byte[0] as char),
                        }
                    }
                    let _ = stream.write_all(
                        b"{\"ok\":false,\"error\":\"this channel refuses every hello\"}\n",
                    );
                }
            })
            .expect("the refusing service's thread spawns");

        // The hook port is free — hosting it would be possible, and must not
        // happen.
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let (registry, _) = web_registry();
        let status = AnswererStatus::starting();
        let status_probe = status.clone();
        std::thread::Builder::new()
            .name("test-zone-refused-channel".to_string())
            .spawn(move || {
                let _guard = tracing::subscriber::set_default(subscriber);
                acquire_loop_at(registry, port, channel, status);
            })
            .expect("the daemon's thread spawns");

        // The status surfaces the error: the port is named as held with
        // nothing this table's names answer through — the state the CLI
        // shows as "this VM's names are not answered on the host".
        assert_eq!(
            await_status(
                || status_probe.get(),
                "the daemon never said why this VM's names answer nothing"
            ),
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "a present channel that refuses is surfaced as an error"
        );

        // The daemon never took the free port: nothing answers there.
        assert!(
            query(port, "host.min.internal.", RecordType::A).is_none(),
            "the daemon must not host the answerer over a present channel, \
             even with the hook port free"
        );

        // And the warn says why, at the first pass of the error episode.
        await_log(
            &buf,
            |line| line.contains("did not answer"),
            "the daemon never warned why it published nothing",
        );
        stop.store(true, Ordering::Relaxed);
        // The refusing service gives up its socket so the temp dir can go.
        let _ = std::fs::remove_file(dir.path().join(CHANNEL_SOCK_FILE));
    }

    /// The crash shape an interim holder leaves: its channel socket file
    /// stays on the disk with nothing listening behind it, and the next
    /// daemon to start must not read the leftover as a machine that has an
    /// answerer. A service manager's socket never refuses a connect — the
    /// manager accepts it and starts the answerer — so a refused connect
    /// names the leftover as nobody's, and the daemon takes the machine's
    /// answerer, replacing the dead file with its own live channel. This is
    /// the fresh-daemon half of the KVM lane's `min ls` after a stopped
    /// session: the line must name the VM host daemon again.
    #[test]
    fn a_dead_holders_socket_file_does_not_wedge_the_machine() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channel socket");
        let channel = dir.path().join(CHANNEL_SOCK_FILE);
        // The corpse: a channel socket file present, its holder gone.
        let listener = UnixListener::bind(&channel).expect("the dead channel binds");
        drop(listener);

        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        let port = probe.local_addr().expect("the probe names its port").port();
        drop(probe);

        let (registry, web) = web_registry();
        let status = AnswererStatus::starting();
        let status_probe = status.clone();
        let channel_probe = channel.clone();
        std::thread::Builder::new()
            .name("test-zone-corpse-channel".to_string())
            .spawn(move || acquire_loop_at(registry, port, channel_probe, status))
            .expect("the daemon's thread spawns");

        // The daemon hosts, not errors: the machine's answerer is nobody's,
        // so this one takes it — the recorded interim, same as a machine
        // whose channel never existed.
        assert_eq!(
            await_status(
                || status_probe.get(),
                "the daemon never took the machine's answerer over the leftover"
            ),
            ZoneAnswererStatus::Holder { port },
            "a dead holder's socket file is not a channel: the next daemon hosts"
        );

        // And the box zone answers here, from this daemon's own table.
        let reply = query(port, "web.min.internal.", RecordType::A)
            .expect("the recovering daemon answers the zone");
        assert_eq!(
            a_answer(&reply),
            web,
            "the box zone answers from the daemon that took over the leftover"
        );

        // The leftover is replaced by a live channel: a connect to the path
        // now reaches the holder's own gate, so the next daemon publishes
        // instead of hosting.
        // Bound right after the holder's status flips, so polled briefly.
        let deadline = Instant::now() + Duration::from_secs(5);
        while UnixStream::connect(&channel).is_err() {
            assert!(
                Instant::now() < deadline,
                "the holder re-bound the channel over the dead file"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The channel paths a test acquisition decides over, all in `dir`: the
    /// service's global channel, the interim's, and the install marker —
    /// none of them created here.
    fn test_paths(dir: &tempfile::TempDir, window: Duration) -> ChannelPaths {
        private_test_dir(&dir.path().join(CHANNEL_SOCK_FILE));
        ChannelPaths {
            global: dir.path().join("global.sock"),
            interim: dir.path().join(CHANNEL_SOCK_FILE),
            marker: dir.path().join("installed.marker"),
            release_window: window,
        }
    }

    /// A free loopback port, reserved only to learn its number.
    fn free_port() -> u16 {
        let probe = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("the probe binds loopback");
        probe.local_addr().expect("the probe names its port").port()
    }

    /// Starts one daemon's acquisition over `paths` on its own thread.
    fn start_daemon(
        registry: BoxRegistry,
        port: u16,
        paths: ChannelPaths,
        node: &str,
    ) -> AnswererStatus {
        let status = AnswererStatus::starting();
        let probe = status.clone();
        let node = node.to_string();
        std::thread::Builder::new()
            .name("test-zone-daemon".to_string())
            .spawn(move || acquire(registry, port, &paths, &node, &status))
            .expect("the daemon's thread spawns");
        probe
    }

    /// With no answerer service installed (no marker), no channel and the
    /// hook port free, a node hosts the interim and hands its own boxes
    /// their addresses: nothing about the host's resolver (no
    /// systemd-resolved, no resolver hook at all) enters the acquisition,
    /// so own-address box registration never depends on it.
    #[test]
    fn interim_host_allocates_without_a_service_or_a_resolver_hook() {
        let dir = tempfile::TempDir::new().expect("a temp dir");
        let port = free_port();
        let status = start_daemon(
            web_registry().0,
            port,
            test_paths(&dir, RELEASE_WINDOW),
            "node-without-service",
        );
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the node never hosted the interim",
        );
        let first = status
            .allocate("box-a")
            .expect("the interim hands out an address");
        let second = status.allocate("box-b").expect("and another");
        assert!(
            in_box_range(first) && in_box_range(second) && first != second,
            "the interim allocates distinct box addresses: {first}, {second}"
        );
    }

    /// A released box address is quarantined for the positive answer TTL
    /// (design §7.1): a host resolver may still answer the old name with it
    /// that long, so no other box is handed it before then — the lowest
    /// address whose quarantine has passed goes first, an older free
    /// address is preferred, and with nothing else free the allocation
    /// fails naming the wait rather than handing the address out early. A
    /// claim by another box is refused the same way; the box that held it
    /// may take it back. Driven on an injected clock, no sleeps.
    #[test]
    fn released_address_is_not_reused_within_the_answer_ttl() {
        let ttl = Duration::from_secs(u64::from(zone_answer::ANSWER_TTL_SECS));
        assert_eq!(
            REUSE_QUARANTINE, ttl,
            "the quarantine is the served answer TTL"
        );
        let t0 = Instant::now();
        let mut book = AddressBook::default();
        let a = book.allocate_at("node-a", "a", t0).expect(".2");
        let b = book.allocate_at("node-a", "b", t0).expect(".3");
        assert_eq!(
            (a, b),
            (Ipv4Addr::new(127, 0, 64, 2), Ipv4Addr::new(127, 0, 64, 3))
        );

        // .2 is released; inside the TTL another box is handed .4, not .2.
        assert_eq!(book.release_at("node-a", "a", t0), Some(a));
        let inside = (t0 + ttl).checked_sub(Duration::from_millis(1)).unwrap();
        let c = book
            .allocate_at("node-b", "c", inside)
            .expect("a fresh address");
        assert_eq!(
            c,
            Ipv4Addr::new(127, 0, 64, 4),
            "the quarantined .2 is skipped"
        );
        assert!(
            book.claim_at("node-b", "intruder", a, inside).is_err(),
            "another box's claim of a quarantined address is refused"
        );

        // An older free address is preferred: .4 released later than .2,
        // and once .2's quarantine has passed it goes first.
        assert_eq!(
            book.release_at("node-b", "c", t0 + Duration::from_secs(5)),
            Some(c)
        );
        let after_a = t0 + ttl;
        assert_eq!(
            book.allocate_at("node-b", "d", after_a),
            Ok(a),
            "the lowest address whose quarantine has passed"
        );
        let e = book
            .allocate_at("node-b", "e", after_a)
            .expect("the next fresh one");
        assert_eq!(
            e,
            Ipv4Addr::new(127, 0, 64, 5),
            "the still-quarantined .4 is skipped"
        );

        // The box that held a quarantined address may take it back.
        assert_eq!(book.release_at("node-a", "b", after_a), Some(b));
        assert_eq!(
            book.allocate_at("node-a", "b", after_a),
            Ok(b),
            "a box re-registered gets its own address back"
        );

        // With every other address held, the allocation fails naming the
        // wait — it never hands the quarantined address out early.
        let mut full = AddressBook::default();
        let (first, last) = switch::box_loopback_interior();
        for (index, _) in (u32::from(first)..=u32::from(last)).enumerate() {
            full.allocate_at("node-a", &format!("box{index}"), t0)
                .expect("the range holds it");
        }
        let freed = full.release_at("node-a", "box0", t0).expect("box0 held .2");
        let refused = full
            .allocate_at("node-b", "late", t0 + Duration::from_secs(10))
            .expect_err("nothing is free outside the quarantine");
        assert!(
            refused.contains("released less than 15 s ago") && refused.contains("frees in 5 s"),
            "the refusal names the quarantine and the wait: {refused}"
        );
        assert_eq!(
            full.allocate_at("node-b", "late", t0 + ttl),
            Ok(freed),
            "once the TTL has passed the address is handed out"
        );
    }

    /// Box addresses are host-global (design §7.1): the answerer hands
    /// each node's boxes the lowest free address of `.2`-`.254`, so two
    /// nodes under separate state dirs never share one, even for boxes of
    /// the same name; a publish of an address another node holds, or of an
    /// address outside the box range, is refused; and an address released
    /// by its box or its departed node is not handed to another box inside
    /// the answer TTL.
    #[test]
    fn two_nodes_never_share_a_box_address() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the service");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, _handle) = start_service(listener, channel_listener);
        let paths = || ChannelPaths {
            global: dir.path().join("no-global.sock"),
            interim: channel.clone(),
            marker: dir.path().join("no-marker"),
            release_window: RELEASE_WINDOW,
        };
        let empty_registry = || {
            let registry = BoxRegistry::new(SUBNET);
            registry.register_node_namespace(7654);
            registry
        };
        let node_a = node_id_for(&dir.path().join("state-a"), "default");
        let node_b = node_id_for(&dir.path().join("state-b"), "default");
        let a = start_daemon(empty_registry(), port, paths(), &node_a);
        let b = start_daemon(empty_registry(), port, paths(), &node_b);
        await_status_is(
            &a,
            ZoneAnswererStatus::ManagerHeld { port },
            "node a never reached the service",
        );
        await_status_is(
            &b,
            ZoneAnswererStatus::ManagerHeld { port },
            "node b never reached the service",
        );

        // Two nodes' boxes of the same name: distinct addresses, both in
        // the box range, the lowest first.
        let a_web = a
            .allocate("web")
            .expect("node a's box is handed an address");
        let b_web = b
            .allocate("web")
            .expect("node b's box is handed an address");
        assert_eq!(
            a_web,
            Ipv4Addr::new(127, 0, 64, 2),
            "the lowest box address first"
        );
        assert_eq!(
            b_web,
            Ipv4Addr::new(127, 0, 64, 3),
            "the next free one for node b"
        );
        assert_ne!(a_web, b_web, "two nodes never share a box address");
        assert_eq!(
            a.allocate("web"),
            Ok(a_web),
            "asking again for the same box hands back the same address"
        );
        let a_db = a.allocate("db").expect("node a's second box");
        assert!(
            a_db != a_web && a_db != b_web && in_box_range(a_db),
            "a third box takes a third address: {a_db}"
        );

        // A publish of another node's address is refused, and so is every
        // address of the reserved range outside the box range.
        let node_c = node_id_for(&dir.path().join("state-c"), "default");
        let intruder = connect_and_publish(
            &channel,
            &node_c,
            vec![
                published_row("intruder", a_web),
                published_row("network", Ipv4Addr::new(127, 0, 64, 0)),
                published_row("one", Ipv4Addr::new(127, 0, 64, 1)),
                published_row("broadcast", Ipv4Addr::new(127, 0, 64, 255)),
            ],
        )
        .expect("node c's connection is served");
        assert_eq!(
            intruder.refused.len(),
            4,
            "every row is refused: {:?}",
            intruder.refused
        );
        assert!(
            intruder.refused[0].reason.contains("holds the address"),
            "the held address is refused naming its holder: {}",
            intruder.refused[0].reason
        );
        for refused in &intruder.refused[1..] {
            assert!(
                refused.reason.contains("outside the box address range"),
                "a reserved-range address outside .2-.254 is refused: {}",
                refused.reason
            );
        }
        drop(intruder);

        // One node's two boxes carrying one free address in one publish:
        // the first claims it, the second is refused rather than taking
        // over the first's holder record.
        let shared = Ipv4Addr::new(127, 0, 64, 200);
        let twins = connect_and_publish(
            &channel,
            &node_c,
            vec![
                published_row("left", shared),
                published_row("right", shared),
            ],
        )
        .expect("node c's second connection is served");
        assert_eq!(
            twins.refused.len(),
            1,
            "only the second box is refused: {:?}",
            twins.refused
        );
        assert!(
            twins.refused[0].name.starts_with("right"),
            "the second box is the one refused: {}",
            twins.refused[0].name
        );
        assert!(
            twins.refused[0]
                .reason
                .contains("already carries the address"),
            "the shared address is refused naming the first box: {}",
            twins.refused[0].reason
        );
        drop(twins);

        // A released box's address leaves the holder's book, but not into
        // another box's hands inside the answer TTL: the next box is handed
        // a fresh address (the reuse after the TTL is
        // `released_address_is_not_reused_within_the_answer_ttl`'s).
        a.release_address("db");
        let deadline = Instant::now() + Duration::from_secs(10);
        let b_api = loop {
            let address = b.allocate("api").expect("node b's next box");
            if address != a_db || Instant::now() > deadline {
                break address;
            }
            b.release_address("api");
            std::thread::sleep(CONNECTION_POLL);
        };
        assert!(
            b_api != a_db && b_api != a_web && b_api != b_web && in_box_range(b_api),
            "a released address is not handed to another box within the answer TTL: {b_api}"
        );

        // A node that leaves releases its addresses — into the same
        // quarantine, so the node that arrives next is handed another one.
        let node_d = node_id_for(&dir.path().join("state-d"), "default");
        let mut leaving = connect_and_publish(&channel, &node_d, Vec::new())
            .expect("node d connects")
            .registration;
        let d_box = leaving
            .allocate("box")
            .expect("the channel serves node d")
            .expect("node d's box is handed an address");
        drop(leaving);
        std::thread::sleep(CONNECTION_POLL * 3);
        let node_e = node_id_for(&dir.path().join("state-e"), "default");
        let mut arriving = connect_and_publish(&channel, &node_e, Vec::new())
            .expect("node e connects")
            .registration;
        let e_box = arriving
            .allocate("box")
            .expect("the channel serves node e")
            .expect("node e's box is handed an address");
        assert_ne!(
            e_box, d_box,
            "a departed node's address is not handed on within the answer TTL"
        );
        drop(arriving);

        stop.store(true, Ordering::SeqCst);
    }

    /// The machine-global channel is one path per host and the interim's
    /// channel one path per operator: nothing of a node's state dir or VM
    /// name enters either, so every state dir of one operator meets on the
    /// same interim (and, once installed, on the one global channel), while
    /// the node id stays per state dir.
    #[test]
    fn channel_path_is_machine_global_across_state_dirs() {
        assert_eq!(
            channel_sock_from(None),
            PathBuf::from(GLOBAL_CHANNEL_SOCK),
            "with no test override the channel is the machine-global path"
        );
        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(GLOBAL_CHANNEL_SOCK, "/run/minimal/answerer.sock");
            assert_eq!(
                interim_channel_sock_from(Some(PathBuf::from("/run/user/1000")), None, 1000),
                PathBuf::from("/run/user/1000/minimal/answerer-interim.sock"),
                "the interim channel is the operator's, in XDG_RUNTIME_DIR"
            );
            assert_eq!(
                interim_channel_sock_from(None, None, 1000),
                PathBuf::from("/tmp/minimal-1000/answerer-interim.sock"),
                "without XDG_RUNTIME_DIR it falls back to a per-uid /tmp dir"
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                GLOBAL_CHANNEL_SOCK,
                "/Library/Application Support/minimal/run/answerer.sock"
            );
            assert_eq!(
                interim_channel_sock_from(None, Some(PathBuf::from("/Users/op")), 501),
                PathBuf::from(
                    "/Users/op/Library/Application Support/minimal/run/answerer-interim.sock"
                ),
                "the interim channel is the operator's, under their home"
            );
        }
        assert_ne!(
            interim_channel_sock(),
            PathBuf::from(GLOBAL_CHANNEL_SOCK),
            "the interim is never the global channel"
        );
        let a = tempfile::TempDir::new().expect("a first state dir");
        let b = tempfile::TempDir::new().expect("a second state dir");
        assert_ne!(
            node_id_for(a.path(), "default"),
            node_id_for(b.path(), "default"),
            "two state dirs' default VMs are two nodes"
        );
    }

    /// The interim's per-user dir is refused when another uid could have
    /// placed it: a dir open to group or other is not bound in, and an
    /// absent one is created 0700.
    #[test]
    fn interim_dir_is_created_private_and_a_wide_one_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::TempDir::new().expect("a temp dir");
        let fresh = dir.path().join("fresh").join(INTERIM_CHANNEL_SOCK_FILE);
        prepare_interim_dir(&fresh).expect("an absent dir is created");
        let mode = std::fs::metadata(fresh.parent().expect("a parent"))
            .expect("the dir exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "created 0700");
        let wide = dir.path().join("wide");
        std::fs::create_dir(&wide).expect("a wide dir");
        std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o777)).expect("made wide");
        let refused = prepare_interim_dir(&wide.join(INTERIM_CHANNEL_SOCK_FILE))
            .expect_err("a dir open to others is refused");
        assert!(
            refused.to_string().contains("refusing to bind"),
            "{refused}"
        );
    }

    /// Two state dirs of one operator, no service installed: the first node
    /// hosts the interim on the hook port and binds the per-user interim
    /// channel; the second, from its own state dir, finds that channel and
    /// publishes into it instead of colliding on the port — its name
    /// answers through the first node's interim, and its status says it is
    /// registered with another node's interim.
    #[test]
    fn second_state_dir_publishes_into_the_first_ones_interim() {
        let dir = tempfile::TempDir::new().expect("a temp dir");
        let port = free_port();
        // One operator's paths, shared by both state dirs: the interim is
        // per user, not per state dir.
        let paths = || test_paths(&dir, RELEASE_WINDOW);
        let node_a = node_id_for(&dir.path().join("state-a"), "default");
        let node_b = node_id_for(&dir.path().join("state-b"), "default");
        let (a_registry, a_web) = named_box_registry("web-a", 9);
        let (b_registry, b_web) = named_box_registry("web-b", 10);
        let a = start_daemon(a_registry, port, paths(), &node_a);
        await_status_is(
            &a,
            ZoneAnswererStatus::Holder { port },
            "node a never hosted the interim",
        );
        let b = start_daemon(b_registry, port, paths(), &node_b);
        await_status_is(
            &b,
            ZoneAnswererStatus::Registered { port },
            "node b, from another state dir, never published into a's interim",
        );
        for (name, address) in [
            ("web-a.min.internal.", a_web),
            ("web-b.min.internal.", b_web),
        ] {
            let reply = await_a_record(
                || query(port, name, RecordType::A),
                "a name never answered through the interim",
            );
            assert_eq!(
                a_answer(&reply),
                address,
                "{name} answers through a's interim"
            );
        }
        // And b's boxes are handed addresses from the interim's book, so
        // they never meet a's.
        let a_box = a.allocate("box").expect("a's box");
        let b_box = b.allocate("box").expect("b's box, through a's interim");
        assert_ne!(
            a_box, b_box,
            "the two state dirs' boxes never share an address"
        );
    }

    /// Name ownership is per node, not per uid: two nodes of one operator
    /// (one uid) are two owners, so the second node's publish of the first's
    /// name is refused and names the owner; the owner itself, reconnecting
    /// after a service restart from a symlinked spelling of its state dir,
    /// is the same node and keeps its name.
    #[test]
    fn name_ownership_is_per_node_not_per_uid() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the service");
        let (port, channel, listener, channel_listener) = service_sockets(&dir);
        let (stop, handle) = start_service(
            listener
                .try_clone()
                .expect("the manager re-hands its listener"),
            channel_listener
                .try_clone()
                .expect("the manager re-hands its channel"),
        );
        let state_a = dir.path().join("state-a");
        let state_b = dir.path().join("state-b");
        std::fs::create_dir_all(&state_a).expect("node a's state dir");
        std::fs::create_dir_all(&state_b).expect("node b's state dir");
        let link_a = dir.path().join("state-a-link");
        std::os::unix::fs::symlink(&state_a, &link_a).expect("a symlinked spelling of a's dir");
        let node_a = node_id_for(&state_a, "default");
        let node_b = node_id_for(&state_b, "default");
        let address = Ipv4Addr::new(127, 0, 64, 21);

        let first = connect_and_publish(&channel, &node_a, vec![published_row("owned", address)])
            .expect("node a publishes");
        assert!(first.refused.is_empty(), "node a's name is held");
        let second = connect_and_publish(&channel, &node_b, vec![published_row("owned", address)])
            .expect("node b's connection is served");
        let [refused] = &second.refused[..] else {
            panic!(
                "node b's claim on a's name is refused: {:?}",
                second.refused
            );
        };
        assert!(
            refused.reason.contains(&node_a),
            "the refusal names the owning node: {}",
            refused.reason
        );
        drop(second);
        drop(first);

        // ── the service restarts; node a re-publishes first, from the
        // symlinked spelling of its state dir.
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("the service's first run ends");
        std::thread::sleep(CONNECTION_POLL * 3);
        let (stop, handle) = start_service(
            listener
                .try_clone()
                .expect("the manager re-hands its listener"),
            channel_listener
                .try_clone()
                .expect("the manager re-hands its channel"),
        );
        let relinked = node_id_for(&link_a, "default");
        assert_eq!(relinked, node_a, "a symlinked state dir is the same node");
        let again = connect_and_publish(&channel, &relinked, vec![published_row("owned", address)])
            .expect("node a re-publishes after the restart");
        assert!(again.refused.is_empty(), "node a keeps its name");
        // A second connection of the same node is the same owner too.
        let same = connect_and_publish(&channel, &node_a, vec![published_row("owned", address)])
            .expect("node a's second connection is served");
        assert!(
            same.refused.is_empty(),
            "the same node is never refused its own name"
        );
        let other = connect_and_publish(&channel, &node_b, vec![published_row("owned", address)])
            .expect("node b's connection is served");
        assert_eq!(other.refused.len(), 1, "node b is still refused the name");
        let reply = await_a_record(
            || query(port, "owned.min.internal.", RecordType::A),
            "the owned name never answered after the restart",
        );
        assert_eq!(a_answer(&reply), address);
        drop((again, same, other));
        stop.store(true, Ordering::SeqCst);
        let _ = handle;
    }

    /// A release frees the hook port and switches the node to the service:
    /// the hosting daemon answers the release once the port is free, the
    /// service binds it, and the daemon's rows answer through the service's
    /// channel — the handover the privileged step drives. A daemon that
    /// hosts nothing answers a release as a no-op.
    #[test]
    fn release_frees_the_port_and_switches_to_the_channel() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let paths = test_paths(&dir, Duration::from_secs(15));
        let port = free_port();
        let (registry, web) = web_registry();
        let status = start_daemon(registry, port, paths.clone(), "node-a");
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the daemon never hosted the interim",
        );
        assert!(paths.interim.exists(), "the interim holds its channel");

        // The step installs the units (the marker), then asks the release.
        std::fs::write(&paths.marker, b"").expect("the marker is written");
        let reply = status.release();
        assert!(reply.acted, "the hosting daemon releases: {reply:?}");
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port))
            .expect("the port is free once the release is answered");
        assert!(!paths.interim.exists(), "the interim's channel is retired");
        let channel_listener =
            UnixListener::bind(&paths.global).expect("the service's channel binds");
        let (stop, handle) = start_service(listener, channel_listener);

        await_status_is(
            &status,
            ZoneAnswererStatus::ManagerHeld { port },
            "the released daemon never published to the service",
        );
        let reply = await_a_record(
            || query(port, "web.min.internal.", RecordType::A),
            "the released daemon's name never answered through the service",
        );
        assert_eq!(a_answer(&reply), web);
        let noop = status.release();
        assert!(
            !noop.acted,
            "a channel client has nothing to release: {noop:?}"
        );
        let noop = status.release_cancel();
        assert!(
            !noop.acted,
            "a channel client has nothing to re-bind: {noop:?}"
        );
        stop.store(true, Ordering::SeqCst);
        let _ = handle;
    }

    /// A box address request that arrives mid-handover waits for the
    /// service's channel instead of being refused: once the service
    /// answers, inside the window, the request is served there and the
    /// box gets an address of the box range.
    #[test]
    fn allocation_during_handover_waits_then_proceeds() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let paths = test_paths(&dir, Duration::from_secs(15));
        let port = free_port();
        let status = start_daemon(web_registry().0, port, paths.clone(), "node-a");
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the daemon never hosted the interim",
        );
        std::fs::write(&paths.marker, b"").expect("the marker is written");
        assert!(status.release().acted, "the hosting daemon releases");

        // Mid-handover: the request is asked now, with no answerer up.
        let asking = status.clone();
        let asked = Instant::now();
        let request = std::thread::spawn(move || asking.allocate("mid-handover"));
        std::thread::sleep(RELEASE_POLL * 4);
        assert!(
            !request.is_finished(),
            "the request waits instead of being refused"
        );

        // The service comes up inside the window; the request proceeds.
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).expect("the port is free");
        let channel_listener =
            UnixListener::bind(&paths.global).expect("the service's channel binds");
        let (stop, _handle) = start_service(listener, channel_listener);
        let address = request
            .join()
            .expect("the requesting thread ends")
            .expect("the request proceeds once the service answers");
        assert!(in_box_range(address), "a box address: {address}");
        assert!(
            asked.elapsed() < Duration::from_secs(15),
            "served inside the handover window"
        );
        await_status_is(
            &status,
            ZoneAnswererStatus::ManagerHeld { port },
            "the released daemon never published to the service",
        );
        stop.store(true, Ordering::SeqCst);
    }

    /// With no answerer channel and the hook port held by a process that
    /// has none, the node cannot host and nothing can allocate: every box
    /// registration fails loudly, naming the port, the holder (here this
    /// test process, which holds the port) and the remedy — never a
    /// fallback to a node-local address.
    #[test]
    fn registration_fails_naming_a_channelless_hook_port_holder() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let squatter =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a foreign holder binds a port");
        let port = squatter.local_addr().expect("the holder's port").port();
        let status = start_daemon(
            web_registry().0,
            port,
            test_paths(&dir, RELEASE_WINDOW),
            "node-a",
        );
        await_status_is(
            &status,
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "the daemon never surfaced the held port",
        );
        let refused = status
            .allocate("box")
            .expect_err("no box is handed an address while the port is held");
        assert!(
            refused.contains(&format!("127.0.0.1:{port}")),
            "the error names the port: {refused}"
        );
        assert!(
            refused.contains(&format!("pid {}", std::process::id())),
            "the error names the holder's pid: {refused}"
        );
        assert!(
            refused.contains(&format!("free port {port} or set the hook port")),
            "the error gives the remedy: {refused}"
        );
        // The native remedy, for a minimald holder.
        let native = channelless_holder_error(port, Some((42, "/usr/bin/minimald".to_string())));
        assert!(
            native.contains("install the answerer service (min session start prints the command)")
                && native.contains("pid 42"),
            "{native}"
        );
        drop(squatter);
    }

    /// A release whose service never comes re-binds the interim on its own
    /// when the window runs out: the hook port is never left unanswered
    /// past the bound.
    #[test]
    fn release_rebinds_the_interim_when_the_channel_never_comes() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let window = Duration::from_secs(2);
        let paths = test_paths(&dir, window);
        let port = free_port();
        let (registry, web) = web_registry();
        let status = start_daemon(registry, port, paths.clone(), "node-a");
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the daemon never hosted the interim",
        );
        std::fs::write(&paths.marker, b"").expect("the marker is written");
        let released_at = Instant::now();
        assert!(status.release().acted, "the hosting daemon releases");
        assert!(
            query(port, "web.min.internal.", RecordType::A).is_none(),
            "nothing answers the released port"
        );
        let reply = await_a_record(
            || query(port, "web.min.internal.", RecordType::A),
            "the interim never re-bound after the window",
        );
        assert!(
            released_at.elapsed() >= window,
            "the interim re-bound only once the window ran out"
        );
        assert_eq!(a_answer(&reply), web);
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the daemon never said it hosts again",
        );
    }

    /// A cancel re-binds the interim at once, well inside the window, and
    /// says so; a cancel with no release pending is a no-op.
    #[test]
    fn release_cancel_rebinds_immediately() {
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let window = Duration::from_secs(60);
        let paths = test_paths(&dir, window);
        let port = free_port();
        let (registry, web) = web_registry();
        let status = start_daemon(registry, port, paths.clone(), "node-a");
        await_status_is(
            &status,
            ZoneAnswererStatus::Holder { port },
            "the daemon never hosted the interim",
        );
        let idle = status.release_cancel();
        assert!(!idle.acted, "no release is pending: {idle:?}");
        assert!(status.release().acted, "the hosting daemon releases");
        let cancelled_at = Instant::now();
        let reply = status.release_cancel();
        assert!(reply.acted, "the cancel re-binds: {reply:?}");
        assert!(
            reply.detail.contains("re-bound"),
            "and says so: {}",
            reply.detail
        );
        let answer = await_a_record(
            || query(port, "web.min.internal.", RecordType::A),
            "the cancelled release never re-bound",
        );
        assert!(
            cancelled_at.elapsed() < window / 4,
            "the cancel re-bound at once, not at the window"
        );
        assert_eq!(a_answer(&answer), web);
        assert!(
            paths.interim.exists(),
            "the re-bound interim holds its channel again"
        );
    }

    /// A socket at the global channel path without the install marker is a
    /// leftover, not a service: the daemon logs the stale path, ignores it,
    /// and hosts the interim — while the marker's presence with a channel
    /// that refuses is an error, never a host.
    #[test]
    fn stale_channel_without_install_marker_hosts_the_interim() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let dir = tempfile::TempDir::new().expect("a temp dir for the channels");
        let paths = test_paths(&dir, Duration::from_secs(15));
        // The leftover: a socket file a dead service left, nothing behind it.
        drop(UnixListener::bind(&paths.global).expect("the leftover binds"));
        assert!(paths.global.exists(), "the leftover socket file stays");
        let port = free_port();
        let (registry, web) = web_registry();
        let status = AnswererStatus::starting();
        let probe = status.clone();
        let global = paths.global.display().to_string();
        let daemon_paths = paths.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        std::thread::Builder::new()
            .name("test-zone-daemon".to_string())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    acquire(registry, port, &daemon_paths, "node-a", &status);
                });
            })
            .expect("the daemon's thread spawns");
        await_status_is(
            &probe,
            ZoneAnswererStatus::Holder { port },
            "a stale global channel without a marker kept the daemon from hosting",
        );
        let reply = await_a_record(
            || query(port, "web.min.internal.", RecordType::A),
            "the interim never answered",
        );
        assert_eq!(a_answer(&reply), web);
        await_log(
            &buf,
            |line| line.contains("no answerer service is installed") && line.contains(&global),
            "the stale global channel path was never logged",
        );

        // The marker present over a channel that refuses: an error, no host.
        let other = tempfile::TempDir::new().expect("a second temp dir");
        let installed = test_paths(&other, Duration::from_secs(15));
        drop(UnixListener::bind(&installed.global).expect("the refusing socket binds"));
        std::fs::write(&installed.marker, b"").expect("the marker is written");
        let port = free_port();
        let (registry, _) = web_registry();
        let status = start_daemon(registry, port, installed, "node-b");
        await_status_is(
            &status,
            ZoneAnswererStatus::PortHeldNoChannel { port },
            "an installed service's refusing channel was hosted around",
        );
        assert!(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok(),
            "the daemon never bound the port over an installed service"
        );
    }
}
