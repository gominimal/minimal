//! Wire contract for minimald's oneshot SSH RPCs.
//!
//! This crate holds the protocol surface shared between the minimald server
//! and its clients: the subsystem names, the request/response payload types,
//! and the [`OneshotSshRpc`] trait that pairs them. It deliberately carries no
//! transport or server dependencies (no `russh`, no `tokio`) so that clients
//! — including the test harness and cross-platform integration tests — encode
//! and decode requests through the very same types the server handles.
//!
//! The server-side serving glue lives in the `minimald` crate.

use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sessions::SessionId;

pub mod exec;
pub mod taskenv;
pub mod trace;

pub use sessions::{
    BoxAddresses, CredentialedUpstream, DynamicIngress, EffectiveEgress, EffectiveSessionPolicy,
    EgressPolicy, IngressPolicy, IpProto, NetworkMode, PortMapping, SessionPolicy,
};

pub const RPC_SUBSYSTEM_PREFIX: &str = "minimald-v1-";

/// Describes a minimal-specific RPC method sent over ssh.
///
/// Oneshot RPCs are not streaming. The trait pairs a subsystem name with its
/// request and response schemas; both the server (which decodes the request
/// and encodes the response) and clients (which do the reverse) implement
/// against this single contract.
pub trait OneshotSshRpc {
    /// The subsystem name used to call for this RPC.
    const NAME: &'static str;
    /// The type schema of the request.
    ///
    /// Bound on `Serialize` exists so that clients (including the test
    /// harness) can encode requests through the same type the handler
    /// decodes them with.
    type Request<'a>: Deserialize<'a> + Serialize;
    /// The type schema of the response.
    ///
    /// Bound on `DeserializeOwned` exists for symmetry with `Request`:
    /// clients decode the same type the handler emitted.
    type Response: Serialize + DeserializeOwned;
}

/// A convinence wrapper to let a response type be able to carry an error.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Errorable<S: std::fmt::Debug + PartialEq> {
    Ok(S),
    Err { error: String },
}

impl<S: std::fmt::Debug + PartialEq> Errorable<S> {
    pub fn unwrap(self) -> S {
        match self {
            Self::Ok(s) => s,
            Errorable::Err { error } => panic!("unwrap of error value: {error}"),
        }
    }

    pub fn ok(self) -> Option<S> {
        match self {
            Self::Ok(s) => Some(s),
            Errorable::Err { .. } => None,
        }
    }
    pub fn err(self) -> Option<String> {
        match self {
            Self::Ok(_) => None,
            Errorable::Err { error } => Some(error),
        }
    }
}

impl<T: std::fmt::Debug + PartialEq, E: ToString> From<Result<T, E>> for Errorable<T> {
    fn from(value: Result<T, E>) -> Self {
        match value {
            Err(e) => Self::Err {
                error: e.to_string(),
            },
            Ok(t) => Self::Ok(t),
        }
    }
}

/// An RPC to get the version of minimald.
pub struct GetVersion;

/// The response to the [`GetVersion`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetVersionResponse {
    pub version: String,
    pub long_version: String,
    pub stdlib_version: String,
}

impl OneshotSshRpc for GetVersion {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetVersion");
    type Request<'a> = ();
    type Response = GetVersionResponse;
}

/// Set to a non-empty value to downgrade the version gate to a warning.
/// Escape hatch for deliberate skew (bisecting a daemon regression against a
/// known-good CLI); named in [`version_skew_message`] so anyone who hits the
/// gate finds it.
pub const SKEW_OVERRIDE_VAR: &str = "MINIMAL_ALLOW_VERSION_SKEW";

/// How [`version_skew_message`] names a daemon whose reply carried no
/// `daemon_version` at all.
///
/// Every RPC that the gated paths piggyback on reports the daemon's build
/// (see [`CreateSessionResponse::daemon_version`]). A reply without one comes
/// from a daemon built before that field existed — which is itself proof that
/// it is not this build, so it is a skew, not an unknown.
pub const UNVERSIONED_DAEMON: &str = "an older build that does not report its version";

/// The operator-facing account of a CLI/daemon version skew, or `None` when
/// the two builds match.
///
/// Lives in the wire crate because *both* ends produce it: the client when a
/// reply reports a build it did not expect, and the daemon when it refuses a
/// create whose [`CreateSessionRequest::must_match_version`] does not name it.
/// One definition means the operator reads the same sentence whichever side
/// caught the skew.
#[must_use]
pub fn version_skew_message(cli: &str, daemon: &str) -> Option<String> {
    (cli != daemon).then(|| {
        format!(
            "This CLI is minimal {cli}, but the running minimald is {daemon}. \
             The two speak the same RPCs only when built together, so continuing \
             would fail partway through and tear down whatever it had created. \
             Restart the daemon on the new build: run `min stop`, then re-run this \
             command (the daemon is started again automatically). \
             Set {SKEW_OVERRIDE_VAR}=1 to proceed anyway."
        )
    })
}

/// An RPC to list sessions managed by this minimald.
pub struct ListSessions;

/// Describes how many times a bell fired, as well as when it last fired.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bell {
    pub count: usize,
    pub last: chrono::DateTime<Utc>,
}

/// Describes a terminal title
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Title {
    pub value: String,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Describes attributes about a running session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningSessionAttrs {
    pub last_stdout: Option<chrono::DateTime<Utc>>,
    pub last_stdin: Option<chrono::DateTime<Utc>>,
    pub title: Option<Title>,
    pub audible_bell: Option<Bell>,
    pub visual_bell: Option<Bell>,
}

/// The per-box egress enforcement state a host-address session's verdict
/// runs under (NET-079), spelled `per_box` when the session's own launch
/// placed its box in a classifier leaf of the host's cgroup tree and `none`
/// when it did not and the box runs with the host's address and no verdict
/// of its own.
///
/// The type is defined in the sessions crate — beside the
/// [`Record`](sessions::Record) field that carries a box's own launch
/// outcome, a session-plane type this crate already depends on — and
/// re-exported here so the paths this crate's clients spell stay what they
/// were: the listing's [`ListSessionsEntry::host_ip_enforcement`] answers in
/// it, and the stringly surfaces carry its machine spelling.
pub use sessions::HostIpEnforcement;

/// An entry in the ListSessions response.
///
/// `project_path` and `status` mirror the fields of the same name on the
/// session [`Record`](sessions::Record). They let a client resolve "which
/// session was built from this directory" and render a state glyph in a
/// picker without a follow-up `GetSessionRecord` round-trip per session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsEntry {
    pub id: SessionId,
    pub name: Option<String>,
    /// The absolute host path the session was built from. `None` on responses
    /// from daemons that predate this field — clients treat such entries as
    /// not matching the cwd but still listable/pickable. Always `Some` from a
    /// current daemon, since [`Record`](sessions::Record) requires the path.
    #[serde(default)]
    pub project_path: Option<paths::HostAbsPath>,
    /// The session's lifecycle status, used to render a state glyph in the
    /// interactive picker. Defaults to `Active` for daemons that predate the
    /// field so an older server still deserializes cleanly.
    #[serde(default)]
    pub status: sessions::SessionStatus,
    /// Git context for the project path, probed by the client at list time
    /// (the daemon cannot probe it: on macOS it runs in the minvmd guest,
    /// where the host's project paths do not exist and git is not on PATH).
    /// `None` on responses from daemons that predate this field, and
    /// whenever the client-side probe fails: not a repo, no git binary, or
    /// a timeout. Boxed so the (usually `None`) field stays small in the
    /// enums that wrap [`ListSessionsEntry`].
    #[serde(default)]
    pub git: Option<Box<GitInfo>>,
    pub attrs: Option<RunningSessionAttrs>,
    /// The per-box egress enforcement the session's box actually runs under
    /// (NET-079): [`HostIpEnforcement::PerBox`] when the box's own launch
    /// placed it in a classifier leaf of the host's tree,
    /// [`HostIpEnforcement::None`] when it did not and the box runs with the
    /// host's address and no verdict of its own. The box's own launch record,
    /// lowered to `none` by the daemon's one classifier fact when the host
    /// can no longer decide per box and never raised above it — so a box
    /// launched unenforced stays `none` for its life, whatever a later launch
    /// of another box decided — and the fact alone only while the session's
    /// box has not launched yet, the same state the create response answers
    /// over. `None` for a session that is not host-address (its verdict is
    /// decided on address leases, never on the host's cgroup tree), for a
    /// host-address box the classifier refused, whose launch said the
    /// refusal, and when the record could not be read back — defaulted so an
    /// entry from an older daemon still decodes, with the same silence the
    /// other surfaces read as "not a host-address session".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip_enforcement: Option<HostIpEnforcement>,
    /// The declared ingress ports this box yields because another box at the
    /// same shared loopback address holds them (NET-129, first-come), one
    /// entry per port naming the holding box: the same registry read
    /// [`SessionRuntimeFacts::shared_port_collisions`] answers from, so a
    /// listing and the policy view cannot disagree. Serde-defaulted, so an
    /// entry from a daemon that predates the field decodes as empty, and
    /// omitted when empty, so the common entry is unchanged on the wire.
    /// Neither this entry nor [`ListSessionsResponse`] is
    /// `deny_unknown_fields`, so a client that predates the field ignores a
    /// populated list rather than refusing the listing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_port_collisions: Vec<SharedPortCollision>,
}

/// The git state of a session's project path, probed by the client on the
/// host filesystem as of the last [`ListSessions`] response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitInfo {
    /// `git rev-parse --abbrev-ref HEAD` — the branch name, or `HEAD` when
    /// detached.
    pub branch: String,
    /// `git rev-parse --show-toplevel` — the working-tree root. For a
    /// linked worktree this is the worktree's root, not the main repo's.
    /// On the host's own filesystem.
    pub repo_root: String,
    /// The checkout is a linked worktree (or submodule): its git directory
    /// lives outside `<toplevel>/.git`.
    pub is_worktree: bool,
}

/// Resources shared by every session managed by a minimald instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourcePool {
    pub cpu_cores: u32,
    pub memory_bytes: u64,
}

/// The response to the [`ListSessions`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    /// Provider capacity shared by all sessions. Optional for compatibility
    /// with minimald versions that predate resource-pool reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_pool: Option<ResourcePool>,
    pub sessions: Vec<ListSessionsEntry>,
    /// The build this daemon runs, so a client can assert the pair matches
    /// without spending a round trip on [`GetVersion`]. `None` from a daemon
    /// that predates the field — see [`UNVERSIONED_DAEMON`] for why that is a
    /// skew rather than an unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_version: Option<String>,
    /// Why `<name>.local.min.internal` hostnames will not route, when they
    /// will not. `None` means the daemon brought its host-side proxy up, or
    /// predates this field.
    ///
    /// The daemon keeps serving when the proxy fails to come up — sessions
    /// still activate and exec still works — so nothing else in this response
    /// betrays the loss. Without this the only trace is a `warn!` in the
    /// daemon log, and the user is at a terminal watching curl fail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_routing_unavailable: Option<String>,
    /// The port the host-side hostname proxy is serving on, so a client can
    /// tell a user where `<name>.min.internal` resolves from. The daemon
    /// listens on the port it was configured with, the documented default
    /// when it was not given one and that one was free, or on an
    /// OS-selected free port when the default was busy — which is why the
    /// port has to travel instead of staying a constant. `None` from a
    /// daemon that predates the field, or while the proxy has not come up
    /// yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_proxy_port: Option<u16>,
    /// The UDP port the box-zone answerer is serving on, beside
    /// [`Self::hostname_proxy_port`] — where the host's resolver is pointed
    /// to answer `*.min.internal`. Carries the same configured / default /
    /// selected story that field does. `None` from a daemon that predates
    /// the field, or while the answerer has not come up yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_answerer_port: Option<u16>,
    /// Whether this daemon's box-zone answerer is bound in its own namespace
    /// — the one fact about the name surfaces this daemon can know (NET-018):
    /// with it the zone *can* be answered natively, without it the hostname
    /// proxy is the only surface that answers at all.
    ///
    /// It says no more than that, on purpose. The daemon probes nothing
    /// beyond itself for this field: the reserved range's presence on the
    /// loopback *it* sits on is the guest's on a VM-backed host, where it
    /// always reads present, so it is the wrong fact rather than an
    /// incomplete one; and whether the *host's* resolver is pointed at
    /// [`Self::zone_answerer_port`] is not a thing a daemon inside the guest
    /// can see at all. The client decides which surface is live from this
    /// fact plus the two it reads on the host itself (the resolver hook, the
    /// range on the host's own loopback), so no verb ever prints this field
    /// as the surface on a host whose resolver it cannot speak for.
    ///
    /// `false` is the default, so a daemon that predates the field reports
    /// the read that changes nothing: an older daemon's silence is not
    /// evidence its answerer serves, and a client that assumed it would name
    /// native DNS on a host that may not have one.
    #[serde(default)]
    pub answerer_bound: bool,
}

impl OneshotSshRpc for ListSessions {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "ListSessions");
    type Request<'a> = ();
    type Response = ListSessionsResponse;
}

/// An RPC to read the session record for a session corresponding to the request.
pub struct GetSessionRecord;

/// The request for a [`GetSessionRecord`] RPC.
///
/// Serialized examples:
///
///  * `{"name": "my-session"}`
///  * `{"id": "<some-uuid>"}`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionRecordRequest {
    Name(String),
    Id(SessionId),
}

/// The response for a [`GetSessionRecord`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSessionRecordResponse {
    pub record: Option<sessions::Record>,
    /// The build this daemon runs, so a client can assert the pair matches
    /// without spending a round trip on [`GetVersion`]. `None` from a daemon
    /// that predates the field — see [`UNVERSIONED_DAEMON`] for why that is a
    /// skew rather than an unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_version: Option<String>,
}

impl OneshotSshRpc for GetSessionRecord {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionRecord");
    type Request<'a> = GetSessionRecordRequest;
    type Response = GetSessionRecordResponse;
}

/// An RPC to snapshot a session's terminal screen without attaching.
pub struct GetSessionScreen;

/// A single terminal cell.
///
/// Colors are strings so the wire contract stays free of any terminal
/// library's color type: an ANSI-256 palette index is `"idx:<n>"` and a
/// truecolor value is `"#rrggbb"`. `None` is the terminal default.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenCell {
    pub ch: char,
    pub fg: Option<String>,
    pub bg: Option<String>,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub reverse: bool,
}

/// A row of terminal cells.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenRow {
    pub cells: Vec<ScreenCell>,
}

/// The terminal screen snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScreenSnapshot {
    pub rows: u16,
    pub cols: u16,
    pub cursor_row: Option<u16>,
    pub cursor_col: Option<u16>,
    pub lines: Vec<ScreenRow>,
}

impl OneshotSshRpc for GetSessionScreen {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionScreen");
    type Request<'a> = SessionId;
    type Response = Errorable<ScreenSnapshot>;
}

/// An RPC to create a new session.
///
/// Allocates the session's record and brings its actor up; the
/// session exists but has no loadout yet. The client follows up with
/// [`ConfigureLoadout`] once the daemon-side workspace holds the
/// project files the composer reads — nothing here composes, so a
/// caller that only needs a session (sftp / exec / session-recovery)
/// can stop after this RPC.
pub struct CreateSession;

/// Session configuration that lives outside the composable
/// [`WireContribution`] — the user-supplied `name`, the project
/// path the session is built from, the network isolation mode, the
/// per-session networking policy, and free-form attrs.
///
/// `username` is deliberately *not* here: it comes from the SSH
/// connection context on the daemon side, never from the caller.
/// `id` and `status` are also out: id is allocated by the store,
/// status is managed by the manager actor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    /// User-supplied name. `None` is anonymous; the daemon may render
    /// a short display name (e.g. `<user>-<project>-<uuid-suffix>`).
    pub name: Option<String>,
    /// Absolute host path the session is built from. Names a location
    /// on the *client's* filesystem — the daemon uses it only for
    /// display and audit. Project files reach the daemon-side
    /// workspace out-of-band via the `WorkspaceFilesTarZst` SFTP-shaped
    /// upload after `CreateSession` returns, before `ConfigureLoadout`
    /// composes against them.
    pub project_path: paths::HostAbsPath,
    /// Network isolation mode.
    #[serde(default)]
    pub network: NetworkMode,
    /// Per-session networking policy (egress + ingress).
    #[serde(default)]
    pub policy: SessionPolicy,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when the activating client registered one: its switch
    /// address, which the in-VM daemon attaches with instead of drawing
    /// its own, and its published loopback address. `None` for every other
    /// activation — a host that is not minvmd-backed, a box that is not
    /// own-address — and the daemon then attaches exactly as it always
    /// has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_addresses: Option<BoxAddresses>,
    /// Whether the session runs the lifecycle hooks composed into it.
    /// Cleared by `min session activate --no-hooks`, and persisted onto
    /// the session record so the later attach/detach/destroy
    /// transitions — which run from processes that never saw the
    /// activating command — honour the same choice. Defaults to `true`
    /// so a client that predates the field gets hooks, not silence.
    #[serde(default = "default_hooks_enabled")]
    pub hooks_enabled: bool,
    /// Free-form attributes (typed by the caller), persisted onto the
    /// session's record. The daemon writes none of its own: NET-079's
    /// per-box enforcement is a daemon-owned launch record, carried on the
    /// session record's own `host_ip_enforcement` field — written only by
    /// the box's launch, never by a create — and displayed as that record
    /// lowered by the host's current fact, so it is never a client attr.
    /// A client supplying the daemon's own `host_ip_enforcement` key has it
    /// stripped unconditionally, whatever the session's network mode — the
    /// state is the host's verdict, never a caller's assertion.
    #[serde(default)]
    pub attrs: std::collections::BTreeMap<String, String>,
}

/// Serde default for [`SessionConfig::hooks_enabled`]. See
/// [`sessions::Record::hooks_enabled`] for why this cannot be a bare
/// `#[serde(default)]`.
fn default_hooks_enabled() -> bool {
    true
}

/// A box's identity on its host: 16 bytes — one UUIDv7, 32 lowercase hex
/// digits on the wire — minted once per box by the host-side creator
/// outside the VM, with its random fields from the host's OS CSPRNG
/// (BEP-070): never a counter, never a digest of the box's facts, never
/// anything a process inside the VM could predict or arrange. The
/// registration that publishes the box's row mints it — a client never
/// presents one — the row and the proxy's attachment hold it, and the
/// reply hands it back so the client records the id its box was created
/// as.
///
/// Unique per creation by construction: a box recreated with the same
/// name and the same addresses is a new box, and its id says so. Ids are
/// never reused — no registration can present one, and the host refuses a
/// mint that collides with a record it holds — so a revocation scoped to
/// an id stays scoped forever. The all-zero id is not
/// a mint's output and never names a box: the delivery header carried it
/// for "no box named" before ids were the box's own, and the acceptor
/// that reads a delivered header refuses it like any other id the
/// source's attachment does not hold.
///
/// On the wire it is one hex string, the same 32 lowercase digits a
/// diagnostic names a box id by — so a log line, a transcript and a
/// socket capture all read the same spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoxId([u8; 16]);

impl BoxId {
    /// Wraps `bytes` as a box id — the shape [`RegisteredBox::box_id`]
    /// carries and a delivery header fills from the box's attachment.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The id's own 16 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl std::fmt::Display for BoxId {
    /// 32 lowercase hex digits — the one fixed form every diagnostic that
    /// names a box id uses, so a tail can compare two lines for the same
    /// box.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for BoxId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for BoxId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(text).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 16] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => {
                return Err(serde::de::Error::custom(format!(
                    "a box id is 32 hex digits (16 bytes); got {} bytes",
                    bytes.len()
                )));
            }
        };
        Ok(Self(bytes))
    }
}

/// What a successful registration hands back: the allocated addresses —
/// the pair [`BoxAddresses`] has always carried — and the box id the
/// published row now holds ([`BoxId`]): the one the host minted for this
/// creation. A registration carries no id; this reply is where the client
/// learns its box's.
///
/// The id travels beside the addresses because both belong to the same
/// fact — this is the box the host just published — so the client records
/// the id it is handed, and the client's record, the sealed member's
/// claims and the proxy's attachment name the box by the same id. A
/// re-registration is a new creation and is handed a new id.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredBox {
    /// The box's address on the switch ([`BoxAddresses::switch_address`]).
    pub switch_address: std::net::Ipv4Addr,
    /// The box's published loopback address
    /// ([`BoxAddresses::loopback_address`]).
    pub loopback_address: std::net::Ipv4Addr,
    /// The box id the published row holds: the box's own UUIDv7, handed
    /// back to the registering client.
    pub box_id: BoxId,
}

/// The wire types of the VM host daemon's box control socket (T66): the
/// one door a client has to the host-side box table (NET-138).
///
/// On a minvmd-backed host, `min session activate` opens this socket — a
/// UDS beside the daemon's ssh socket in the provider's state dir — writes
/// one [`BoxControlRequest`] line of JSON — a registration when the box is
/// created, a withdrawal when the session that registered it is destroyed
/// or its activation fails — and reads one [`BoxControlReply`] line back.
/// Nothing else crosses it: the session RPCs are the daemon crate's
/// HTTP-shaped socket, and the box's switch and loopback addresses come
/// from here so the daemon's create request can carry them (see
/// [`SessionConfig`]).
///
/// These types live here rather than in `minvmd` because both ends depend
/// on this crate — the activating client and the host daemon — and the
/// protocol must not drift between them.
///
/// A box's identity is its [`BoxId`]: minted once per box by the host-side
/// creator outside the VM — never carried on the registration the client
/// sends — and handed back on the reply, so the client, the published row
/// and the proxy's attachment all name the box by one id.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterBoxRequest {
    /// The box's name — the session name the following create request
    /// carries, so the host-side row and the session identify the same box.
    /// A box's id on the host is its name.
    pub name: String,
    /// The external ports the box's ingress rules admit, as the client
    /// expanded them. The host row holds the expanded ports rather than the
    /// rules so the rule grammar stays the client's: the attaching side
    /// reaches ports without re-parsing declarations.
    #[serde(default)]
    pub ingress_ports: Vec<u16>,
    /// The box's egress policy, as the client expanded it. Absent means the
    /// allow-all default — the same meaning the create request's policy
    /// carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressPolicy>,
    /// The box's declaration of a credentialed upstream (NET-134), carried
    /// from the session's policy: `Some` marks the Box Egress Proxy's
    /// listener as the box's infrastructure — the one destination its
    /// egress rules never decide — and `None`, the default, is no lane: the
    /// row the host publishes refuses the box's frames to the proxy's
    /// address under the box-to-host default-deny. The minimum of the proxy
    /// document's field schema; a client that predates the field declares
    /// nothing, exactly as one that never asked for a lane does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentialed_upstream: Option<CredentialedUpstream>,
    /// The box's dynamic-ingress stance (NET-045), from the same create
    /// inputs the session record holds: the stance half of the grant the
    /// host-side row holds a runtime port report against — a report under
    /// `allow` records in range, one under `ask` records what the attached
    /// human answered yes to, and `deny`, the stance an absent declaration
    /// carries, admits nothing. The host decides; the guest only reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_ingress: Option<DynamicIngress>,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance, the same meaning the create request's absent range
    /// carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_allowed_range: Option<(u16, u16)>,
    /// Whether the registration is held as a lease until its client
    /// commits it. With `hold`, the daemon writes the reply and keeps the
    /// connection open: the client writes one `commit` line once its
    /// session is active, and a close or an error before that line
    /// withdraws the row, so an activation that dies between registering
    /// and committing leaves no row holding its name. A client that omits
    /// the field, or a daemon that predates it, keeps the one-shot
    /// registration: one line each way, and the row lives until its
    /// creator withdraws it.
    #[serde(default)]
    pub hold: bool,
}

/// The one line a held registration's client writes on the lease
/// connection once its session is active ([`RegisterBoxRequest::hold`]):
/// from then on the row stays when the connection closes.
pub const REGISTRATION_COMMIT_LINE: &str = "commit";

/// The withdrawal a destroyed session's client sends for the row its
/// activation registered: the name the row went by and the pair the
/// registration handed back. The pair is the proof that the withdrawer is
/// the row's creator — a row is its registering side's to withdraw (NET-138),
/// and no other client holds the pair, which no session record but the
/// creator's carries.
///
/// Withdrawal answers [`BoxControlReply::Addresses`] echoing the pair back
/// when the row is gone. The daemon answers a row already withdrawn — or a
/// daemon restarted since the registration — the same way: no row at the
/// named switch address is the goal state either way, so the withdrawal
/// succeeds. A row that *is* published there under a different name or pair
/// is refused with [`BoxControlReply::Error`]: the requesting client is not
/// its creator, and no client may remove another box's row.
///
/// The addresses themselves are spent for good by design — the host's
/// allocation cursors never regress — so a withdrawal ends a row's
/// admissions without ever returning its addresses to the plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawBoxRequest {
    /// The name the row to withdraw was registered under.
    pub name: String,
    /// The switch address the registration handed back, which keys the row
    /// in the host table.
    pub switch_address: std::net::Ipv4Addr,
    /// The loopback address the registration handed back, which the pair
    /// proof checks against the row's own.
    pub loopback_address: std::net::Ipv4Addr,
}

/// What side of the in-VM daemon reported a runtime-admitted port (NET-045,
/// NET-138): the fixed fact the host's log line and audit copy name, so a
/// tail can tell an expose decision from an answered ask from a listen
/// without parsing the daemon's own logs.
///
/// Reported, never trusted: the host records the port only inside the grant
/// the host-side registration holds ([`RegisterBoxRequest`]), whatever this
/// says — the source is a label on the report, not a permission.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PortReportSource {
    /// An `expose` decided allow under a `dynamic_ingress = allow` stance.
    Expose,
    /// The attached human answered yes to an ask (NET-045).
    Ask,
    /// A listen-publish the box's own watcher made (the permitted-listener
    /// half of the dynamic stance).
    Listen,
}

/// The in-VM daemon's report that one of its boxes published a port at
/// runtime (NET-138): the fixed, size-bounded message — the row key, the
/// port, the protocol, and the reporting source, nothing else — the guest
/// sends the VM host daemon before the publish is reported to the caller.
///
/// The row key is the box's **switch address**, the address the host-side
/// registration handed back: it is the one fact the guest cannot invent a
/// row with, because no row exists at an address the host did not allocate,
/// so a report keyed anywhere else is refused as no row's. The port is
/// checked against the grant the row holds — the box's
/// `dynamic_ingress` stance and its allowed range, both carried at
/// registration — and a refusal answers [`BoxControlReply::Error`] naming
/// why, so the guest's publish unwinds with no partial mapping.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmitPortRequest {
    /// The switch address of the row the port belongs to — the row's own
    /// key, the address the registration handed back.
    pub switch_address: std::net::Ipv4Addr,
    /// The runtime-published port the box is admitting.
    pub port: u16,
    /// The protocol the port was published under.
    pub proto: IpProto,
    /// Which side of the in-VM daemon reported it
    /// ([`PortReportSource`]): the label the host's log and audit lines
    /// carry.
    pub source: PortReportSource,
}

/// The in-VM daemon's report that one of its boxes stopped publishing a
/// runtime-admitted port: the withdrawal half of [`AdmitPortRequest`], the
/// same row key and port, sent when the mapping closes — an unexpose, a
/// listener's end, or the box's own stop.
///
/// A withdrawal is never refused by the cap or the rate the admit path
/// answers to: removing a fact the row holds is always the row's goal
/// state, so the host answers [`BoxControlReply::PortRecorded`] whether the
/// port was held or not.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawPortRequest {
    /// The switch address of the row the port belongs to.
    pub switch_address: std::net::Ipv4Addr,
    /// The runtime-published port the box withdrew.
    pub port: u16,
    /// The protocol the port was published under.
    pub proto: IpProto,
    /// Which side of the in-VM daemon reported it
    /// ([`PortReportSource`]).
    pub source: PortReportSource,
}

/// The read-only row verb's key: the box's name, the identity a row is
/// registered under ([`RegisterBoxRequest::name`]). Liveness is the table's
/// own fact — a name that no live box holds answers
/// [`BoxControlReply::NoRow`], never a destroyed box's last row, because a
/// withdrawn row is gone, not archived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadRowRequest {
    /// The name the row was registered under.
    pub name: String,
}

/// The read-only row verb's answer for a live box: the row's switch address
/// — the key its reports carry — beside the facts the host holds about it:
/// the egress allow-list derived from its declared rules, and its declared
/// and runtime-admitted ports, so a host-side read can see both halves of
/// what the gate admits for the box.
///
/// The allow-list is the row's compiled egress subnets as CIDR strings —
/// `0.0.0.0/0` for the absent-policy allow-all, empty for a row that
/// declared a policy no subnet passes — because the read is a person's
/// surface: the strings are the policy as it was declared, not the
/// compiled form only the gate reads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoxRow {
    /// The name the row was registered under.
    pub name: String,
    /// The box's identity on its host ([`BoxId`]): the row's own
    /// host-minted id, so a host-side client can subscribe to the row's
    /// pending asks by an identity no guest-reported string can name
    /// (NET-045). Required the same way [`RegisteredBox::box_id`] is: a
    /// row read from a daemon that predates ids fails the whole parse on
    /// a new client rather than silently naming a box no id names.
    pub box_id: BoxId,
    /// The box's address on the switch: the row's key.
    pub switch_address: std::net::Ipv4Addr,
    /// The row's derived egress allow-list, as CIDR strings.
    pub egress_allow_list: Vec<String>,
    /// The external ports the box's ingress declaration admitted, in the
    /// order the registration carried them.
    pub declared_ports: Vec<u16>,
    /// The ports the row holds as runtime-admitted — reported by the in-VM
    /// daemon within the grant and not yet withdrawn — in report order.
    pub runtime_ports: Vec<u16>,
}

/// A pending ask's identity on its host: 16 bytes — one UUIDv4, 32
/// lowercase hex digits on the wire — minted by the VM host daemon when
/// the in-VM daemon reports an ask (NET-045), never carried by any
/// client: the offer hands the id to the attached host client, and the
/// recorded answer carries it back, so the id names one ask's whole
/// lifetime — offered, answered, consumed — and no client can name an
/// ask the host did not mint.
///
/// Unique per ask by construction, like [`BoxId`]: the daemon that mints
/// one draws it from the host's OS CSPRNG, and an answer for an id the
/// daemon never minted — or minted and already consumed — is refused, so
/// a recorded yes can be spent by exactly the one admit it answers and
/// never replayed. The wire form is one hex string, the same spelling a
/// diagnostic names an ask by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AskId([u8; 16]);

impl AskId {
    /// Wraps `bytes` as an ask id — the shape the VM host daemon mints and
    /// the offer and the recorded answer carry.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The id's own 16 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl std::fmt::Display for AskId {
    /// 32 lowercase hex digits — the one fixed form every diagnostic that
    /// names an ask id uses, so a log line and a socket capture read the
    /// same spelling.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for AskId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for AskId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text: &str = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(text).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 16] = match bytes.try_into() {
            Ok(bytes) => bytes,
            Err(bytes) => {
                return Err(serde::de::Error::custom(format!(
                    "an ask id is 32 hex digits (16 bytes); got {} bytes",
                    bytes.len()
                )));
            }
        };
        Ok(Self(bytes))
    }
}

/// The answer a host client records for one pending ask over the host
/// door (NET-045): `yes` from a human who picked Allow, `no` from a human
/// who picked Deny or ended the dialog without a pick — Ctrl-C, Escape, a
/// closed input — and `no_tty` when no terminal was there to render the
/// dialog at all, so the host's audit can tell a human's own *no* from a
/// render that never reached one.
///
/// The daemon never answers on its own behalf: a client that went away
/// before answering is an un-asked ask the admit path refuses, not an
/// answer this enum could carry.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AskAnswer {
    /// The attached human chose Allow: the ask's port is recorded in the
    /// row, and the waiting admit publishes.
    Yes,
    /// The attached human chose Deny, or ended the dialog: the ask is
    /// cleared and admits nothing.
    No,
    /// No terminal was there to render the dialog: nobody answered, and
    /// the ask is cleared without recording a port.
    NoTty,
}

/// The in-VM daemon's report that one of its boxes' exposes was decided
/// `ask` (NET-045): the row key, the port and the protocol — nothing
/// else, the same fixed, size-bounded shape [`AdmitPortRequest`] carries,
/// and for the same reason: the guest can raise a question but never
/// answer one, and a name or a prompt string it might have sent is not
/// something a dialog could trust.
///
/// The VM host daemon mints the ask's [`AskId`], offers it to every host
/// client attached to the row, and holds this request's reply until a
/// recorded answer resolves it — there is no deadline on either side, so
/// an ask ends only by an answer or a cancellation, never by a timer
/// expiring a publish the human never saw.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmitAskRequest {
    /// The switch address of the row the ask belongs to — the row's own
    /// key, the address the registration handed back.
    pub switch_address: std::net::Ipv4Addr,
    /// The port the exposure asks to publish.
    pub port: u16,
    /// The protocol the port would publish under.
    pub proto: IpProto,
}

/// A host client's recorded answer for one pending ask (NET-045): the
/// offer's [`AskId`] and the answer. Served on the host's control socket
/// only — the guest door refuses it, because a guest can raise a question
/// but never answer one — and the first recorded answer wins: every later
/// one is refused as an answer for an id the daemon already consumed, so
/// a yes can be spent by exactly the one admit it answered.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordAskAnswerRequest {
    /// The ask the offer named.
    pub ask_id: AskId,
    /// The answer the attached human gave, or the render's own no-tty.
    pub answer: AskAnswer,
}

/// An attached host client's subscription to one row's pending asks
/// (NET-045): keyed by the row's [`BoxId`] — the host-minted identity, so
/// a guest-reported name can never subscribe — and held only while the
/// connection lives. The daemon answers [`BoxControlReply::AsksSubscribed`],
/// then pushes one [`BoxControlReply::PendingAskOffer`] line per ask the
/// row gains and one [`BoxControlReply::PendingAskDismissed`] line per ask
/// another client answered, until the client closes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscribeAsksRequest {
    /// The row's box id — the host-minted identity the row read hands the
    /// client.
    pub box_id: BoxId,
}

/// One pending ask as the VM host daemon offers it to an attached client
/// (NET-045): the ask's id, the row it belongs to, and the port and
/// protocol the exposure named. The box's name travels here too — from
/// the host's own row, never from a guest-supplied string, because the
/// dialog the client renders is built from these fields alone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingAskOffer {
    /// The ask's host-minted id: what the recorded answer carries back.
    pub ask_id: AskId,
    /// The row's box id — the identity the client subscribed by.
    pub box_id: BoxId,
    /// The box's name, from the host's own row: the one guest-untouched
    /// field the dialog's text is built from.
    pub name: String,
    /// The port the exposure asks to publish.
    pub port: u16,
    /// The protocol the port would publish under.
    pub proto: IpProto,
}

/// Why a pending ask will not publish (NET-045): the typed end the ask
/// met, so the in-VM daemon's refusal says which end it was rather than
/// parsing a sentence. [`Denied`] alone is the attached human's own no;
/// every other end is an ask nobody answered, and the guest fails it
/// closed the way it fails an ask with no client at all.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AskRefused {
    /// No row is published at the named switch address.
    NoRow,
    /// No host client was attached to the row's box when the ask arrived.
    NoClient,
    /// The row's pending-ask queue was at its bound when the ask arrived.
    QueueFull,
    /// The row's stance is not `ask`.
    StanceNotAsk,
    /// The row's grant admits no such port: no range is declared, or the
    /// port is outside the one that is. Refused at the host before any
    /// dialog is offered, so a client is never asked to answer for a
    /// publish the grant would refuse anyway.
    OutsideGrant,
    /// The attached human answered no.
    Denied,
    /// The dialog could not be rendered: no terminal was there.
    NoTty,
    /// The ask was cancelled before an answer: the row was withdrawn, the
    /// guest's connection ended, the last attached client detached, or
    /// the daemon stopped.
    Cancelled,
}

/// The VM host daemon's answer to the in-VM daemon's ask admit (NET-045):
/// the outcome of the ask the offered dialog decided, tagged `ask` so the
/// untagged reply cannot mistake it for any older shape. [`Admitted`]
/// alone records the port in the row — the one reply a publish may go
/// ahead on; [`Refused`] names which end the ask met
/// ([`AskRefused`]), and the guest's publish unwinds with no partial
/// mapping either way.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "ask", rename_all = "snake_case")]
pub enum AskAdmitOutcome {
    /// The attached human answered yes: the port is recorded in the row
    /// under the ask's id, and this admit — this one — may publish.
    Admitted {
        /// The ask that was answered.
        ask_id: AskId,
        /// The port the host now holds as runtime-admitted.
        port: u16,
        /// The protocol the port was recorded under.
        proto: IpProto,
    },
    /// The ask will not publish: the typed end it met.
    Refused {
        /// The ask that met this end.
        ask_id: AskId,
        /// Which end the ask met.
        reason: AskRefused,
        /// What cancelled the ask, for a [`AskRefused::Cancelled`] end;
        /// absent for every other end.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cause: Option<AskCancelCause>,
    },
}

/// What cancelled a pending ask (NET-045): the four ends an ask meets with
/// no answer, so the in-VM daemon and a late client can each say which.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AskCancelCause {
    /// The last host client attached to the box detached.
    LastDetach,
    /// The box's host row was withdrawn.
    RowWithdrawn,
    /// The in-VM daemon closed the asking connection: it withdrew the ask.
    GuestClosed,
    /// The VM host daemon is stopping.
    MinvmdStopping,
}

impl std::fmt::Display for AskCancelCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LastDetach => "the last attached client detached",
            Self::RowWithdrawn => "the box's host row was withdrawn",
            Self::GuestClosed => "the guest connection closed",
            Self::MinvmdStopping => "minvmd is stopping",
        })
    }
}

/// How an already-ended ask ended (NET-045), as the VM host daemon answers
/// a late recorded answer for it: the client whose dialog outlived the ask
/// says what actually happened instead of guessing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "end", rename_all = "snake_case")]
pub enum AskLateEnd {
    /// Another attach's yes admitted it.
    Allowed,
    /// Another attach answered no (or could not show the prompt).
    Denied,
    /// It was cancelled before an answer.
    Cancelled {
        /// What cancelled it.
        cause: AskCancelCause,
    },
}

/// The host-side port the in-VM daemon's box-port reports cross to: the
/// vsock port the guest dials `VMADDR_CID_HOST` on to report a runtime
/// admission or withdrawal into the host-held grant, pinned here because
/// both ends — the in-VM daemon that dials it and the VM host daemon that
/// bridges it to its guest control channel — depend on this crate, so the
/// report channel cannot drift between them. Beside the boot-marker port
/// (`minimald`'s `VM_HOST_MARKER_PORT`, 7350), one port per purpose: the
/// marker is one-way and fire-and-forget, this one answers, because a report
/// the grant refused must be refused *to the reporter* for the publish to
/// unwind (NET-138). Not 7351: the timekeep bridge owns that number, in the
/// opposite direction — the host dials *into* the guest on it — and one
/// number serving two purposes is two channels one misroute away.
pub const VM_HOST_BOX_REPORT_PORT: u32 = 7352;

/// The one request line the control socket takes: which verb the client
/// wants, tagged in the line itself.
///
/// The tag is the version corner, and it leans the safe way. A daemon that
/// predates a verb cannot parse the tagged line and refuses it — and an old
/// CLI's registration, untagged, fails the new daemon's parse the same way,
/// so the daemon is autospawned by the CLI from the same install and the
/// mixed-version pair is the corner, not the rule. Without the tag, dispatch
/// ordered register-then-withdraw would parse a withdraw line on a daemon
/// that predates the verb as a *spurious registration* — the line's extra
/// fields ignored, a row with no ports and an allow-all policy filling in,
/// spending a finite hand-out address — which is worse than the refusal:
/// the registering side's row stays published either way, but only the
/// refusal leaves no new fact on the host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum BoxControlRequest {
    /// Register the box's declaration: allocate the box's addresses on the
    /// host and fill the row the egress gate decides by.
    Register(RegisterBoxRequest),
    /// Withdraw the row a registration filled: the destroyed or failed
    /// session's creator presenting the pair the registration handed back.
    Withdraw(WithdrawBoxRequest),
    /// Read the machine's zone-answerer status (see [`ZoneAnswererStatus`])
    /// — the read-only verb: no row is touched, no state changes, the reply
    /// is the status the answerer's acquisition last left.
    AnswererStatus,
    /// The in-VM daemon's report that one of its boxes published a port at
    /// runtime (NET-138), carried on the daemon's own control channel: the
    /// host records it in the row only within the grant the host-side
    /// registration holds, and answers the refusal so the guest's publish
    /// unwinds.
    AdmitPort(AdmitPortRequest),
    /// The in-VM daemon's report that one of its boxes stopped publishing a
    /// runtime-admitted port: the withdrawal half of the admit report,
    /// accepted whatever the row's cap or rate says.
    WithdrawPort(WithdrawPortRequest),
    /// The in-VM daemon's report that an expose was decided `ask`
    /// (NET-045): carried on the daemon's own control channel like the
    /// port reports, answered when a host client the daemon offered the
    /// ask to records an answer — with no deadline on the reply, because
    /// no timer ever answers an ask.
    AdmitAsk(AdmitAskRequest),
    /// A host client's recorded answer for one pending ask (NET-045):
    /// served on the host's control socket only — the guest door refuses
    /// it, because a guest can raise a question but never answer one —
    /// and the first answer recorded for an ask is the only one that
    /// counts.
    RecordAskAnswer(RecordAskAnswerRequest),
    /// An attached host client's subscription to one row's pending asks
    /// (NET-045): keyed by the row's host-minted [`BoxId`] — never a
    /// guest-reported name — and served on the host's control socket
    /// only, whose owner-only file mode is its access control. The
    /// subscription lives exactly as long as the connection it arrived on.
    SubscribeAsks(SubscribeAsksRequest),
    /// Read one box's row by name — the read-only row verb: the row's
    /// switch address, its derived egress allow-list, and its declared and
    /// runtime-admitted ports, or [`BoxControlReply::NoRow`] when no live
    /// box holds the name. Served on the host's control socket only, whose
    /// owner-only file mode is its access control.
    ReadRow(ReadRowRequest),
    /// Release the interim answerer (NET-122's handover to the host
    /// service): the daemon stops the answerer it hosts and frees the hook
    /// port, then waits a bounded window for the service's channel and
    /// publishes its rows there, re-binding the interim if the channel
    /// never comes. Answered with [`BoxControlReply::AnswererRelease`] once
    /// the port is free; a daemon that hosts no interim answers a no-op.
    /// Accepted from the operator's uid and from root only.
    ReleaseAnswerer,
    /// Cancel a release: the daemon re-binds its interim answerer at once.
    /// A daemon with no release pending answers a no-op.
    ReleaseAnswererCancel,
}

/// The VM host daemon's answerer status: the state of the machine's
/// box-zone answerer as this daemon sees it (NET-138's single-operator
/// interim), read over the control socket by the verbs that surface it —
/// the session start and `min ls`.
///
/// The zone is answered by whichever VM host daemon bound the machine's
/// answerer port — the holder — and every other VM host daemon on the
/// machine registers its table's rows with the holder over the answerer
/// channel, so one answerer serves every VM's names. The status says which
/// of the states this daemon is in, so the client can say where to look and
/// who holds the port; whether the answerer is *live* at that port is the
/// client's own A query for `host.min.internal` to prove (the row the
/// answerer itself holds), not a fact this status could vouch for.
///
/// The CLI reads this over the control socket and never through the in-VM
/// daemon, because it is a host fact: a guest relaying a host fact is
/// forgeable from inside the escape boundary, and the answerer's port is
/// held on the host's loopback, where only the host's own client can read
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ZoneAnswererStatus {
    /// The answerer's acquisition has not finished its first pass: the
    /// daemon has not yet said which state it is in.
    Starting,
    /// This VM host daemon holds the machine's answerer port on the host
    /// loopback and answers the zone from its own host-authored table.
    Holder {
        /// The port the answerer listens on.
        port: u16,
    },
    /// Another VM host daemon on this machine holds the answerer port; this
    /// daemon's table rows answer through it over the answerer channel.
    Registered {
        /// The machine's answerer port the holder serves.
        port: u16,
    },
    /// The installed answerer host service holds the answerer port (NET-122's
    /// host service): the service manager holds its sockets and this
    /// daemon's table rows answer through it over the machine-global answerer
    /// channel. The zone is manager-held, so it answers whether or not any
    /// session holds it.
    ManagerHeld {
        /// The machine's answerer port the service serves.
        port: u16,
    },
    /// The answerer port is held by a process with no channel — a native
    /// minimald, or a foreign process — so this VM's names are not answered
    /// on the host and the hostname proxy remains the only surface.
    PortHeldNoChannel {
        /// The machine's answerer port, held by a process with no channel.
        port: u16,
    },
    /// The hostname proxy this VM host daemon reserved for its VM is not
    /// serving, and this is the host-side cause (T93): the port the
    /// supervisor drew or was pinned and what kept it from publishing. It
    /// rides the answerer's read because that read is already the one
    /// host-side fact the CLI asks this daemon for — the proxy's publish
    /// outcome is a host fact the same way the answerer's state is, never
    /// something the guest could vouch for, and it is the CLI's only way to
    /// say *why* the proxy is down rather than that it merely is.
    ProxyNotServing {
        /// The port the supervisor reserved and the guest could not publish.
        port: u16,
        /// What kept the proxy from serving on that port.
        cause: ProxyDownCause,
    },
}

/// Why a VM host daemon says its VM's hostname proxy is not serving (T93):
/// the terminal publish outcomes the supervisor itself reached — the port
/// it reserved is held by another process on the host, or the draws to find
/// a free one ran out — or that its publish is unconfirmed, the one
/// non-terminal state: the VM is up, the publish is not one the host saw. A
/// host that merely has no switch to publish through says nothing here: that
/// boot's proxy never attempted a publish, and its story stays the daemon
/// log's, not a cause this status could name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDownCause {
    /// Another process on the host holds the published port — for a port
    /// the operator pinned this fails the start outright; for a drawn one
    /// it is what every redraw skipped.
    PortHeld,
    /// The drawn port's publish tries ran out: every port the reservation
    /// drew was already taken when the guest tried to publish it.
    RedrawsRanOut,
    /// The VM came up but the guest never reported the publish, and the
    /// supervisor could not attribute the port to this VM's own forwarder:
    /// nothing answers on it, or its holder is one the host does not let
    /// this user see. Not a failure — the VM stays up — but not a publish
    /// the host can vouch for either, so the surfaces say "unconfirmed"
    /// rather than "serving" until the guest's late report clears it.
    PublishUnconfirmed,
    /// The VM came up with its publish unconfirmed, and the guest's late
    /// report then said the port is held: the VM stays up with no hostname
    /// proxy — not a start failure, so it never reads like one. Names the
    /// holder as the host saw it when the report landed (`pid <pid>
    /// (<exe>)`), or `None` when the host would not name it.
    PortHeldAfterStart {
        /// Who holds the port, when the host let the supervisor see it.
        holder: Option<String>,
    },
}

/// The addresses a successful registration hands back
/// ([`sessions::BoxAddresses`]): the box's switch address and its published
/// loopback address, both allocated on the host from the address plan the
/// host switch serves — the same pair the create request carries so the
/// in-VM daemon attaches with it.
///
/// The one reply line the control socket answers any verb with: the handed
/// addresses, or the reason the verb did not happen. A registration hands
/// the allocated pair and the box id the row holds back
/// ([`RegisteredBox`]); a withdrawal echoes the pair it withdrew by, so
/// the client can check the daemon meant the row it asked about; the status
/// verb answers the answerer's state. Untagged so the reply stays one flat
/// JSON object either way.
///
/// The untagged order carries the same rule
/// [`Registered`](Self::Registered) documents: a variant is tried before
/// any it is a strict superset of. The ask shapes are disjoint from every
/// older one by a required field each carries and no other does —
/// [`AsksSubscribed`](Self::AsksSubscribed) its `subscribed`,
/// [`PendingAskOffer`](Self::PendingAskOffer) its `ask_id`,
/// [`PendingAskDismissed`](Self::PendingAskDismissed) its `dismissed`,
/// [`AskAnswerRecorded`](Self::AskAnswerRecorded) its `recorded`,
/// [`AskAdmit`](Self::AskAdmit) its `ask` tag — but two of them also carry
/// a port and a protocol, so a `PortRecorded` document is a strict subset
/// of their fields: they are placed before it rather than after, so an
/// offered ask cannot decode as a recorded port. The older newer shapes
/// stay disjoint the same way — [`Row`](Self::Row) its
/// `egress_allow_list`, [`NoRow`](Self::NoRow) its `no_row`,
/// [`PortRecorded`](Self::PortRecorded) its `proto` — so no document of
/// one can decode as another's, and the order among them is free.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum BoxControlReply {
    /// The record-ask-answer verb's answer for an ask that already ended
    /// (NET-045): how it ended, and the port and protocol it was about.
    /// Nothing is recorded. `already_ended` is required — the marker that
    /// keeps this document from decoding as any other reply; placed first,
    /// before every shape whose fields are a subset of its own.
    AskAlreadyEnded {
        /// The ask the late answer named.
        ask_id: AskId,
        /// The port the ask was about.
        port: u16,
        /// The protocol the ask was about.
        proto: IpProto,
        /// How the ask ended.
        already_ended: AskLateEnd,
    },
    /// The subscribe-asks verb's answer: the row's box id the client is
    /// now attached to. `subscribed` is required — the marker that keeps
    /// this document from decoding as any other reply, a registration's
    /// id-carrying answer included.
    AsksSubscribed {
        /// The marker: always `true`, carried so the untagged reply
        /// discriminates this from every other shape.
        subscribed: bool,
        /// The row's box id the subscription is attached to.
        box_id: BoxId,
    },
    /// A pending ask, pushed to a subscribed client's connection
    /// (NET-045): the ask's id, the row, the port and the protocol — the
    /// host row's own fields, never a guest-supplied string, because the
    /// dialog the client renders is built from these alone. Carries an
    /// `ask_id` no other reply shape has, and is placed before
    /// [`PortRecorded`](Self::PortRecorded), whose port and protocol are
    /// a subset of its fields.
    PendingAskOffer(PendingAskOffer),
    /// A pending ask taken away from a subscribed client: another client
    /// recorded the first answer, the ask was cancelled, or the client's
    /// own subscription ended — the dialog it may still be showing is not
    /// the one that decides. `dismissed` is required — the marker.
    PendingAskDismissed {
        /// The ask that is no longer this client's to answer.
        ask_id: AskId,
        /// The marker: always `true`, carried so the untagged reply
        /// discriminates this from every other shape.
        dismissed: bool,
    },
    /// The record-ask-answer verb's answer: the ask the daemon recorded
    /// the client's answer against — the first answer, because every
    /// later one is refused as an unknown-or-consumed id and answers
    /// [`Error`](Self::Error) instead. `recorded` is required — the
    /// marker.
    AskAnswerRecorded {
        /// The ask whose first answer this was.
        ask_id: AskId,
        /// The marker: always `true`, carried so the untagged reply
        /// discriminates this from every other shape.
        recorded: bool,
    },
    /// The ask admit's answer ([`AskAdmitOutcome`]): the ask's end, as a
    /// `ask`-tagged document no older reply shape can decode as.
    AskAdmit(AskAdmitOutcome),
    /// The registration succeeded: the allocated addresses and the box id
    /// the published row holds ([`RegisteredBox`]) — the reply the register
    /// verb answers with. The withdrawal never answers this: it has no id
    /// to hand back, and the addresses echo it has always answered with
    /// stays its answer ([`Addresses`](Self::Addresses)).
    ///
    /// First in the order on purpose. The reply is untagged and serde
    /// ignores a document's unknown fields, so a variant whose fields are
    /// a strict superset of another's must be tried before it: an
    /// id-carrying reply parsed as `Addresses` would silently drop the
    /// id, and the client would record no id for a box the host named. A
    /// reply that carries no `box_id` — from a daemon that predates ids —
    /// fails this variant and parses as `Addresses`: the registration
    /// succeeded, and the client simply records no id for the box.
    Registered(RegisteredBox),
    /// The verb succeeded: a withdrawal's echo of the pair the row went by,
    /// and a registration's answer on a daemon that predates box ids.
    Addresses(BoxAddresses),
    /// The verb failed: `error` is a sentence naming why, for the client to
    /// warn with.
    Error { error: String },
    /// The answerer-status read succeeded: the state of the machine's
    /// zone answerer as the daemon holds it ([`ZoneAnswererStatus`]).
    Status(ZoneAnswererStatus),
    /// The read-only row verb's answer for a live box: the row's switch
    /// address, its derived egress allow-list, and its declared and
    /// runtime-admitted ports ([`BoxRow`]).
    Row(BoxRow),
    /// The read-only row verb's answer for a name no live box holds: the
    /// name back, with `no_row` marking the shape, so a reader cannot
    /// mistake "the row is gone" for a parse failure. `no_row` is required
    /// — the marker that keeps this document from decoding as any other
    /// reply.
    NoRow {
        /// The name that was asked about.
        name: String,
        /// The marker: always `true`, carried so the untagged reply
        /// discriminates this from a live row's answer.
        no_row: bool,
    },
    /// A port report was recorded: the port and protocol the host now holds
    /// — the one reply both report verbs answer with, the withdrawal
    /// included, because a withdrawal's goal state holds even when the
    /// port was never admitted.
    PortRecorded {
        /// The port the report named.
        port: u16,
        /// The protocol the report named.
        proto: IpProto,
    },
    /// A release or release-cancel was answered: `acted` says whether the
    /// daemon did anything (false: it hosted no interim, or had no release
    /// pending), and `detail` is the sentence it logged.
    AnswererRelease {
        /// Whether the request changed anything.
        acted: bool,
        /// What the daemon did, as its log line said it.
        detail: String,
    },
}

/// The request for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    /// Out-of-band session config.
    pub config: SessionConfig,
    /// The build the caller expects the daemon to be. When set, the daemon
    /// compares it against its own version and fails the RPC with
    /// [`version_skew_message`] *before allocating anything*, so a skewed pair
    /// cannot leave a half-built session behind (#1251). `None` asserts
    /// nothing and behaves exactly as this RPC always has — which is what a
    /// client sends when the operator set [`SKEW_OVERRIDE_VAR`], since a
    /// daemon-side refusal is not something a client-side override could
    /// downgrade to a warning.
    ///
    /// Carried here rather than checked by a preceding [`GetVersion`] because
    /// this is the first RPC of the activation path, and that path must not
    /// pay a round trip for a check the create can make itself.
    ///
    /// A daemon that predates this field ignores it —
    /// [`CreateSessionRequest`] is not `deny_unknown_fields`, deliberately, so
    /// that older clients keep working — and is caught instead by the
    /// [`CreateSessionResponse::daemon_version`] it fails to echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub must_match_version: Option<String>,
}

/// The response for a [`CreateSession`] RPC: the allocated session.
///
/// The session's loadout is not composed yet — the returned id is
/// what the client names it by in the [`ConfigureLoadout`] that
/// follows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionResponse {
    /// Daemon-assigned session id.
    pub id: SessionId,
    /// The build this daemon runs, so a client can assert the pair matches
    /// without spending a round trip on [`GetVersion`]. `None` from a daemon
    /// that predates the field — see [`UNVERSIONED_DAEMON`] for why that is a
    /// skew rather than an unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_version: Option<String>,
    /// Why `<name>.local.min.internal` hostnames will not route, when they
    /// will not — see [`ListSessionsResponse::hostname_routing_unavailable`].
    ///
    /// Carried on the activation reply as well as the list because activation
    /// is where a user is about to rely on it, and the session comes up
    /// looking healthy either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_routing_unavailable: Option<String>,
    /// The port the host-side hostname proxy is serving on — see
    /// [`ListSessionsResponse::hostname_proxy_port`].
    ///
    /// Carried on the activation reply as well as the list for the same
    /// reason as `hostname_routing_unavailable`: activation is where the
    /// user is about to rely on the names this port routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_proxy_port: Option<u16>,
    /// The UDP port the box-zone answerer is serving on — see
    /// [`ListSessionsResponse::zone_answerer_port`].
    ///
    /// Carried on the activation reply as well as the list for the same
    /// reason as `hostname_proxy_port`: activation is where the user is
    /// about to point `HTTP(S)_PROXY` — and the host resolver — at this
    /// daemon's ports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_answerer_port: Option<u16>,
    /// Whether the daemon's session-start bind probe found the reserved local
    /// range absent — the interim verdict, true when this session is on the
    /// shared `127.0.0.1` interim rather than the range (NET-123).
    ///
    /// A client that reads `true` surfaces the naming advisory again
    /// (NET-122): a session on the interim is a fact nothing else shows.
    /// The interim ends when the range is installed on the host — on macOS
    /// the root-held boot step design §7.1 folds into the same advisory
    /// command, not yet part of the command the client renders.
    /// `false` from a daemon that predates
    /// the field is the safe read — nothing downstream is gated on it; the
    /// advisory a client prints from its own host-resolver detection is not,
    /// and the [`Self::daemon_version`] gate already refuses a daemon that
    /// old.
    #[serde(default)]
    pub interim_loopback: bool,
    /// Whether the serving daemon opted out of the deny-all egress default
    /// (NET-077). The rollout's one fact the client cannot know from its
    /// own build: the phase is a build-time constant both sides share
    /// ([`sessions::EGRESS_DEFAULT_PHASE`]), but the opt-out is set on the
    /// daemon alone. Carried here — on the reply the activation path
    /// already holds — so `min session activate` can keep its coming-change
    /// notice (NET-076) off a deployment that has already chosen to keep
    /// the shipped default: the notice's remedy names the very flag an
    /// opted-out daemon runs, and would tell it to do what it has done.
    ///
    /// `None` from a daemon that predates the field — and a daemon that
    /// predates it cannot have the opt-out flag either, so a client reading
    /// `None` prints the notice exactly as this reply's older readers did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_all_opt_out: Option<bool>,
    /// Whether this daemon's box-zone answerer is bound in its own namespace
    /// — see [`ListSessionsResponse::answerer_bound`] for what that fact
    /// does and does not say. Carried on the activation reply, beside the
    /// answerer's port it is the answerer's own half of, because activation
    /// is where the user is about to rely on the names the surface answers.
    #[serde(default)]
    pub answerer_bound: bool,
    /// The classifier advisory this host's verdict owes the session start
    /// (NET-079): `Some` only when both halves it is about are true — the
    /// daemon is not running inside a microVM, whose causes name its
    /// image's builder rather than anything the person starting a session
    /// could run, and the session is a host-address box, whose verdict is
    /// the one the host's cgroup tree decides — and that host cannot
    /// decide it per box, naming the cause in
    /// words, the state that leaves the box in — unenforced, except that
    /// a deny-all declaration is refused at placement while the probe
    /// that would decide it cannot be read — and the exact command that
    /// installs the
    /// classifier's privileged step only when that step is the cause that
    /// is missing, because a host that cannot confine a box is not
    /// cleared by installing anything. Spelled by the daemon, which is
    /// the one that read the host; printed by the client verbatim, and
    /// never a prompt — running the command (and any privilege prompt it
    /// carries) is the person's act, never the session start's: the start
    /// still hands the box the host's address and runs it unenforced, and
    /// only a deny-all declaration is refused later, at placement, while
    /// the probe that would decide it cannot be read.
    ///
    /// `None` from a host that decides per box: silence is that host's
    /// state, and a client reading `None` prints exactly what it printed
    /// before this field. `None` from a daemon that predates it reads the
    /// same way — nothing said, so nothing to print.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifier_advisory: Option<String>,
    /// The per-box egress enforcement this host's verdict gives a
    /// host-address session (NET-079): `per_box` when this host can decide
    /// a box's verdict on a classifier leaf of its own, `none` when it
    /// cannot and the box runs with the host's address and no verdict of
    /// its own. Spelled in the machine spelling the daemon's log line and
    /// the other replies use, so a script reads the state as data and not
    /// by parsing the prose around it. `None` for a session that is not
    /// host-address: an own-address or none box's verdict is decided on
    /// address leases, never on the host's cgroup tree.
    ///
    /// The same derivation the listing and the policy read answer through,
    /// with the same refusal gate: the session this create is minting has
    /// no launch record yet, so the daemon's one classifier fact is the
    /// best either half of it knows, and the box the gate refuses — a
    /// deny-all host-address box the host cannot enforce, the one its own
    /// launch would refuse — carries no enforcement value anywhere.
    /// Never recorded at create: only a launch writes the box's own
    /// outcome. `None` from a daemon that
    /// predates the field is that daemon's silence, never a decided
    /// `per_box`: a client that reads nothing here claims nothing from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip_enforcement: Option<String>,
}

impl OneshotSshRpc for CreateSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "CreateSession");
    type Request<'a> = CreateSessionRequest;
    type Response = Errorable<CreateSessionResponse>;
}

/// An RPC to compose a session's loadout, completing its create flow.
///
/// Split from [`CreateSession`] because the composer reads the
/// project config out of the session's *daemon-side workspace*, which
/// only holds the project files once the client has streamed them up
/// via `WorkspaceFilesTarZst` — the record's `project_path` is a path
/// on the client's machine, which the daemon generally can't read.
/// So the client creates the session, populates its workspace, and
/// only then configures the loadout.
pub struct ConfigureLoadout;

/// The request for a [`ConfigureLoadout`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigureLoadoutRequest {
    /// The session to configure, from [`CreateSessionResponse::id`].
    pub session_id: SessionId,
    /// Client-side Phase 1 contribution. Defaulted (empty) by
    /// callers that aren't composing a session, which take the
    /// empty-contribution fast path to
    /// [`ConfigureLoadoutResponse::Materialized`].
    #[serde(default)]
    pub contribution: sessions::wire::request::WireContribution,
}

/// The response for a [`ConfigureLoadout`] RPC.
///
/// Both variants are part of the Phase 2 flow and reachable on the
/// wire: `Materialized` when the daemon's composer finalizes in one
/// shot (the session record is now
/// [`Materializing`](sessions::SessionStatus::Materializing), not
/// yet `Active`), `Pending` when it collects items the client must
/// gate before composition completes (the client follows up via
/// `SubmitVerdict`).
///
/// In both `Materialized` branches the client still has to upload
/// patches and call `FinalizeSession` before the session is
/// attachable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigureLoadoutResponse {
    /// No items need user gating; composition is complete and the
    /// session record has advanced to
    /// [`Materializing`](sessions::SessionStatus::Materializing).
    /// The client still has to upload the composition's patches
    /// and call `FinalizeSession` before the session becomes
    /// attachable.
    Materialized,
    /// Items need client-side gating. The session stays in
    /// [`Pending`](sessions::SessionStatus::Pending); the client
    /// follows up with `SubmitVerdict` carrying the same id.
    Pending {
        /// Pending items the client must gate.
        response: sessions::wire::request::ContributionResponse,
    },
}

impl OneshotSshRpc for ConfigureLoadout {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "ConfigureLoadout");
    type Request<'a> = ConfigureLoadoutRequest;
    type Response = Errorable<ConfigureLoadoutResponse>;
}

/// An RPC to promote a `Materializing` session to `Active`.
///
/// The client uploads composition patches to the daemon via
/// `WorkspacePatchesTarZst`, then calls this RPC to signal "every
/// side-channel upload is in and I'm ready for the session to be
/// attachable." The daemon checks for the patches-ready marker
/// under `<workspace>/patches/` and refuses to finalize if the
/// upload never completed.
///
/// Idempotent: calling on an already-`Active` session returns
/// success. Refused with `InvalidInput` on `Pending` sessions
/// (configure the loadout first) or `Materializing` sessions
/// missing the patches marker.
pub struct FinalizeSession;

/// The request for a [`FinalizeSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeSessionRequest {
    /// The session to finalize.
    pub session_id: SessionId,
    /// The client decodes [`FinalizeSessionResponse::shared_port_collisions`],
    /// so the daemon may fill it. [`FinalizeSessionResponse`] is
    /// `deny_unknown_fields`: a client built before that field would refuse a
    /// reply carrying it and abort the activation, so the daemon reports the
    /// list only to a client that asks. Serde-defaulted, so an older client's
    /// request reads as `false`, and omitted when `false`, so the request an
    /// older daemon reads is unchanged — it ignores the key either way.
    #[serde(default, skip_serializing_if = "is_false")]
    pub report_shared_port_collisions: bool,
}

/// Serde helper: omit a `false` request flag, so the request matches the one
/// a client that predates the flag sends.
fn is_false(v: &bool) -> bool {
    !*v
}

/// The response for a [`FinalizeSession`] RPC.
///
/// Carries what the session's `on_activate` hooks did, so the client can
/// report it: a hook that ran is otherwise invisible to the user, since
/// activation is headless and its output goes to the daemon log. A
/// *failing* activate hook fails the whole RPC instead, so anything
/// listed here succeeded.
/// `deny_unknown_fields` is load-bearing, not tidiness. [`Errorable`] is
/// `#[serde(untagged)]`, so it tries `Ok(S)` first and takes it if it
/// parses — and a struct whose every field is optional parses from *any*
/// object, including `{"error": "..."}`. Without this, every failed
/// finalize would decode as a successful one with no hooks.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalizeSessionResponse {
    /// One entry per `on_activate` hook that ran, in the order they ran.
    /// Serde-defaulted so a daemon that predates the field still answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activate_hooks: Vec<RanHook>,
    /// True when the finalize's package check stepped aside — its deadline
    /// expired, or the session context or package graph could not be
    /// evaluated — rather than refusing an unknown package. The session
    /// still activates; the client warns so the operator knows unknown
    /// names will surface at first exec. Serde-defaulted and omitted when
    /// false so a daemon that predates the field still answers to an older
    /// client.
    #[serde(default, skip_serializing_if = "package_check_skipped_is_false")]
    pub package_check_skipped: bool,
    /// One entry per declared ingress port another box at the same shared
    /// address already holds, so this box's attach yields it (first-come):
    /// the port, and the box that holds it. The box still activates and
    /// serves its other ports; the client warns so the operator knows the
    /// declared mapping is served by the holding box, not this one.
    /// Serde-defaulted, so a reply from a daemon that predates the field
    /// decodes as empty; filled only when the request set
    /// [`FinalizeSessionRequest::report_shared_port_collisions`], because
    /// this struct is `deny_unknown_fields` and a client that predates the
    /// field would refuse the reply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_port_collisions: Vec<SharedPortCollision>,
}

/// A declared ingress port the box yields because another box at the same
/// shared loopback address holds it, as the finalize reply reports it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedPortCollision {
    /// The port both boxes declared and the holding box serves.
    pub port: u16,
    /// The holding box's name, as the warning names it.
    pub held_by: String,
}

/// Serde helper: omit [`FinalizeSessionResponse::package_check_skipped`]
/// when it is `false`, so the common success payload is unchanged for
/// clients that predate the field.
fn package_check_skipped_is_false(v: &bool) -> bool {
    !*v
}

/// One hook that ran, as reported back to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RanHook {
    /// Where it was declared, e.g. ``user loadout `dev` ``.
    pub declared_by: String,
    /// The hook's own description, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Tail of the hook's captured stdout and stderr, when it wrote
    /// any. Serde-defaulted so a daemon that predates the field still
    /// answers.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub output: String,
}

impl OneshotSshRpc for FinalizeSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "FinalizeSession");
    type Request<'a> = FinalizeSessionRequest;
    type Response = Errorable<FinalizeSessionResponse>;
}

/// An RPC to rename an existing session.
pub struct RenameSession;

/// The request for a [`RenameSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameSessionRequest {
    pub id: SessionId,
    pub new_name: String,
}

/// The response for a [`RenameSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RenameSessionResponse;

impl OneshotSshRpc for RenameSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "RenameSession");
    type Request<'a> = RenameSessionRequest;
    type Response = Errorable<RenameSessionResponse>;
}

/// An RPC to destroy an existing session.
pub struct DestroySession;

/// The request for a [`DestroySession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DestroySessionRequest {
    pub id: SessionId,
}

/// The response for a [`DestroySession`] RPC.
///
/// Carries the session's failed `on_destroy` hooks, so the client can
/// report them: a failing destroy hook does not stop the destroy, and
/// without this the only trace is the daemon log.
///
/// This was a unit struct, which encodes as `null`. It still does when
/// no hook failed, so a client and a daemon either side of the change
/// keep agreeing on a clean destroy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    from = "DestroySessionResponseWire",
    into = "DestroySessionResponseWire"
)]
pub struct DestroySessionResponse {
    /// One line per `on_destroy` hook that did not succeed: where it was
    /// declared and what happened, followed by its captured output tail
    /// on the lines after, when there is any.
    pub hook_failures: Vec<String>,
}

/// [`DestroySessionResponse`] on the wire: `null` (the old unit shape)
/// or an object.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum DestroySessionResponseWire {
    Unit(()),
    Fields(DestroySessionResponseFields),
}

/// `deny_unknown_fields` for the same reason as on
/// [`FinalizeSessionResponse`]: without it, `{"error": "..."}` parses as
/// a successful destroy with no failures.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DestroySessionResponseFields {
    #[serde(default)]
    hook_failures: Vec<String>,
}

impl From<DestroySessionResponseWire> for DestroySessionResponse {
    fn from(wire: DestroySessionResponseWire) -> Self {
        match wire {
            DestroySessionResponseWire::Unit(()) => Self::default(),
            DestroySessionResponseWire::Fields(f) => Self {
                hook_failures: f.hook_failures,
            },
        }
    }
}

impl From<DestroySessionResponse> for DestroySessionResponseWire {
    fn from(resp: DestroySessionResponse) -> Self {
        if resp.hook_failures.is_empty() {
            Self::Unit(())
        } else {
            Self::Fields(DestroySessionResponseFields {
                hook_failures: resp.hook_failures,
            })
        }
    }
}

impl OneshotSshRpc for DestroySession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "DestroySession");
    type Request<'a> = DestroySessionRequest;
    type Response = Errorable<DestroySessionResponse>;
}

/// An RPC to read what work is at risk in a session's workspace — what a
/// destroy would permanently lose. Serves the destroy-confirm listing in
/// `min session destroy`.
pub struct SessionDelta;

/// The request for a [`SessionDelta`] RPC. By id only: every caller has
/// already resolved the session record (destroy must, to name what it
/// deletes), so there is no name-lookup arm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDeltaRequest {
    pub id: SessionId,
}

/// The response for a [`SessionDelta`] RPC: the session's at-risk state, in
/// decreasing order of precision. Row strings render as `A <path>` /
/// `M <path>` / `D <path>`, sorted by path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionDeltaResponse {
    /// The workspace is a git repository and git answered: what is at risk
    /// is precisely the uncommitted work and the unpushed commits. Both
    /// empty/zero means the session is proven clean — everything is
    /// committed and pushed, and a destroy loses nothing.
    Vcs {
        /// One row per file with uncommitted changes (untracked renders
        /// as `A`).
        uncommitted: Vec<String>,
        /// Commits on any branch that no remote has.
        unpushed_commits: u64,
    },
    /// No usable VCS state (no root `.git`, git missing or failing): the
    /// rows are the files that differ from the activation-time baseline,
    /// which may include work that was committed during the session. An
    /// empty vec means nothing changed since activation.
    ChangedSinceActivation { rows: Vec<String> },
    /// Neither VCS state nor a baseline delta could be computed — no such
    /// session, no running host, no baseline, or the bounded computation
    /// failed. The caller cannot claim anything about the workspace.
    Unavailable,
}

impl OneshotSshRpc for SessionDelta {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SessionDelta");
    type Request<'a> = SessionDeltaRequest;
    type Response = SessionDeltaResponse;
}

/// An RPC asking the daemon to shut down its session manager so the process
/// can terminate gracefully.
pub struct Shutdown;

/// The request for a [`Shutdown`] RPC.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShutdownRequest {
    /// When `true`, live sessions are destroyed and the daemon shuts down
    /// regardless. When `false`, the daemon refuses to shut down if any
    /// session is still live, answering with [`ShutdownResponse::SessionsLive`].
    #[serde(default)]
    pub force: bool,
}

/// The response for a [`Shutdown`] RPC.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShutdownResponse {
    /// The daemon accepted the request: the session manager is shutting down
    /// and rejecting further work.
    ShuttingDown,
    /// The daemon refused: live sessions exist and `force` was not set. No
    /// state changed; the caller may retry with `force = true`.
    SessionsLive,
}

impl OneshotSshRpc for Shutdown {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "Shutdown");
    type Request<'a> = ShutdownRequest;
    type Response = ShutdownResponse;
}

/// Resume a `Pending` session with the client's per-item
/// [`ContributionVerdict`]. The daemon promotes the record
/// `Pending → Materializing` and replies with
/// [`SessionStep::Materialized`](sessions::wire::request::SessionStep::Materialized);
/// the client still has to upload patches and call
/// `FinalizeSession` before the session is attachable.
/// A `Fault` reply carries a structured
/// [`WireError`](sessions::wire::errors::WireError) —
/// `UnknownSessionId` for a verdict against no stashed session,
/// `WrongState` if the record isn't `Pending`, or an
/// `InvalidContribution` / `Internal` reflecting a failed
/// `resume_from_verdict`.
pub struct SubmitVerdict;

impl OneshotSshRpc for SubmitVerdict {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SubmitVerdict");
    type Request<'a> = sessions::wire::request::ContributionVerdict;
    type Response = Errorable<sessions::wire::request::SessionStep>;
}

/// Abort a `Pending` session before its `SubmitVerdict`.
///
/// Called by the client when its Phase 3 gating produces no verdict —
/// user cancelled at a prompt, policy hooks returned `Abort`, or an
/// upstream resolution / expansion failed. Drops the daemon's stash
/// entry and deletes the on-disk `Pending` record so the session name
/// is freed and the stash slot isn't burned.
///
/// Refuses non-`Pending` records: an unknown id or a record already
/// promoted to `Active` (destroy that via [`DestroySession`]) surfaces
/// as an `Errorable::Err`.
pub struct AbortSession;

/// The request for an [`AbortSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbortSessionRequest {
    pub id: SessionId,
}

/// The response for an [`AbortSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbortSessionResponse;

impl OneshotSshRpc for AbortSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "AbortSession");
    type Request<'a> = AbortSessionRequest;
    type Response = Errorable<AbortSessionResponse>;
}

// ---------------------------------------------------------------------------
// Networking policy types (Unit 2: egress, ingress, dynamic port mapping).
//
// `PortMapping`, `EgressPolicy`, `IngressPolicy`, `SessionPolicy`, and the
// effective halves (`EffectiveEgress`, `EffectiveSessionPolicy`) are defined
// in `sessions` and re-exported above, so the only live per-session store
// (`sessions::Record`) can carry the policy configured at launch without a
// `sessions` → `minimald-rpc` dependency cycle. The RPC method types below
// stay here, where the wire contract lives.
// ---------------------------------------------------------------------------

/// An RPC to read the effective networking policy for a session (R2.6).
pub struct GetSessionPolicy;

/// Request for the [`GetSessionPolicy`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionPolicyRequest {
    Name(String),
    Id(SessionId),
}

impl OneshotSshRpc for GetSessionPolicy {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionPolicy");
    type Request<'a> = GetSessionPolicyRequest;
    type Response = Errorable<SessionPolicy>;
}

/// An RPC to read the *effective* networking policy for a session: the same
/// record [`GetSessionPolicy`] serves, with its egress half resolved to what
/// the gate enforces (NET-075) — the answer `min session policy` renders.
///
/// A separate response rather than a field on [`SessionPolicy`], so the
/// strict declaration a client reads back stays exactly what the box was
/// launched with: the deny-all default (NET-074) reaches the client as
/// `deny_all` in this response without rewriting the record. The daemon
/// answers it, not the client, because the inputs are the daemon's own
/// facts — the rollout phase its build ships and its opt-out flag
/// (NET-077) — which no client can know.
pub struct GetEffectiveSessionPolicy;

/// Request for the [`GetEffectiveSessionPolicy`] RPC: the same lookup as
/// [`GetSessionPolicyRequest`], over the same record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetEffectiveSessionPolicyRequest {
    Name(String),
    Id(SessionId),
}

impl OneshotSshRpc for GetEffectiveSessionPolicy {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetEffectiveSessionPolicy");
    type Request<'a> = GetEffectiveSessionPolicyRequest;
    type Response = Errorable<EffectiveSessionPolicy>;
}

/// One live dynamic-ingress mapping (NET-044): a port a process inside the box
/// published at runtime with the box's own `min net expose`, held from the
/// publish until the box stops.
///
/// Not a [`PortMapping`]: a declaration names what a box *may* publish, and
/// this is what it *did* — the mapping's `local` is a full `host:port` on the
/// box's own published address (NET-010), not an external port number to bind
/// wherever the publish surface happens to stand, so the row a client renders
/// can name the address a connection actually reaches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveMapping {
    /// The host-side `host:port` the forward is published on, spelled as the
    /// switch bound it.
    pub local: String,
    /// The port inside the box the forward delivers to.
    pub internal_port: u16,
    /// The transport the forward carries.
    pub proto: IpProto,
    /// Whether the box's own relay gate has not admitted the port. A current
    /// daemon admits a runtime publish at the gate in the same step it binds
    /// the forward (NET-044), so it always answers `Some(false)`. Only a
    /// daemon from before that change answers `Some(true)`: its gate admitted
    /// only the declared ports, so a connection to such a row's `local` was
    /// answered by the relay, not by the box.
    ///
    /// An `Option`, defaulted on the wire, so a reply from a daemon older
    /// than the field — one that carries no `pending` key — still decodes,
    /// as `None`: the row's state reads as *unknown*, and never as the
    /// reachable reading a missing key must not default itself into. Both
    /// renderings `min session policy` writes spell that (`unknown` in the
    /// text row, `null` in the JSON document); a daemon that does carry the
    /// field answers `Some(true)` or `Some(false)`, and only those.
    ///
    /// Deprecated: daemons from the gate-admits-exposed-ports change onward
    /// always send `Some(false)`, so the field carries information only from
    /// an older daemon. Remove it, and the client's `pending` rendering, when
    /// the support window for those older daemons ends.
    #[serde(default)]
    pub pending: Option<bool>,
}

impl LiveMapping {
    /// The `host:port` pair a client renders, split — `None` when `local` is
    /// not a `host:port` pair with a numeric port, a shape the daemon never
    /// publishes.
    #[must_use]
    pub fn host_port(&self) -> Option<(&str, u16)> {
        let (host, port) = self.local.rsplit_once(':')?;
        Some((host, port.parse().ok()?))
    }
}

/// An RPC to read the live dynamic-ingress mappings a session's box published
/// at runtime (NET-044) — the rows `min session policy` lists beside the
/// declaration, which is what makes a publish visible rather than only
/// permitted.
///
/// A separate response rather than a field on [`EffectiveSessionPolicy`], for
/// the same reason the effective halves are separate from the strict
/// [`SessionPolicy`] at all: the declaration is a fact about the launch, and
/// these are facts about the running box. They are also the live actor's own
/// state — a box that is not running holds none — so this resolves the session
/// where [`GetSessionPolicy`] and [`GetEffectiveSessionPolicy`] read the
/// record.
pub struct GetLiveIngress;

/// Request for the [`GetLiveIngress`] RPC: the same lookup as
/// [`GetSessionPolicyRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetLiveIngressRequest {
    Name(String),
    Id(SessionId),
}

impl OneshotSshRpc for GetLiveIngress {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetLiveIngress");
    type Request<'a> = GetLiveIngressRequest;
    type Response = Errorable<Vec<LiveMapping>>;
}

/// An RPC to read the runtime facts about a session a policy render wants
/// beside its rules (NET-079): the per-box egress enforcement the session's
/// box actually runs under — the same state [`ListSessionsEntry::host_ip_enforcement`]
/// and the create response answer over, served the same way.
///
/// A separate reply rather than a field on [`EffectiveSessionPolicy`] because
/// that policy struct is `deny_unknown_fields`: a strict struct an older `min`
/// has no field for rejects a new key rather than ignoring it, so a fact that
/// did not exist when that client was built must ride its own reply, the same
/// shape live ingress takes ([`GetLiveIngress`]) — an older client that cannot
/// ask for it never sees it, and a newer one degrades to silence rather than
/// failing to read the rules at all. The facts are the daemon's to answer,
/// because the enforcement is decided on the host's cgroup tree and recorded
/// by the daemon at the box's own launch: no client can read either.
pub struct GetSessionRuntimeFacts;

/// Request for the [`GetSessionRuntimeFacts`] RPC: the same lookup as
/// [`GetEffectiveSessionPolicyRequest`], over the same record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionRuntimeFactsRequest {
    Name(String),
    Id(SessionId),
}

/// The runtime facts [`GetSessionRuntimeFacts`] answers with.
///
/// Not `deny_unknown_fields`: runtime facts grow, and a client built before
/// a later fact must still read the ones it knows, so an unknown key is
/// ignored. What keeps the untagged [`Errorable`] honest instead is the
/// required `id`: serde reads a missing `Option` as `None`, so an
/// all-optional struct would parse *any* object, the daemon's
/// `{"error": "..."}` included, as a facts reply with nothing to report. A
/// field the error object never carries makes that reply fail the `Ok(S)`
/// arm and fall through to `Err`, without refusing a key it does not know.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRuntimeFacts {
    /// The session these facts are about: the record the daemon read them
    /// from. Required, so the daemon's error reply never decodes as facts.
    pub id: SessionId,
    /// The per-box egress enforcement the session's box actually runs under
    /// (NET-079): the box's own launch record —
    /// [`Record::host_ip_enforcement`](sessions::Record) — lowered to `none`
    /// when the host can no longer decide per box and never raised above it,
    /// and the host's own state only while the session's box has not
    /// launched. `None` for a session that is not host-address, for a
    /// host-address box the classifier refused, and when the record could not
    /// be read back — the same states
    /// [`ListSessionsEntry::host_ip_enforcement`] names.
    pub host_ip_enforcement: Option<HostIpEnforcement>,
    /// The permitted listening ports the box's listen watcher left
    /// unpublished because their allow's audit record could not be written
    /// (NET-046 fails closed), in port order. A watcher-driven publish has
    /// no caller to answer, so this is where its failure reaches the user:
    /// `min session policy` prints a warning per port. Absent when empty,
    /// and absent from a daemon that predates the field — both read as
    /// nothing to warn about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unaudited_listen_ports: Vec<u16>,
    /// The daemon's audit log path the warnings for
    /// [`Self::unaudited_listen_ports`] name. Set only beside a non-empty
    /// list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_log: Option<String>,
    /// The declared ingress ports this box's attach yields because another
    /// box at the same shared loopback address holds them (first-come):
    /// one entry per port, naming the holding box. Serde-defaulted and
    /// omitted when empty, so a daemon that predates the field still
    /// answers to an older client; a client that cannot ask reads the
    /// same silence an empty list reads as.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_port_collisions: Vec<SharedPortCollision>,
}

impl OneshotSshRpc for GetSessionRuntimeFacts {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionRuntimeFacts");
    type Request<'a> = GetSessionRuntimeFactsRequest;
    type Response = Errorable<SessionRuntimeFacts>;
}

/// An RPC to list the lifecycle hooks composed into a session, and where
/// each was declared.
///
/// Served from the session's persisted composition snapshot rather than
/// live state, so it answers after a daemon restart and for a session
/// nobody is attached to. The snapshot holds only the hooks that
/// survived the user-policy gate, so what this returns is what will
/// actually run — not what the loadouts and project asked for.
pub struct GetSessionHooks;

/// Request for the [`GetSessionHooks`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GetSessionHooksRequest {
    Name(String),
    Id(SessionId),
}

impl OneshotSshRpc for GetSessionHooks {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionHooks");
    type Request<'a> = GetSessionHooksRequest;
    /// Each hook paired with the loadout or project that declared it, in
    /// setup order (project first, then loadouts). Teardown order is the
    /// reverse; the caller renders whichever it needs.
    type Response = Errorable<Vec<sessions::wire::primitives::WireProvenancedHook>>;
}

/// An RPC for a process inside a PTask to request a dynamic ingress port
/// mapping at runtime (R2.4).
pub struct DynamicPortMap;

/// Request for the [`DynamicPortMap`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicPortMapRequest {
    pub id: SessionId,
    pub external_port: u16,
    pub internal_port: u16,
    pub proto: IpProto,
}

impl DynamicPortMapRequest {
    pub fn new(id: SessionId, external_port: u16, internal_port: u16, proto: IpProto) -> Self {
        Self {
            id,
            external_port,
            internal_port,
            proto,
        }
    }
}

/// Response for the [`DynamicPortMap`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DynamicPortMapResponse;

impl OneshotSshRpc for DynamicPortMap {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "DynamicPortMap");
    type Request<'a> = DynamicPortMapRequest;
    type Response = Errorable<DynamicPortMapResponse>;
}

// ---------------------------------------------------------------------------
// WireGuard mesh status (Unit 4: R4.6).
//
// These types are the wire contract for `minimal mesh status` and carry no
// WireGuard dependency, so they compile in every build regardless of the
// daemon's `networking-wg` feature. A daemon built without the feature answers
// with `configured = false`.
// ---------------------------------------------------------------------------

/// One peer's entry in a [`MeshStatus`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshPeerStatus {
    /// The peer's configured name.
    pub name: String,
    /// The peer's WireGuard public key, base64-encoded.
    pub public_key: String,
    /// The peer's UDP endpoint (`host:port`), if known.
    pub endpoint: Option<String>,
    /// Seconds since the last completed handshake with this peer, or `None` if
    /// no handshake has completed.
    pub last_handshake_secs: Option<u64>,
}

impl MeshPeerStatus {
    /// Builds a peer status entry. The struct is `#[non_exhaustive]`, so the
    /// daemon (a different crate) constructs it through this constructor.
    #[must_use]
    pub fn new(
        name: String,
        public_key: String,
        endpoint: Option<String>,
        last_handshake_secs: Option<u64>,
    ) -> Self {
        Self {
            name,
            public_key,
            endpoint,
            last_handshake_secs,
        }
    }
}

/// The current WireGuard mesh state, as returned by [`GetMeshStatus`] (R4.6).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeshStatus {
    /// Whether a WireGuard mesh is configured and running. `false` when the
    /// daemon was built without the `networking-wg` feature or no mesh config
    /// is present.
    pub configured: bool,
    /// This node's WireGuard public key, base64-encoded; `None` when not
    /// configured.
    pub own_public_key: Option<String>,
    /// The subnets this node advertises to the mesh (subnet-router model),
    /// rendered as CIDR strings.
    pub advertised_subnets: Vec<String>,
    /// The configured peers and their last-handshake state.
    pub peers: Vec<MeshPeerStatus>,
}

impl MeshStatus {
    /// Builds a configured mesh status. The struct is `#[non_exhaustive]`, so
    /// the daemon constructs it through this constructor.
    #[must_use]
    pub fn new(
        own_public_key: String,
        advertised_subnets: Vec<String>,
        peers: Vec<MeshPeerStatus>,
    ) -> Self {
        Self {
            configured: true,
            own_public_key: Some(own_public_key),
            advertised_subnets,
            peers,
        }
    }

    /// The status reported when no mesh is configured, or the daemon was built
    /// without the `networking-wg` feature.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self {
            configured: false,
            own_public_key: None,
            advertised_subnets: Vec::new(),
            peers: Vec::new(),
        }
    }
}

/// An RPC to read the current WireGuard mesh status (R4.6).
pub struct GetMeshStatus;

impl OneshotSshRpc for GetMeshStatus {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetMeshStatus");
    type Request<'a> = ();
    type Response = MeshStatus;
}

// ---------------------------------------------------------------------------
// Diagnostic bundle (`min bug`).
// ---------------------------------------------------------------------------

/// Streaming RPC subsystem: the daemon's contribution to a `min bug`
/// diagnostic bundle.
///
/// Not an [`OneshotSshRpc`]: the client writes one JSON-encoded
/// [`DiagBundleRequest`] and half-closes, then the daemon streams back a
/// zstd-compressed tar archive of its diagnostic bundle and closes. Errors hit
/// before streaming starts are relayed over extended-data stream 1, so a client
/// that reads zero payload bytes should surface the extended data as the
/// failure reason.
///
/// Served identically by the native Linux minimald and the in-VM minimald
/// behind the minvmd bridge — the archive's `meta.json` says which one
/// answered.
pub const DIAG_BUNDLE_SUBSYSTEM: &str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "DiagBundleTarZst");

/// Request body for [`DIAG_BUNDLE_SUBSYSTEM`].
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiagBundleRequest {
    /// Per-log-file tail cap in bytes; `0` means the daemon's default. The
    /// daemon clamps this to its own ceiling — the value is caller-controlled.
    #[serde(default)]
    pub log_tail_bytes: u64,
    /// Include the recursive state-dir listing (names/sizes only).
    #[serde(default = "default_true")]
    pub include_state_listing: bool,
}

impl Default for DiagBundleRequest {
    fn default() -> Self {
        Self {
            log_tail_bytes: 0,
            include_state_listing: true,
        }
    }
}

/// The type is `#[non_exhaustive]`, so other crates cannot write a struct
/// literal for it; these are how a client departs from the defaults.
impl DiagBundleRequest {
    #[must_use]
    pub fn with_log_tail_bytes(mut self, bytes: u64) -> Self {
        self.log_tail_bytes = bytes;
        self
    }

    #[must_use]
    pub fn with_state_listing(mut self, include: bool) -> Self {
        self.include_state_listing = include;
        self
    }
}

fn default_true() -> bool {
    true
}

/// Reclaim the daemon's local cache, streaming progress.
///
/// Not an [`OneshotSshRpc`]: the client writes one JSON-encoded
/// [`CleanCacheRequest`] (an empty body asks for the daemon's defaults) and
/// half-closes, then the daemon streams back one JSON-encoded
/// [`CleanCacheUpdate`] per line — a `Removed` for each thing reclaimed, then
/// exactly one terminal `Done` or `Failed` — and closes.
pub const CLEAN_CACHE_SUBSYSTEM: &str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "CleanCache");

/// Request body for [`CLEAN_CACHE_SUBSYSTEM`].
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanCacheRequest {
    /// Only reclaim cache entries unread for at least this many seconds; `0`
    /// means the daemon's default. Note that a small value is honored as
    /// given — the daemon holds back what its sessions need, not what is
    /// merely recent.
    #[serde(default)]
    pub older_than_secs: u64,
}

/// The type is `#[non_exhaustive]`, so other crates cannot write a struct
/// literal for it; this is how a client departs from the defaults.
impl CleanCacheRequest {
    #[must_use]
    pub fn with_older_than_secs(mut self, secs: u64) -> Self {
        self.older_than_secs = secs;
        self
    }
}

/// One line of a [`CLEAN_CACHE_SUBSYSTEM`] response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CleanCacheUpdate {
    /// Something was reclaimed. `detail` is the daemon's own rendering of it,
    /// so every transport reports a clean identically; it is for humans, not
    /// for parsing.
    Removed { detail: String },
    /// Terminal: the clean finished, having removed this many cache entries
    /// and leftover execution directories.
    Done { entries: usize, dirs: usize },
    /// Terminal: the clean ran and failed. Nothing, some, or all of the
    /// reclaimable set may have gone before it stopped.
    Failed { error: String },
}

impl CleanCacheUpdate {
    /// Whether this update ends the stream.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done { .. } | Self::Failed { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::wire::request::{ContributionResponse, WireContribution};

    /// A failed finalize must decode as an error, not as a success with
    /// nothing in it.
    ///
    /// [`Errorable`] is `#[serde(untagged)]`, so it takes `Ok(S)` if `S`
    /// parses at all — and a response whose fields are all optional
    /// parses from any object, an error payload included. Adding
    /// `activate_hooks` reopened exactly that hole, and the symptom is
    /// silent: every activation, including a failing one, reads as
    /// successful. `deny_unknown_fields` is what closes it, and this is
    /// what keeps it closed.
    #[test]
    fn a_finalize_error_does_not_decode_as_a_successful_finalize() {
        let err: Errorable<FinalizeSessionResponse> =
            serde_json_lenient::from_str(r#"{"error":"activation hook failed"}"#)
                .expect("an error payload must decode");
        match err {
            Errorable::Err { error } => assert!(error.contains("activation hook failed")),
            Errorable::Ok(ok) => {
                panic!("an error decoded as success: {ok:?}")
            }
        }

        // The success shapes still decode: with hooks, and without.
        let bare: Errorable<FinalizeSessionResponse> =
            serde_json_lenient::from_str("{}").expect("an empty success must decode");
        assert_eq!(bare, Errorable::Ok(FinalizeSessionResponse::default()));
        let with_hooks: Errorable<FinalizeSessionResponse> = serde_json_lenient::from_str(
            r#"{"activate_hooks":[{"declared_by":"user loadout `dev`"}]}"#,
        )
        .expect("a populated success must decode");
        match with_hooks {
            Errorable::Ok(ok) => {
                assert_eq!(ok.activate_hooks.len(), 1);
                assert_eq!(ok.activate_hooks[0].declared_by, "user loadout `dev`");
            }
            Errorable::Err { error } => panic!("a success decoded as an error: {error}"),
        }
    }

    /// A hook's captured output must cross the wire, so the client can
    /// show what the hook said rather than only its author-supplied
    /// description.
    #[test]
    fn a_ran_hook_carries_its_captured_output() {
        let resp = FinalizeSessionResponse {
            activate_hooks: vec![RanHook {
                declared_by: "user loadout `dev`".to_string(),
                description: Some("emit to stdout and stderr".to_string()),
                output: "HOOK_STDOUT_VISIBLE\nHOOK_STDERR_VISIBLE\n".to_string(),
            }],
            ..Default::default()
        };
        let wire = serde_json_lenient::to_string(&resp).expect("must serialize");
        let back: FinalizeSessionResponse =
            serde_json_lenient::from_str(&wire).expect("must decode");
        assert_eq!(back, resp);
        assert_eq!(
            back.activate_hooks[0].output,
            "HOOK_STDOUT_VISIBLE\nHOOK_STDERR_VISIBLE\n"
        );

        // A daemon predating the field still decodes, with empty output.
        let old: Errorable<FinalizeSessionResponse> = serde_json_lenient::from_str(
            r#"{"activate_hooks":[{"declared_by":"user loadout `dev`"}]}"#,
        )
        .expect("a field-less hook must decode");
        match old {
            Errorable::Ok(ok) => assert!(ok.activate_hooks[0].output.is_empty()),
            Errorable::Err { error } => panic!("a success decoded as an error: {error}"),
        }
    }

    /// `package_check_skipped` is omitted from the wire when false, so a
    /// client that predates the field still decodes the common success
    /// payload; when true it is present so the client can warn.
    #[test]
    fn package_check_skipped_is_omitted_when_false() {
        let wire = serde_json_lenient::to_string(&FinalizeSessionResponse::default())
            .expect("must serialize");
        assert!(
            !wire.contains("package_check_skipped"),
            "a false skip must not be serialized, got {wire:?}"
        );

        let skipped = FinalizeSessionResponse {
            package_check_skipped: true,
            ..Default::default()
        };
        let wire = serde_json_lenient::to_string(&skipped).expect("must serialize");
        assert!(
            wire.contains("package_check_skipped"),
            "a true skip must be serialized, got {wire:?}"
        );
        let back: FinalizeSessionResponse =
            serde_json_lenient::from_str(&wire).expect("must decode");
        assert!(back.package_check_skipped);
    }

    /// `shared_port_collisions` is omitted from the wire when empty, so a
    /// client that predates the field still decodes the common success
    /// payload; when a port was yielded it is present, naming the port and
    /// the box that holds it so the client can warn.
    #[test]
    fn shared_port_collisions_are_omitted_when_empty() {
        let wire = serde_json_lenient::to_string(&FinalizeSessionResponse::default())
            .expect("must serialize");
        assert!(
            !wire.contains("shared_port_collisions"),
            "an empty collision list must not be serialized, got {wire:?}"
        );

        let yielded = FinalizeSessionResponse {
            shared_port_collisions: vec![SharedPortCollision {
                port: 8080,
                held_by: "first.min.internal".to_string(),
            }],
            ..Default::default()
        };
        let wire = serde_json_lenient::to_string(&yielded).expect("must serialize");
        assert!(
            wire.contains("shared_port_collisions"),
            "a yielded port must be serialized, got {wire:?}"
        );
        let back: FinalizeSessionResponse =
            serde_json_lenient::from_str(&wire).expect("must decode");
        assert_eq!(
            back.shared_port_collisions,
            vec![SharedPortCollision {
                port: 8080,
                held_by: "first.min.internal".to_string(),
            }],
            "the collision list must round-trip"
        );
    }

    /// A client and a daemon on either side of the
    /// `report_shared_port_collisions` flag still finalize. An older
    /// client's request (no flag) reads as not asking, so a newer daemon
    /// leaves the collision list off a reply that client's
    /// `deny_unknown_fields` type would refuse; a newer client's request
    /// that does not ask is byte-for-byte the older one; and a newer
    /// client that asks still decodes an older daemon's reply, which has
    /// no list, as empty.
    #[test]
    fn finalize_collision_report_survives_version_skew_both_ways() {
        let id = SessionId::nil();
        let older_request = format!(r#"{{"session_id":"{}"}}"#, id.as_ref());
        let decoded: FinalizeSessionRequest =
            serde_json_lenient::from_str(&older_request).expect("an older request must decode");
        assert!(
            !decoded.report_shared_port_collisions,
            "an older client never asked for the list"
        );

        let not_asking = FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: false,
        };
        assert_eq!(
            serde_json_lenient::to_string(&not_asking).expect("must serialize"),
            older_request,
            "a request that does not ask is the one an older client sends"
        );

        let asking = FinalizeSessionRequest {
            session_id: id,
            report_shared_port_collisions: true,
        };
        let wire = serde_json_lenient::to_string(&asking).expect("must serialize");
        assert!(
            wire.contains("report_shared_port_collisions"),
            "a request that asks says so: {wire}"
        );

        let older_reply: Errorable<FinalizeSessionResponse> =
            serde_json_lenient::from_str("{}").expect("an older daemon's reply must decode");
        assert_eq!(
            older_reply,
            Errorable::Ok(FinalizeSessionResponse::default()),
            "an older daemon's reply reads as no collisions"
        );
    }

    /// An empty request body must decode with the documented defaults so a
    /// bare `{}` probe (or an older client) still gets a full bundle.
    #[test]
    fn diag_bundle_request_defaults_from_empty_object() {
        let req: DiagBundleRequest = serde_json_lenient::from_str("{}").expect("deserialize");
        assert_eq!(req, DiagBundleRequest::default());
        assert_eq!(req.log_tail_bytes, 0);
        assert!(req.include_state_listing);
    }

    #[test]
    fn diag_bundle_request_round_trips() {
        let req = DiagBundleRequest::default()
            .with_log_tail_bytes(1024)
            .with_state_listing(false);
        assert_eq!(round_trip(&req), req);
        assert_eq!(
            DIAG_BUNDLE_SUBSYSTEM, "minimald-v1-DiagBundleTarZst",
            "subsystem name is wire contract; changing it breaks old clients"
        );
    }

    /// The clean-cache framing is wire contract: an empty request body means
    /// the daemon's defaults, the updates are self-describing by `kind`, and
    /// the subsystem name can't drift without breaking old clients.
    #[test]
    fn clean_cache_wire_shapes_round_trip() {
        let req: CleanCacheRequest = serde_json_lenient::from_str("{}").expect("deserialize");
        assert_eq!(req, CleanCacheRequest::default());
        assert_eq!(req.older_than_secs, 0);
        assert_eq!(
            round_trip(&req.clone().with_older_than_secs(3600)).older_than_secs,
            3600
        );

        for update in [
            CleanCacheUpdate::Removed {
                detail: "Deleting package curl [abc]".to_string(),
            },
            CleanCacheUpdate::Done {
                entries: 2,
                dirs: 1,
            },
            CleanCacheUpdate::Failed {
                error: "nope".to_string(),
            },
        ] {
            assert_eq!(round_trip(&update), update);
        }
        assert!(
            !CleanCacheUpdate::Removed {
                detail: String::new()
            }
            .is_terminal()
        );
        assert!(
            CleanCacheUpdate::Done {
                entries: 0,
                dirs: 0
            }
            .is_terminal()
        );
        assert!(
            CleanCacheUpdate::Failed {
                error: String::new()
            }
            .is_terminal()
        );

        assert_eq!(
            CLEAN_CACHE_SUBSYSTEM, "minimald-v1-CleanCache",
            "subsystem name is wire contract; changing it breaks old clients"
        );
    }

    #[test]
    fn policy_types_are_present_and_serializable() {
        // PortMapping construction and round-trip
        let mapping = PortMapping {
            external_port: 8080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let json = serde_json_lenient::to_string(&mapping).unwrap();
        let rt: PortMapping = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(rt, mapping);

        // IngressPolicy default and round-trip
        let ingress = IngressPolicy {
            port_mappings: vec![mapping],
            dynamic_allowed_range: Some((10000, 20000)),
            dynamic_ingress: Some(sessions::DynamicIngress::Ask),
        };
        let json = serde_json_lenient::to_string(&ingress).unwrap();
        let rt: IngressPolicy = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(rt, ingress);

        // EgressPolicy default serializes without error
        let egress = EgressPolicy::default();
        let json = serde_json_lenient::to_string(&egress).unwrap();
        let _: EgressPolicy = serde_json_lenient::from_str(&json).unwrap();

        // SessionPolicy with null egress and default ingress matches expected CLI output
        let policy = SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy::default()),
            credentialed_upstream: None,
        };
        let json = serde_json_lenient::to_string(&policy).unwrap();
        assert!(json.contains("\"egress\":null"), "got: {json}");
        assert!(json.contains("\"port_mappings\":[]"), "got: {json}");
        assert!(
            json.contains("\"dynamic_allowed_range\":null"),
            "got: {json}"
        );
        assert!(json.contains("\"dynamic_ingress\":null"), "got: {json}");
    }

    /// A daemon that predates `hook_failures` answers a destroy with the
    /// old unit shape, `null`; it must still read as a clean success, and
    /// a clean success must still go out as `null` for an older client.
    /// An error must not read as a success with no failures.
    #[test]
    fn destroy_session_response_decodes_the_old_shape() {
        let old: Errorable<DestroySessionResponse> =
            serde_json_lenient::from_str("null").expect("the old shape must decode");
        assert_eq!(old, Errorable::Ok(DestroySessionResponse::default()));
        assert_eq!(
            serde_json_lenient::to_string(&Errorable::Ok(DestroySessionResponse::default()))
                .unwrap(),
            "null"
        );

        let failed = DestroySessionResponse {
            hook_failures: vec!["user loadout `dev`: exited with status 3".to_string()],
        };
        assert_eq!(round_trip(&failed), failed);

        let err: Errorable<DestroySessionResponse> =
            serde_json_lenient::from_str(r#"{"error":"no such session"}"#)
                .expect("an error payload must decode");
        assert!(
            matches!(err, Errorable::Err { .. }),
            "an error decoded as success: {err:?}"
        );
    }

    fn round_trip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let json = serde_json_lenient::to_string(value).expect("serialize");
        serde_json_lenient::from_str(&json).expect("deserialize")
    }

    /// Regression: the daemon reports "no such session" from `GetSessionPolicy`
    /// as `Errorable::Err { error }` (`{"error":"..."}`). Because `Errorable`
    /// is untagged and every `SessionPolicy` field is optional, that object
    /// once decoded as `Ok(SessionPolicy { egress: None, ingress: None })` —
    /// exit 0, "no restrictions" — for any nonexistent session. It must decode
    /// as `Err` instead.
    #[test]
    fn errorable_session_policy_decodes_daemon_error_as_err() {
        let decoded: Errorable<SessionPolicy> =
            serde_json_lenient::from_str(r#"{"error":"no session found"}"#).expect("deserialize");
        assert_eq!(
            decoded,
            Errorable::Err {
                error: "no session found".to_string()
            }
        );

        // A real policy response still decodes as the `Ok` arm.
        let decoded: Errorable<SessionPolicy> =
            serde_json_lenient::from_str(r#"{"egress":null,"ingress":null}"#).expect("deserialize");
        assert_eq!(
            decoded,
            Errorable::Ok(SessionPolicy {
                egress: None,
                ingress: None,
                credentialed_upstream: None
            })
        );
    }

    /// The live-ingress response (NET-044) round-trips, and — because it rides
    /// an untagged `Errorable` — the daemon's `{"error":"..."}` reply for an
    /// unknown session must still decode as `Err` rather than as an empty
    /// mapping list, which would read as "the box published nothing" for a box
    /// that does not exist.
    #[test]
    fn live_ingress_response_round_trips_and_decodes_daemon_error() {
        let live = vec![
            LiveMapping {
                local: "127.0.64.2:3000".to_string(),
                internal_port: 3000,
                proto: IpProto::Tcp,
                // A runtime publish the relay gate has not admitted yet:
                // bound on the host, but the box's own gate still refuses it.
                pending: Some(true),
            },
            LiveMapping {
                local: "127.0.64.2:5353".to_string(),
                internal_port: 5353,
                proto: IpProto::Udp,
                pending: Some(false),
            },
        ];
        assert_eq!(
            round_trip(&Errorable::Ok(live.clone())),
            Errorable::Ok(live.clone())
        );

        // The reachability half rides the wire by name: a pending publish
        // says so in the JSON any client of the RPC reads.
        let json = serde_json_lenient::to_string(&live[0]).unwrap();
        assert!(
            json.contains("\"pending\":true"),
            "the mapping's pending state is part of its wire shape: {json}"
        );

        // A reply from a daemon older than the field carries no `pending`
        // key: it decodes as `None` — unknown, the renderings' own spelling
        // — never as the reachable reading a missing key could default
        // itself into.
        let mut pre_field: serde_json_lenient::Value = serde_json_lenient::from_str(&json).unwrap();
        pre_field
            .as_object_mut()
            .expect("a mapping encodes as an object")
            .remove("pending");
        let decoded: LiveMapping =
            serde_json_lenient::from_str(&serde_json_lenient::to_string(&pre_field).unwrap())
                .unwrap();
        assert_eq!(
            decoded.pending, None,
            "a pre-field reply decodes as unknown, not as not-pending: {json}"
        );

        let decoded: Errorable<Vec<LiveMapping>> =
            serde_json_lenient::from_str(r#"{"error":"no session found"}"#).expect("deserialize");
        assert_eq!(
            decoded,
            Errorable::Err {
                error: "no session found".to_string()
            },
            "a daemon error must not decode as an empty mapping list"
        );

        // The split a renderer reads: `local` is a `host:port` pair.
        let mapping = LiveMapping {
            local: "127.0.64.2:3000".to_string(),
            internal_port: 3000,
            proto: IpProto::Tcp,
            pending: Some(false),
        };
        assert_eq!(mapping.host_port(), Some(("127.0.64.2", 3000)));
    }

    /// `SessionDelta` distinguishes proven-clean VCS state, the
    /// activation-delta fallback, and "unavailable"; all three shapes must
    /// survive the wire, tagged by `kind`.
    #[test]
    fn session_delta_response_round_trips() {
        let vcs = SessionDeltaResponse::Vcs {
            uncommitted: vec!["A notes.md".to_string(), "M src/main.rs".to_string()],
            unpushed_commits: 3,
        };
        assert_eq!(round_trip(&vcs), vcs);
        let json = serde_json_lenient::to_string(&vcs).unwrap();
        assert!(json.contains(r#""kind":"vcs""#), "got: {json}");

        let fallback = SessionDeltaResponse::ChangedSinceActivation {
            rows: vec!["A scratch.txt".to_string()],
        };
        assert_eq!(round_trip(&fallback), fallback);
        let json = serde_json_lenient::to_string(&fallback).unwrap();
        assert!(
            json.contains(r#""kind":"changed_since_activation""#),
            "got: {json}"
        );

        let unavailable = SessionDeltaResponse::Unavailable;
        assert_eq!(round_trip(&unavailable), unavailable);
        let json = serde_json_lenient::to_string(&unavailable).unwrap();
        assert!(json.contains(r#""kind":"unavailable""#), "got: {json}");
    }

    #[test]
    fn create_session_request_round_trips() {
        let req = CreateSessionRequest {
            config: SessionConfig {
                name: Some("my-session".into()),
                project_path: paths::HostAbsPath::try_new("/home/u/proj").unwrap(),
                network: NetworkMode::OwnIp,
                policy: SessionPolicy::default(),
                // The non-`None` shape of the handed addresses: a fixture
                // leaving it `None` would round-trip green even if the
                // field never reached the wire.
                box_addresses: Some(BoxAddresses {
                    switch_address: std::net::Ipv4Addr::new(100, 64, 0, 2),
                    loopback_address: std::net::Ipv4Addr::new(127, 0, 64, 0),
                }),
                // The non-default (`--no-hooks`): `true` is the serde
                // default, so a fixture using it would round-trip green
                // even if the field never reached the wire.
                hooks_enabled: false,
                attrs: [("color".to_string(), "blue".to_string())]
                    .into_iter()
                    .collect(),
            },
            must_match_version: Some("0.6.0".into()),
        };
        assert_eq!(round_trip(&req), req);
    }

    /// A client that predates `must_match_version` sends no such field, and
    /// the daemon must read that as "assert nothing" rather than fail to
    /// decode the request. `CreateSessionRequest` is deliberately *not*
    /// `deny_unknown_fields`, which is the same property read the other way:
    /// a daemon that predates the field ignores it instead of rejecting the
    /// create outright.
    #[test]
    fn create_session_request_predating_must_match_version_asserts_nothing() {
        let json = r#"{"config":{
            "name": "s",
            "project_path": "/p",
            "network": "host_net",
            "attrs": {}
        }}"#;
        let req: CreateSessionRequest =
            serde_json_lenient::from_str(json).expect("legacy request must load");
        assert!(req.must_match_version.is_none());

        // And the forward direction: an old daemon's serde ignores the new
        // field rather than refusing the request.
        let with_field = r#"{"config":{
            "name": "s",
            "project_path": "/p",
            "network": "host_net",
            "attrs": {}
        },"must_match_version":"0.6.0"}"#;
        let req: CreateSessionRequest =
            serde_json_lenient::from_str(with_field).expect("the new field must decode");
        assert_eq!(req.must_match_version.as_deref(), Some("0.6.0"));
    }

    /// The skew wording names both builds, the recovery, and the override —
    /// and says nothing at all when the two builds agree.
    #[test]
    fn version_skew_message_names_both_builds_the_recovery_and_the_override() {
        assert!(version_skew_message("0.6.0", "0.6.0").is_none());
        let msg = version_skew_message("0.6.0", "0.5.0-dev.12.g86ce5c3a")
            .expect("differing builds are a skew");
        assert!(msg.contains("0.6.0"), "missing the CLI version: {msg}");
        assert!(
            msg.contains("0.5.0-dev.12.g86ce5c3a"),
            "missing the daemon version: {msg}"
        );
        assert!(msg.contains("min stop"), "missing the recovery: {msg}");
        assert!(
            msg.contains(SKEW_OVERRIDE_VAR),
            "missing the override: {msg}"
        );
    }

    /// A `SessionConfig` from a client that predates `hooks_enabled`
    /// deserializes with hooks **on**. A bare `#[serde(default)]` would
    /// give `false` and silently disable hooks for every older client.
    #[test]
    fn session_config_predating_hooks_enabled_defaults_to_on() {
        let json = r#"{
            "name": "s",
            "project_path": "/p",
            "network": "host_net",
            "attrs": {}
        }"#;
        let c: SessionConfig = serde_json_lenient::from_str(json).expect("legacy config must load");
        assert!(c.hooks_enabled);
    }

    #[test]
    fn create_session_response_round_trips() {
        let resp = CreateSessionResponse {
            id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            daemon_version: Some("0.6.0".into()),
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            // The interim flag survives the wire: the re-advise a client
            // prints on it (NET-123) must not be able to silently drop off.
            interim_loopback: true,
            deny_all_opt_out: None,
            // So does the answerer's half of the name-surface report: the
            // line `min session activate` prints from it (NET-018) must not
            // be able to silently drop off.
            answerer_bound: true,
            // And the classifier state (NET-079): the advisory a start
            // prints and the enforcement a host-address box runs under
            // must not be able to silently drop off either.
            classifier_advisory: None,
            host_ip_enforcement: None,
        };
        let json = serde_json_lenient::to_string(&resp).expect("serializes");
        assert!(
            json.contains(r#""answerer_bound":true"#),
            "a daemon whose answerer is bound must say so on the wire, got: {json}",
        );
        assert_eq!(round_trip(&resp), resp);
    }

    /// The opt-out a daemon reports on its create reply (NET-077) survives
    /// the wire both ways, and is *absent* — not `false` — when the daemon
    /// has not set it, so a daemon that keeps the default and a daemon that
    /// predates the field stay distinguishable to the client deciding
    /// whether the coming change applies to it (NET-076's notice).
    #[test]
    fn create_session_response_carries_the_deny_all_opt_out() {
        let opted_out = CreateSessionResponse {
            deny_all_opt_out: Some(true),
            id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            daemon_version: Some("0.6.0".into()),
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            interim_loopback: false,
            answerer_bound: false,
            classifier_advisory: None,
            host_ip_enforcement: None,
        };
        let json = serde_json_lenient::to_string(&opted_out).expect("serializes");
        assert!(
            json.contains(r#""deny_all_opt_out":true"#),
            "an opted-out daemon must say so on the wire, got: {json}",
        );
        assert_eq!(
            serde_json_lenient::from_str::<CreateSessionResponse>(&json)
                .expect("decodes back")
                .deny_all_opt_out,
            Some(true),
        );

        let opted_in = CreateSessionResponse {
            deny_all_opt_out: Some(false),
            ..opted_out
        };
        assert_eq!(round_trip(&opted_in), opted_in);
    }

    /// The classifier state a host that cannot decide per box puts on its
    /// create replies (NET-079), pinned on the wire: the unenforced state
    /// as `host_ip_enforcement: none` in the machine spelling — `per_box` on
    /// a host that decides, so the two hosts stay distinguishable to
    /// whatever reads the field — the cause in words inside the advisory,
    /// and the install command only for the cause it clears. A daemon
    /// that predates both fields decodes with neither: silence, never a
    /// decided `per_box`.
    #[test]
    fn create_response_carries_the_classifier_state() {
        // The host whose step is missing: the advisory names the cause in
        // words, names the state it leaves the box in, and carries the
        // exact command that installs the privileged step.
        let step_missing = CreateSessionResponse {
            id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            daemon_version: Some("0.6.0".into()),
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            interim_loopback: false,
            deny_all_opt_out: None,
            answerer_bound: false,
            classifier_advisory: Some(
                "note: this host cannot decide a host-address box's egress \
                 verdict per box: the classifier's privileged step is not \
                 installed on this host. While it cannot, its host-address \
                 boxes run unenforced — whatever the boxes' declarations \
                 say. Install the classifier's privileged step with:\n  \
                 run: curl -fsSLO https://raw.githubusercontent.com/gominimal/\
                 minimal/main/scripts/install-host-classifier.sh && sudo bash \
                 ./install-host-classifier.sh --user <the account this \
                 daemon runs as> --cohort-address <cohort address> \
                 --node-plane-address <node-plane address>"
                    .to_string(),
            ),
            host_ip_enforcement: Some("none".into()),
        };
        let json = serde_json_lenient::to_string(&step_missing).expect("serializes");
        assert!(
            json.contains(r#""host_ip_enforcement":"none""#),
            "the unenforced state must ride the wire in the machine spelling, got: {json}",
        );
        assert!(
            json.contains("the classifier's privileged step is not installed"),
            "the advisory names its cause in words, got: {json}",
        );
        assert!(
            json.contains("sudo bash ./install-host-classifier.sh"),
            "the step's cause names the exact command that installs it, got: {json}",
        );
        assert_eq!(round_trip(&step_missing), step_missing);

        // The host that cannot confine a box: the same state, named without
        // a command — installing the step over such a tree would leave the
        // cause standing, so the advisory must not name one.
        let cannot_confine = CreateSessionResponse {
            classifier_advisory: Some(
                "note: this host cannot decide a host-address box's egress \
                 verdict per box: no cgroup2 mount with nsdelegate covers \
                 the classifier tree, so a box could migrate out of its \
                 leaf. While it cannot, its host-address boxes run \
                 unenforced — whatever the boxes' declarations say."
                    .to_string(),
            ),
            host_ip_enforcement: Some("none".into()),
            ..step_missing
        };
        let json = serde_json_lenient::to_string(&cannot_confine).expect("serializes");
        assert!(
            !json.contains("install-host-classifier"),
            "a cause no command clears names no command, got: {json}",
        );
        assert_eq!(round_trip(&cannot_confine), cannot_confine);

        // The decided host: nothing to say, so nothing on the wire — a
        // client of either build reads the reply it always read.
        let decided = CreateSessionResponse {
            classifier_advisory: None,
            host_ip_enforcement: Some("per_box".into()),
            ..cannot_confine
        };
        let json = serde_json_lenient::to_string(&decided).expect("serializes");
        assert!(
            json.contains(r#""host_ip_enforcement":"per_box""#),
            "a host that decides per box says so in the machine spelling, got: {json}",
        );
        assert!(
            !json.contains("classifier_advisory"),
            "a decided host carries no advisory, got: {json}",
        );
        assert_eq!(round_trip(&decided), decided);

        // A daemon that predates both fields: the reply it always sent
        // decodes with neither, and absence must not read as a decided
        // `per_box` — an older daemon's silence is not evidence of
        // anything, and a client that reads nothing claims nothing.
        let pre_field: Errorable<CreateSessionResponse> = serde_json_lenient::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000001","daemon_version":"0.5.0"}"#,
        )
        .expect("a pre-field CreateSession reply must still decode");
        match pre_field {
            Errorable::Ok(c) => {
                assert!(c.classifier_advisory.is_none());
                assert_eq!(c.host_ip_enforcement, None);
            }
            Errorable::Err { error } => panic!("expected Ok, got {error}"),
        }
    }

    /// NET-079's enforcement state never rides the strict policy reply: an
    /// older `min` built against the two-field [`EffectiveSessionPolicy`] —
    /// `deny_unknown_fields`, the strictness that keeps an all-optional
    /// struct from swallowing the daemon's `{"error":...}` replies under
    /// the untagged [`Errorable`] — rejects a key it has no field for, so a
    /// policy reply that grew the state would make every old client fail
    /// `min session policy` outright. Pinned here as the contract that keeps
    /// that from regressing: the reply this build serves decodes in the old
    /// client's own strict shape, and the state answers over
    /// [`GetSessionRuntimeFacts`] instead — a reply an old client simply
    /// never asks for, and this build's own answer to it stays anchored the
    /// same way the policy's `egress` is.
    #[test]
    fn effective_policy_reply_decodes_in_the_old_clients_strict_shape() {
        // The reply this build serves: two fields, no enforcement key.
        let reply = Errorable::Ok(EffectiveSessionPolicy {
            egress: EffectiveEgress::DenyAll,
            ingress: None,
        });
        let json = serde_json_lenient::to_string(&reply).expect("the policy reply serializes");
        assert!(
            !json.contains("host_ip_enforcement"),
            "the strict policy reply must carry no enforcement key, got: {json}",
        );

        // The old client: the strict two-field shape it was built against,
        // spelled as its own derive would spell it. It decodes the reply
        // above because the reply never grew a field — and it refuses a
        // reply that did, which is exactly why the state must ride its own
        // RPC rather than a new field here.
        #[derive(serde::Deserialize, Debug, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct OldClientPolicy {
            egress: EffectiveEgress,
            ingress: Option<IngressPolicy>,
        }
        let decoded: Errorable<OldClientPolicy> = serde_json_lenient::from_str(&json)
            .expect("the reply this build serves decodes in the old client's shape");
        assert_eq!(
            decoded,
            Errorable::Ok(OldClientPolicy {
                egress: EffectiveEgress::DenyAll,
                ingress: None,
            })
        );
        assert!(
            serde_json_lenient::from_str::<Errorable<OldClientPolicy>>(
                r#"{"egress":"deny_all","ingress":null,"host_ip_enforcement":"none"}"#
            )
            .is_err(),
            "the old client refuses a policy reply that grew the key — the \
             reason the state answers over its own runtime-facts reply",
        );

        // The runtime-facts reply keeps the property the strict shapes
        // exist for without being strict: its required `id` is a field the
        // daemon's `{"error":...}` never carries, so an error answer falls
        // through the untagged decode to `Err` rather than decoding as a
        // facts object with nothing to report — while a facts reply that
        // grew a key this client has no field for still decodes, because
        // runtime facts grow and an older client keeps the ones it knows.
        let facts = SessionRuntimeFacts {
            id: SessionId::nil(),
            host_ip_enforcement: Some(HostIpEnforcement::None),
            unaudited_listen_ports: Vec::new(),
            audit_log: None,
            shared_port_collisions: Vec::new(),
        };
        assert_eq!(round_trip(&facts), facts);
        let unaudited = SessionRuntimeFacts {
            unaudited_listen_ports: vec![3000, 3001],
            audit_log: Some("/state/audit/decisions.log".to_string()),
            ..facts.clone()
        };
        assert_eq!(round_trip(&unaudited), unaudited);
        let empty = serde_json_lenient::to_string(&facts).expect("facts serialize");
        assert!(
            !empty.contains("unaudited_listen_ports") && !empty.contains("audit_log"),
            "an empty unaudited list is omitted from the wire: {empty}"
        );
        match serde_json_lenient::from_str::<Errorable<SessionRuntimeFacts>>(
            r#"{"error":"no session found"}"#,
        )
        .expect("an error reply is one of the untagged arms")
        {
            Errorable::Err { error } => assert_eq!(error, "no session found"),
            Errorable::Ok(facts) => {
                panic!("an error reply must not decode as facts, got {facts:?}")
            }
        }
        match serde_json_lenient::from_str::<Errorable<SessionRuntimeFacts>>(
            r#"{"id":"00000000-0000-0000-0000-000000000000","host_ip_enforcement":"per_box","a_later_fact":true}"#,
        )
        .expect("a facts reply with a key this client does not know still decodes")
        {
            Errorable::Ok(decoded) => assert_eq!(
                decoded,
                SessionRuntimeFacts {
                    id: SessionId::nil(),
                    host_ip_enforcement: Some(HostIpEnforcement::PerBox),
                    unaudited_listen_ports: Vec::new(),
                    audit_log: None,
                    shared_port_collisions: Vec::new(),
                },
                "the facts this client knows decode beside a key it does not"
            ),
            Errorable::Err { error } => {
                panic!("a facts reply must not decode as an error, got {error}")
            }
        }
    }

    /// A daemon that predates `hostname_routing_unavailable` must still decode,
    /// with the field absent. Absent has to mean "said nothing", not "reported
    /// a fault": an older daemon is not evidence that routing is down, and a
    /// client that read it that way would warn on every session it lists.
    /// `deny_all_opt_out` rides the same reply and reads the same way — absent
    /// from a daemon that predates it, which is a daemon that cannot have
    /// opted out (NET-077), so the client prints the notice it always did.
    /// `answerer_bound` rides the same replies and reads the same way — absent
    /// from a daemon that predates it, which decodes as `false`, the read that
    /// changes nothing: an older daemon's silence is not evidence its
    /// answerer serves, and a client that assumed it would name native DNS on
    /// a host that may not have one (NET-018).
    #[test]
    fn responses_predating_hostname_routing_field_decode_as_absent() {
        let list: ListSessionsResponse =
            serde_json_lenient::from_str(r#"{"sessions":[],"daemon_version":"0.5.0"}"#)
                .expect("a pre-field ListSessions reply must still decode");
        assert!(list.hostname_routing_unavailable.is_none());
        assert!(list.hostname_proxy_port.is_none());
        assert!(list.zone_answerer_port.is_none());
        assert!(!list.answerer_bound);

        let create: Errorable<CreateSessionResponse> = serde_json_lenient::from_str(
            r#"{"id":"00000000-0000-0000-0000-000000000001","daemon_version":"0.5.0"}"#,
        )
        .expect("a pre-field CreateSession reply must still decode");
        match create {
            Errorable::Ok(c) => {
                assert!(c.hostname_routing_unavailable.is_none());
                assert!(c.hostname_proxy_port.is_none());
                assert!(c.zone_answerer_port.is_none());
                // The interim flag's legacy default is `false`, the read that
                // changes nothing: an older daemon's reply is not evidence the
                // reserved range is absent, and nothing downstream is gated
                // on the flag.
                assert!(!c.interim_loopback);
                assert!(c.deny_all_opt_out.is_none());
                assert!(!c.answerer_bound);
            }
            Errorable::Err { error } => panic!("expected Ok, got {error}"),
        }
    }

    /// The field is omitted from the wire when there is nothing wrong, so the
    /// healthy path costs no bytes and an older client sees exactly what it
    /// saw before.
    #[test]
    fn hostname_routing_field_is_omitted_when_healthy() {
        let resp = ListSessionsResponse {
            daemon_version: Some("0.6.0".into()),
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            answerer_bound: false,
            resource_pool: None,
            sessions: vec![],
        };
        let json = serde_json_lenient::to_string(&resp).expect("serializes");
        assert!(
            !json.contains("hostname_routing_unavailable"),
            "healthy reply should omit the field, got {json}"
        );
        assert!(
            !json.contains("hostname_proxy_port"),
            "a reply that has not discovered its port should omit the field, got {json}"
        );
        assert!(
            !json.contains("zone_answerer_port"),
            "a reply that has not discovered its answerer port should omit the field, got {json}"
        );

        let down = ListSessionsResponse {
            hostname_routing_unavailable: Some("port 7654 is held".into()),
            ..resp.clone()
        };
        let json = serde_json_lenient::to_string(&down).expect("serializes");
        let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
        assert_eq!(
            back.hostname_routing_unavailable.as_deref(),
            Some("port 7654 is held")
        );

        let discovered = ListSessionsResponse {
            hostname_proxy_port: Some(41234),
            ..resp.clone()
        };
        let json = serde_json_lenient::to_string(&discovered).expect("serializes");
        let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
        assert_eq!(back.hostname_proxy_port, Some(41234));

        // The list reply carries the answerer's half the same way (NET-018):
        // `min ls` reads it off this reply, not the activation one.
        let bound = ListSessionsResponse {
            answerer_bound: true,
            ..resp.clone()
        };
        let json = serde_json_lenient::to_string(&bound).expect("serializes");
        let back: ListSessionsResponse = serde_json_lenient::from_str(&json).expect("round trips");
        assert!(back.answerer_bound);
    }

    /// The reply a daemon that predates `daemon_version` sends must still
    /// decode — with `None`, which is what tells the client it is talking to
    /// a build older than the handshake and therefore a skewed one.
    #[test]
    fn create_session_response_predating_daemon_version_decodes_as_absent() {
        let resp: Errorable<CreateSessionResponse> =
            serde_json_lenient::from_str(r#"{"id":"00000000-0000-0000-0000-000000000001"}"#)
                .expect("a legacy reply must decode");
        assert!(resp.unwrap().daemon_version.is_none());
    }

    /// Same for the two read RPCs the attach/exec paths gate on.
    #[test]
    fn read_responses_predating_daemon_version_decode_as_absent() {
        let listed: ListSessionsResponse =
            serde_json_lenient::from_str(r#"{"sessions":[]}"#).expect("deserialize");
        assert!(listed.daemon_version.is_none());
        let record: GetSessionRecordResponse =
            serde_json_lenient::from_str(r#"{"record":null}"#).expect("deserialize");
        assert!(record.daemon_version.is_none());
    }

    #[test]
    fn list_sessions_accepts_response_without_resource_pool() {
        let resp: ListSessionsResponse =
            serde_json_lenient::from_str(r#"{"sessions":[]}"#).expect("deserialize");
        assert!(resp.resource_pool.is_none());
        assert!(resp.sessions.is_empty());
    }

    /// A daemon that predates `project_path` and `status` on
    /// `ListSessionsEntry` omits both fields; the client must accept that
    /// response (project_path → `None`, status → `Active`) rather than fail
    /// deserialization.
    #[test]
    fn list_sessions_entry_accepts_response_without_project_path_and_status() {
        let resp: ListSessionsResponse = serde_json_lenient::from_str(
            r#"{"sessions":[{"id":"00000000-0000-0000-0000-000000000001","name":"old"}]}"#,
        )
        .expect("deserialize");
        assert_eq!(resp.sessions.len(), 1);
        let entry = &resp.sessions[0];
        assert_eq!(
            entry.id,
            SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
        );
        assert_eq!(entry.name.as_deref(), Some("old"));
        assert!(entry.project_path.is_none(), "missing project_path → None");
        assert_eq!(
            entry.status,
            sessions::SessionStatus::Active,
            "missing status → default Active"
        );
    }

    #[test]
    fn configure_loadout_request_round_trips_with_explicit_contribution() {
        let req = ConfigureLoadoutRequest {
            session_id: SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            contribution: WireContribution::default(),
        };
        assert_eq!(round_trip(&req), req);
    }

    /// A caller that doesn't compose a session omits `contribution`
    /// entirely; it defaults to empty rather than failing to parse.
    #[test]
    fn configure_loadout_request_accepts_missing_contribution_field() {
        let raw = serde_json_lenient::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
        });
        let req: ConfigureLoadoutRequest =
            serde_json_lenient::from_value(raw).expect("deserialize");
        assert_eq!(req.contribution, WireContribution::default());
    }

    #[test]
    fn configure_loadout_response_materialized_round_trips() {
        let resp = ConfigureLoadoutResponse::Materialized;
        assert_eq!(round_trip(&resp), resp);
        let json = serde_json_lenient::to_string(&resp).unwrap();
        assert!(json.contains(r#""kind":"materialized""#), "got: {json}");
    }

    #[test]
    fn configure_loadout_response_pending_round_trips() {
        let id = SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let resp = ConfigureLoadoutResponse::Pending {
            response: ContributionResponse {
                session_id: id,
                vars: vec![],
                patches: vec![],
                lifecycle_hooks: vec![],
            },
        };
        assert_eq!(round_trip(&resp), resp);
        let json = serde_json_lenient::to_string(&resp).unwrap();
        assert!(json.contains(r#""kind":"pending""#), "got: {json}");
    }

    /// Back-compat both directions: a daemon that predates `git` omits the
    /// field and decodes to `None`; an extra field in the payload is
    /// accepted (no `deny_unknown_fields`), so a new daemon still serves
    /// old clients.
    #[test]
    fn list_sessions_entry_decodes_with_and_without_git() {
        let bare = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "api",
            "project_path": "/src/api",
            "status": "active",
            "attrs": null
        }"#;
        let without: ListSessionsEntry =
            serde_json_lenient::from_str(bare).expect("pre-git payload");
        assert_eq!(without.git, None);

        let with_git = serde_json_lenient::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "api",
            "project_path": "/src/api",
            "status": "active",
            "git": {
                "branch": "main",
                "repo_root": "/src/api",
                "is_worktree": true
            },
            "attrs": null
        });
        let with: ListSessionsEntry =
            serde_json_lenient::from_value(with_git).expect("post-git payload");
        assert_eq!(
            with.git,
            Some(Box::new(GitInfo {
                branch: "main".to_string(),
                repo_root: "/src/api".to_string(),
                is_worktree: true,
            }))
        );
        assert_eq!(round_trip(&with), with);
    }

    /// NET-129's listing half survives version skew both ways without a
    /// request flag, because neither [`ListSessionsResponse`] nor
    /// [`ListSessionsEntry`] is `deny_unknown_fields`. A newer daemon's
    /// populated entry carries one key more than an older client knows, and
    /// these types skip a key they do not know — shown here with a key this
    /// build does not know either, the position an older client is in. An
    /// older daemon's entry carries no list and decodes as empty, and an
    /// empty list stays off the wire.
    #[test]
    fn list_sessions_shared_port_collisions_survive_version_skew_both_ways() {
        let entry = |collisions: Vec<SharedPortCollision>| ListSessionsEntry {
            id: SessionId::nil(),
            name: Some("second".to_string()),
            project_path: None,
            status: sessions::SessionStatus::Active,
            git: None,
            attrs: None,
            host_ip_enforcement: None,
            shared_port_collisions: collisions,
        };
        let response = |sessions| ListSessionsResponse {
            resource_pool: None,
            sessions,
            daemon_version: None,
            hostname_routing_unavailable: None,
            hostname_proxy_port: None,
            zone_answerer_port: None,
            answerer_bound: false,
        };

        let quiet = serde_json_lenient::to_string(&response(vec![entry(Vec::new())]))
            .expect("must serialize");
        assert!(
            !quiet.contains("shared_port_collisions"),
            "an empty list must not be serialized, got {quiet}"
        );

        let yielded = entry(vec![SharedPortCollision {
            port: 8080,
            held_by: "first.min.internal".to_string(),
        }]);
        let mut wire =
            serde_json_lenient::to_value(response(vec![yielded.clone()])).expect("serializes");
        assert_eq!(
            wire["sessions"][0]["shared_port_collisions"],
            serde_json_lenient::json!([{"port": 8080, "held_by": "first.min.internal"}]),
            "a yielded port is listed under its wire key: {wire}"
        );

        // A newer daemon's reply, one key past what this build knows: still
        // decodes, so an older client's listing survives a populated list.
        wire["sessions"][0]["a_later_field"] = serde_json_lenient::json!([1]);
        wire["a_later_field"] = serde_json_lenient::json!(true);
        let newer: ListSessionsResponse =
            serde_json_lenient::from_value(wire).expect("unknown keys are ignored");
        assert_eq!(newer.sessions, vec![yielded]);

        // An older daemon's entry: no list, decoded as empty.
        let older: ListSessionsResponse = serde_json_lenient::from_str(
            r#"{"sessions":[{"id":"00000000-0000-0000-0000-000000000000","name":"second","attrs":null}]}"#,
        )
        .expect("a pre-field entry must decode");
        assert!(older.sessions[0].shared_port_collisions.is_empty());
    }

    /// The port-report verbs (NET-138) round-trip as the fixed, size-bounded
    /// messages they are: the tagged line names its verb, the request carries
    /// the row key, the port, the protocol and the reporting source, and the
    /// one reply both verbs answer with cannot be mistaken for any other
    /// reply shape — the discrimination the untagged reply depends on, since
    /// a report the grant refused is answered as `Error` and a publish that
    /// unwinds must be able to tell which it got.
    #[test]
    fn box_control_admit_and_withdraw_round_trip() {
        let admit = BoxControlRequest::AdmitPort(AdmitPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
            port: 8080,
            proto: IpProto::Tcp,
            source: PortReportSource::Ask,
        });
        let wire = serde_json_lenient::to_string(&admit).expect("serialize");
        assert!(
            wire.contains(r#""verb":"admit_port""#),
            "the tagged line names its verb: {wire}"
        );
        assert_eq!(round_trip(&admit), admit);

        let withdraw = BoxControlRequest::WithdrawPort(WithdrawPortRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
            port: 8080,
            proto: IpProto::Udp,
            source: PortReportSource::Listen,
        });
        let wire = serde_json_lenient::to_string(&withdraw).expect("serialize");
        assert!(
            wire.contains(r#""verb":"withdraw_port""#),
            "the tagged line names its verb: {wire}"
        );
        assert_eq!(round_trip(&withdraw), withdraw);
        assert!(
            wire.contains(r#""source":"listen""#) && wire.contains(r#""proto":"udp""#),
            "the source and the protocol cross in their wire spellings: {wire}"
        );

        // The reply a recorded report answers with round-trips, and a
        // document of no other variant's shape decodes as it — the
        // untagged discrimination, checked from the other side.
        let recorded = BoxControlReply::PortRecorded {
            port: 8080,
            proto: IpProto::Tcp,
        };
        assert_eq!(round_trip(&recorded), recorded);
        let decoded: BoxControlReply =
            serde_json_lenient::from_str(r#"{"port":8080,"proto":"tcp"}"#)
                .expect("a recorded report's reply decodes");
        assert_eq!(decoded, recorded);

        // The refusal a grant-refused report answers with still decodes as
        // the error it is — the shape the guest unwinds its publish by.
        let refused: BoxControlReply = serde_json_lenient::from_str(
            r#"{"error":"the reported port is outside the box's allowed range"}"#,
        )
        .expect("a refusal decodes");
        assert_eq!(
            refused,
            BoxControlReply::Error {
                error: "the reported port is outside the box's allowed range".to_string()
            }
        );

        // The report port is the wire contract between the two ends that
        // depend on this crate — the in-VM daemon that dials it and the VM
        // host daemon that bridges it — pinned beside the guest's boot
        // marker, one port per purpose, and clear of the timekeep bridge's
        // own number, which runs the opposite direction.
        assert_eq!(
            VM_HOST_BOX_REPORT_PORT, 7352,
            "the report port is wire contract; changing it breaks both ends"
        );
    }

    /// The ask verbs' offer half (NET-045) round-trips: the guest's ask
    /// admit carries only the row key, the port and the protocol — no name
    /// or free text a guest could smuggle a prompt with — the subscription
    /// keys itself by the row's box id, and the offer the daemon pushes to
    /// an attached client carries the host row's own fields. Every ask
    /// reply stays distinct from every older shape in the untagged order —
    /// an offered ask is never a recorded port, and a registration's
    /// id-carrying answer is never a subscription's.
    #[test]
    fn box_control_pending_ask_offer_round_trip() {
        let box_id = BoxId::from_bytes([
            0x01, 0x95, 0x65, 0x5f, 0x7f, 0x1e, 0x7a, 0xbc, 0x9d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d,
            0x6e, 0x7f,
        ]);

        // The guest's ask admit: the row key, the port, the protocol, and
        // nothing else — the one fixed shape a guest may raise a question
        // in.
        let admit_ask = BoxControlRequest::AdmitAsk(AdmitAskRequest {
            switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
            port: 8080,
            proto: IpProto::Tcp,
        });
        let wire = serde_json_lenient::to_string(&admit_ask).expect("serialize");
        assert!(
            wire.contains(r#""verb":"admit_ask""#)
                && wire.contains(r#""port":8080"#)
                && wire.contains(r#""proto":"tcp""#),
            "the tagged line names its verb and the port and protocol it asks for: {wire}"
        );
        assert!(
            !wire.contains("name") && !wire.contains("source") && !wire.contains("answer"),
            "the ask admit carries no name, no source and no answer — the guest can raise a \
             question but neither phrase it nor answer it: {wire}"
        );
        assert_eq!(round_trip(&admit_ask), admit_ask);

        // The subscription: keyed by the row's box id, never a name.
        let subscribe = BoxControlRequest::SubscribeAsks(SubscribeAsksRequest { box_id });
        let wire = serde_json_lenient::to_string(&subscribe).expect("serialize");
        assert!(
            wire.contains(r#""verb":"subscribe_asks""#)
                && wire.contains(r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#),
            "the subscription names its verb and the box id it keys by: {wire}"
        );
        assert_eq!(round_trip(&subscribe), subscribe);

        // The subscription's answer: subscribed marks the shape, so a
        // registration's id-carrying answer — a strict superset of the
        // marker-less fields — still decodes as the registration it is,
        // from either side of the order.
        let subscribed = BoxControlReply::AsksSubscribed {
            subscribed: true,
            box_id,
        };
        assert_eq!(round_trip(&subscribed), subscribed);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(
                r#"{"subscribed":true,"box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#
            )
            .expect("the subscription's answer decodes"),
            subscribed
        );
        let registered: BoxControlReply = serde_json_lenient::from_str(
            r#"{"switch_address":"100.64.127.255","loopback_address":"127.0.0.2","box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#,
        )
        .expect("a registration reply still decodes");
        assert!(
            matches!(registered, BoxControlReply::Registered(_)),
            "a registration's answer is never a subscription's: {registered:?}"
        );

        // The offer: the host row's own fields — ask id, box id, name,
        // port, protocol — and a document of it decodes as nothing else,
        // the recorded-port reply its fields are a superset of included.
        let ask_id = AskId::from_bytes([
            0x9f, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c,
            0x4d, 0x5e,
        ]);
        let offer = BoxControlReply::PendingAskOffer(PendingAskOffer {
            ask_id,
            box_id,
            name: "web".to_string(),
            port: 8080,
            proto: IpProto::Tcp,
        });
        let wire = serde_json_lenient::to_string(&offer).expect("serialize");
        for field in [
            r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#,
            r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#,
            r#""name":"web""#,
            r#""port":8080"#,
            r#""proto":"tcp""#,
        ] {
            assert!(wire.contains(field), "the offer spells {field}: {wire}");
        }
        assert_eq!(round_trip(&offer), offer);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(&wire)
                .expect("an offered ask decodes as its own reply"),
            offer,
            "the offer is placed before the recorded-port reply its fields \
             are a superset of"
        );

        // The dismissal: the marker keeps it distinct, both directions.
        let dismissed = BoxControlReply::PendingAskDismissed {
            ask_id,
            dismissed: true,
        };
        assert_eq!(round_trip(&dismissed), dismissed);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(
                r#"{"ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e","dismissed":true}"#
            )
            .expect("a dismissal decodes"),
            dismissed
        );
    }

    /// The ask verbs' answer half (NET-045) round-trips: the client's
    /// recorded answer carries the offer's ask id and one of the three
    /// answers — a human's yes, a human's no, a render that found no
    /// terminal — and the admit's reply carries the ask's end, as a
    /// `ask`-tagged document the recorded-port reply cannot be mistaken
    /// for in either direction.
    #[test]
    fn box_control_record_ask_answer_round_trip() {
        let ask_id = AskId::from_bytes([
            0x9f, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d, 0x9e, 0x0f, 0x1a, 0x2b, 0x3c,
            0x4d, 0x5e,
        ]);

        for (answer, spelling) in [
            (AskAnswer::Yes, r#""answer":"yes""#),
            (AskAnswer::No, r#""answer":"no""#),
            (AskAnswer::NoTty, r#""answer":"no_tty""#),
        ] {
            let record =
                BoxControlRequest::RecordAskAnswer(RecordAskAnswerRequest { ask_id, answer });
            let wire = serde_json_lenient::to_string(&record).expect("serialize");
            assert!(
                wire.contains(r#""verb":"record_ask_answer""#)
                    && wire.contains(r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#)
                    && wire.contains(spelling),
                "the recorded answer names its verb, its ask and its answer: {wire}"
            );
            assert_eq!(round_trip(&record), record);
        }

        // The record's answer: the first answer is acknowledged, the
        // marker keeps the shape distinct, and an id the daemon never
        // minted or already consumed is the error it is instead.
        let recorded = BoxControlReply::AskAnswerRecorded {
            ask_id,
            recorded: true,
        };
        assert_eq!(round_trip(&recorded), recorded);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(
                r#"{"ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e","recorded":true}"#
            )
            .expect("a recorded answer's reply decodes"),
            recorded
        );

        // The admit's answer: admitted names the port the host now holds
        // and the ask it was admitted under; refused names the typed end
        // the ask met. Both are `ask`-tagged documents, and the older
        // recorded-port reply — a strict subset of admitted's fields —
        // decodes as the port record it is, not as an ask.
        let admitted = BoxControlReply::AskAdmit(AskAdmitOutcome::Admitted {
            ask_id,
            port: 8080,
            proto: IpProto::Tcp,
        });
        let wire = serde_json_lenient::to_string(&admitted).expect("serialize");
        assert!(
            wire.contains(r#""ask":"admitted""#)
                && wire.contains(r#""ask_id":"9f1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e""#)
                && wire.contains(r#""port":8080"#),
            "the admitted answer spells its tag, its ask and its port: {wire}"
        );
        assert_eq!(round_trip(&admitted), admitted);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(&wire)
                .expect("the admitted answer decodes as its own reply"),
            admitted,
            "the admitted answer is placed before the recorded-port reply its \
             fields are a superset of"
        );

        for (reason, spelling) in [
            (AskRefused::Denied, r#""reason":"denied""#),
            (AskRefused::NoClient, r#""reason":"no_client""#),
            (AskRefused::QueueFull, r#""reason":"queue_full""#),
            (AskRefused::OutsideGrant, r#""reason":"outside_grant""#),
            (AskRefused::NoTty, r#""reason":"no_tty""#),
            (AskRefused::Cancelled, r#""reason":"cancelled""#),
            (AskRefused::NoRow, r#""reason":"no_row""#),
            (AskRefused::StanceNotAsk, r#""reason":"stance_not_ask""#),
        ] {
            let cause = (reason == AskRefused::Cancelled).then_some(AskCancelCause::LastDetach);
            let refused = BoxControlReply::AskAdmit(AskAdmitOutcome::Refused {
                ask_id,
                reason,
                cause,
            });
            let wire = serde_json_lenient::to_string(&refused).expect("serialize");
            assert!(
                wire.contains(r#""ask":"refused""#) && wire.contains(spelling),
                "the refused answer spells its tag and its typed end: {wire}"
            );
            assert_eq!(
                wire.contains(r#""cause":"last-detach""#),
                cause.is_some(),
                "only a cancellation carries its cause: {wire}"
            );
            assert_eq!(round_trip(&refused), refused);
        }

        // A late answer for an ended ask is answered with how it ended, a
        // shape no other reply decodes as.
        for (end, spelling) in [
            (AskLateEnd::Allowed, r#""end":"allowed""#),
            (AskLateEnd::Denied, r#""end":"denied""#),
            (
                AskLateEnd::Cancelled {
                    cause: AskCancelCause::MinvmdStopping,
                },
                r#""cause":"minvmd-stopping""#,
            ),
        ] {
            let late = BoxControlReply::AskAlreadyEnded {
                ask_id,
                port: 8080,
                proto: IpProto::Tcp,
                already_ended: end,
            };
            let wire = serde_json_lenient::to_string(&late).expect("serialize");
            assert!(
                wire.contains(spelling),
                "the late end spells {spelling}: {wire}"
            );
            assert_eq!(
                serde_json_lenient::from_str::<BoxControlReply>(&wire).expect("decodes"),
                late
            );
        }

        // The older recorded-port reply still decodes as the port record
        // it is — no ask-shaped variant claims a document with no ask in
        // it.
        let decoded: BoxControlReply =
            serde_json_lenient::from_str(r#"{"port":8080,"proto":"tcp"}"#)
                .expect("a recorded report's reply still decodes");
        assert_eq!(
            decoded,
            BoxControlReply::PortRecorded {
                port: 8080,
                proto: IpProto::Tcp
            }
        );
    }

    /// The read-only row verb round-trips under its key, and its two
    /// answers stay two answers: a live row's reply cannot decode as the
    /// no-row marker or as any older reply shape, so a host-side read can
    /// say "destroyed" without an error standing in for the fact.
    #[test]
    fn box_control_read_row_round_trip() {
        let read = BoxControlRequest::ReadRow(ReadRowRequest {
            name: "web".to_string(),
        });
        let wire = serde_json_lenient::to_string(&read).expect("serialize");
        assert!(
            wire.contains(r#""verb":"read_row""#) && wire.contains(r#""name":"web""#),
            "the tagged line names its verb and its key: {wire}"
        );
        assert_eq!(round_trip(&read), read);

        let row = BoxControlReply::Row(BoxRow {
            name: "web".to_string(),
            box_id: BoxId::from_bytes([
                0x01, 0x95, 0x65, 0x5f, 0x7f, 0x1e, 0x7a, 0xbc, 0x9d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d,
                0x6e, 0x7f,
            ]),
            switch_address: std::net::Ipv4Addr::new(100, 64, 127, 255),
            egress_allow_list: vec!["10.0.0.0/8".to_string()],
            declared_ports: vec![8080, 9090],
            runtime_ports: vec![3000],
        });
        let wire = serde_json_lenient::to_string(&row).expect("serialize");
        for field in [
            r#""switch_address":"100.64.127.255""#,
            r#""box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f""#,
            r#""egress_allow_list":["10.0.0.0/8"]"#,
            r#""declared_ports":[8080,9090]"#,
            r#""runtime_ports":[3000]"#,
        ] {
            assert!(
                wire.contains(field),
                "the row answer spells {field}: {wire}"
            );
        }
        assert_eq!(round_trip(&row), row);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(&wire)
                .expect("decodes as its own reply"),
            row
        );

        // No live box: the marker answer, discriminated from the row by the
        // `no_row` field and from every older shape by the same.
        let no_row = BoxControlReply::NoRow {
            name: "web".to_string(),
            no_row: true,
        };
        assert_eq!(round_trip(&no_row), no_row);
        assert_eq!(
            serde_json_lenient::from_str::<BoxControlReply>(r#"{"name":"web","no_row":true}"#)
                .expect("the no-row answer decodes"),
            no_row
        );
        assert_ne!(
            serde_json_lenient::from_str::<BoxControlReply>(r#"{"name":"web","no_row":true}"#)
                .expect("the no-row answer decodes"),
            row,
            "a no-row answer is never a live row's answer"
        );

        // The older replies still decode after the new variants joined the
        // untagged order: a registration's answer keeps its id, and an
        // error stays an error.
        let registered: BoxControlReply = serde_json_lenient::from_str(
            r#"{"switch_address":"100.64.127.255","loopback_address":"127.0.0.2","box_id":"0195655f7f1e7abc9d1f2a3b4c5d6e7f"}"#,
        )
        .expect("a registration reply still decodes");
        assert!(matches!(registered, BoxControlReply::Registered(_)));
        let error: BoxControlReply = serde_json_lenient::from_str(
            r#"{"error":"the row's creator did not present its pair"}"#,
        )
        .expect("an error reply still decodes");
        assert!(matches!(error, BoxControlReply::Error { .. }));
    }
}
