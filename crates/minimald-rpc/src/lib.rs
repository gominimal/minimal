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

use boxes::SessionId;
use chrono::Utc;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub mod exec;
pub mod taskenv;
pub mod trace;

pub use boxes::{
    BoxAddresses, BoxPolicy, CredentialedUpstream, DynamicIngress, EffectiveBoxPolicy,
    EffectiveEgress, EgressPolicy, IngressPolicy, IpProto, NetworkMode, PortMapping,
};

pub const RPC_SUBSYSTEM_PREFIX: &str = "minimald-v1-";

/// The message every RPC refusal carries once the daemon has begun its
/// shutdown: a client racing `min stop` matches on it to name the lost race
/// in plain language instead of surfacing the raw RPC chain. Matching keys
/// on this exact text across builds, so changing it is a wire-contract
/// change, not display copy.
pub const SHUTDOWN_REFUSAL: &str = "the daemon is shutting down";

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
             Restart the daemon on the new build: run `min stop --force` (the \
             plain stop is refused while sessions are live), then re-run this \
             command (the daemon is started again automatically). \
             Set {SKEW_OVERRIDE_VAR}=1 to proceed anyway."
        )
    })
}

/// How a user-namespace refusal opens (NET-141): the daemon formats a
/// create refused on the host's user-namespace verdict as this lead, the
/// cause (`sandbox::UsernsRestriction::cause`) closing the parenthesis,
/// and the cause's remedy for the daemon on a second line. Clients print
/// the daemon's text verbatim, as they do every create refusal, so nothing
/// on their side matches on the lead. Only the lead lives here: the cause
/// and remedy texts are `sandbox`'s, where the restriction is diagnosed
/// and both binaries that probe it already look.
pub const USER_NAMESPACE_REFUSAL_LEAD: &str =
    "this machine blocks the private sandbox every box runs in (";

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
/// The type is defined in the `boxes` crate — beside the
/// [`Record`](boxes::Record) field that carries a box's own launch
/// outcome, a session-plane type this crate already depends on — and
/// re-exported here so the paths this crate's clients spell stay what they
/// were: the listing's [`ListSessionsEntry::host_ip_enforcement`] answers in
/// it, and the stringly surfaces carry its machine spelling.
pub use boxes::HostIpEnforcement;

/// An entry in the ListSessions response.
///
/// `project_path` and `status` mirror the fields of the same name on the
/// session [`Record`](boxes::Record). They let a client resolve "which
/// session was built from this directory" and render a state glyph in a
/// picker without a follow-up `GetSessionRecord` round-trip per session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsEntry {
    pub id: SessionId,
    pub name: Option<String>,
    /// The absolute host path the session was built from. `None` on responses
    /// from daemons that predate this field — clients treat such entries as
    /// not matching the cwd but still listable/pickable. Always `Some` from a
    /// current daemon, since [`Record`](boxes::Record) requires the path.
    #[serde(default)]
    pub project_path: Option<paths::HostAbsPath>,
    /// The session's lifecycle status, used to render a state glyph in the
    /// interactive picker. Defaults to `Active` for daemons that predate the
    /// field so an older server still deserializes cleanly.
    #[serde(default)]
    pub status: boxes::BoxState,
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
    /// [`BoxRuntimeFacts::shared_port_collisions`] answers from, so a
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
    pub record: Option<boxes::Record>,
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
pub struct BoxConfig {
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
    pub policy: BoxPolicy,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when the activating client registered one: its switch
    /// address, which the in-VM daemon attaches with instead of drawing
    /// its own, and its published loopback address. `None` for every other
    /// activation — a host that is not minvmd-backed, a box that is not
    /// own-address — and the daemon then attaches exactly as it always
    /// has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_addresses: Option<BoxAddresses>,
    /// The task addresses the same registration handed (NET-138): the
    /// switch addresses the box's task runs attach at, each filed on the
    /// host under the box's own row. Empty for every activation that
    /// handed no box addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_addresses: Vec<std::net::Ipv4Addr>,
    /// The box id the same registration handed back
    /// ([`boxes::Record::box_id`]): the id the host's row of the box
    /// holds. `None` for every activation that handed no box addresses.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "boxes::box_id_hex::option"
    )]
    pub box_id: Option<BoxId>,
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
    /// The sealed value of each of the box's GitHub grants (BEP-007), as
    /// the creating client minted them for [`Self::box_id`]. The daemon
    /// copies them into the box's record, and every launch places each one
    /// in its grant's environment variable. Empty for a box with no grant.
    /// A daemon that predates the field ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed_deliveries: Vec<boxes::SealedDelivery>,
    /// The Box Egress Proxy's root certificate, PEM-encoded, for the box to
    /// trust. `None` until the proxy publishes the certificate
    /// (<https://github.com/gominimal/minimal/issues/2437>), and the daemon
    /// reads nothing from it yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate: Option<String>,
    /// The client verb that asked for the box. The daemon stamps the
    /// record's Box Type from it. A client that predates the field sends
    /// none, and the box is a session.
    #[serde(default)]
    pub creating_verb: CreatingVerb,
    /// The root of the project the box comes from: the directory that
    /// holds the project's `minimal.toml`, which can be a parent of
    /// [`Self::project_path`]. `None` from a client that predates the
    /// field. The daemon then records `project_path` as the root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<paths::HostAbsPath>,
}

/// The client verb that asked for a box ([`BoxConfig::creating_verb`]).
/// A closed set: a value outside it does not deserialize.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatingVerb {
    /// `min session activate`, or the dashboard's create.
    #[default]
    Session,
    /// `min task run`.
    Task,
}

/// Serde default for [`BoxConfig::hooks_enabled`]. See
/// [`boxes::Record::hooks_enabled`] for why this cannot be a bare
/// `#[serde(default)]`.
fn default_hooks_enabled() -> bool {
    true
}

/// A box's identity ([`boxes::BoxId`]): the one id type every request and
/// reply names a box by, the same type as [`SessionId`]. Defined beside the
/// record that is keyed on it, and re-exported under the path its clients
/// spell. A session reply spells it in the hyphenated form. The VM host's
/// box control wire spells it as 32 hex digits, through
/// [`boxes::box_id_hex`] on each of its fields. Both are the bytes each
/// reply carried before the two id types merged.
pub use boxes::BoxId;

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisteredBox {
    /// The box's address on the switch ([`BoxAddresses::switch_address`]).
    pub switch_address: std::net::Ipv4Addr,
    /// The box's published loopback address
    /// ([`BoxAddresses::loopback_address`]).
    pub loopback_address: std::net::Ipv4Addr,
    /// The box id the published row holds: the box's own UUIDv7, handed
    /// back to the registering client.
    #[serde(with = "boxes::box_id_hex")]
    pub box_id: BoxId,
    /// The task addresses filed with the box ([`RegisterBoxRequest::task_slots`]):
    /// one switch address per task slot, each a row of its own carrying
    /// the box's id and egress. Empty from a host that predates them, or
    /// for a registration that asked for none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub task_addresses: Vec<std::net::Ipv4Addr>,
}

/// How many task addresses an activation registers with its box: the
/// number of task runs (`min run` from inside the box, or a task run over
/// exec) one session holds an address for at once. Task runs are
/// interactive, so concurrency beyond a handful is rare, and the cost is
/// four addresses of a hand-out run of thousands on the default switch
/// (126 on a carved /24) — small enough that every own-address box can
/// pay it up front rather than draw inside the VM.
pub const TASK_SLOTS_PER_BOX: u8 = 4;

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
/// [`BoxConfig`]).
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
    /// How many task addresses to register with the box (NET-138): the
    /// host draws one switch address per slot and files each as a row
    /// carrying the box's id and egress, withdrawn with the box. Zero —
    /// the default, and what a client that predates the field sends —
    /// registers none.
    #[serde(default)]
    pub task_slots: u8,
}

/// The one line a held registration's client writes on the lease
/// connection once its session is active ([`RegisterBoxRequest::hold`]):
/// from then on the row stays when the connection closes.
pub const REGISTRATION_COMMIT_LINE: &str = "commit";

/// How each of the VM host daemon's address-capacity refusals of a
/// registration opens: the switch's hand-out run, the loopback slice, and
/// the machine's zone answerer, each with nothing left to hand out. The
/// refusal travels as a [`BoxControlReply::Error`] sentence; the daemon
/// spells these openings from here and the client classifies a refusal by
/// them ([`is_address_capacity_refusal`]), so the two cannot drift.
pub const SWITCH_PLAN_EXHAUSTED: &str = "the switch's address plan is exhausted";
/// See [`SWITCH_PLAN_EXHAUSTED`].
pub const LOOPBACK_SLICE_EXHAUSTED: &str = "the host's loopback slice is exhausted";
/// See [`SWITCH_PLAN_EXHAUSTED`]: the answerer's refusal, which names the
/// run after it.
pub const BOX_ADDRESSES_EXHAUSTED: &str = "every box address in";

/// Whether a registration refusal is the host running out of addresses
/// for a box — the host cannot hold one more — rather than a refusal of
/// this box's declaration. Matched anywhere in the sentence: the control
/// socket prefixes the answerer's reason with its own.
#[must_use]
pub fn is_address_capacity_refusal(error: &str) -> bool {
    [
        SWITCH_PLAN_EXHAUSTED,
        LOOPBACK_SLICE_EXHAUSTED,
        BOX_ADDRESSES_EXHAUSTED,
    ]
    .iter()
    .any(|opening| error.contains(opening))
}

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
/// A withdrawal ends the row's admissions and returns its addresses: the
/// switch address to the host's hand-out run, handed again only after its
/// reuse quarantine (or at once for a row no frame ever crossed the gate
/// under), and the published loopback address to the machine's answerer.
/// Because an address can be handed again, the withdrawal may name the
/// row's [`BoxId`] — the epoch the pair was handed under — so a stale
/// creator never removes a newer row holding the same name and addresses.
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
    /// The box id the registration handed back with the pair, when the
    /// withdrawing client holds it: a row at the pair under another id is
    /// a newer box, and the withdrawal is refused with
    /// [`BoxControlReply::Error`] rather than removing it. `None` from a
    /// client that predates the field, or one that no longer holds the id
    /// (a destroy reads the pair from the session record, which carries
    /// none): the pair proof alone decides, as before.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "boxes::box_id_hex::option"
    )]
    pub box_id: Option<BoxId>,
}

/// A creator's request for its box's row back
/// ([`BoxControlRequest::ResumeBox`], NET-138): the session that registered
/// the box presenting the pair — and the id, when it holds one — the
/// registration handed back, before it attaches to or runs in a box whose
/// row may have been withdrawn while nothing carried its frames: the box's
/// host ended and stayed down past the host's detach grace, or the VM host
/// daemon restarted under it.
///
/// The pair is the proof and the lookup key, as for a withdrawal
/// ([`WithdrawBoxRequest`]); every fact the reinstated row holds comes from
/// the host's own record of the registration, never from this request.
/// Answered with [`BoxControlReply::Registered`] — the row's addresses and
/// box id — whether the row stood or was reinstated, or with
/// [`BoxControlReply::Error`] when the host holds no registration of the
/// box the pair proves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeBoxRequest {
    /// The name the box was registered under.
    pub name: String,
    /// The switch address the registration handed back.
    pub switch_address: std::net::Ipv4Addr,
    /// The loopback address the registration handed back.
    pub loopback_address: std::net::Ipv4Addr,
    /// The box id the registration handed back, when the resuming client
    /// holds it: a registration of the name under another id is a newer
    /// box, and the resume is refused. `None` when the client holds no id
    /// (the session record carries none): the pair proof alone decides.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "boxes::box_id_hex::option"
    )]
    pub box_id: Option<BoxId>,
}

/// The in-VM daemon's read of whether the host still holds a row at its
/// box's switch address ([`BoxControlRequest::RowStanding`], NET-138):
/// asked before the daemon relaunches a box's host after the host it ran
/// ended, so the box rejoins the switch only while the host's row stands
/// for it. A read, never a report: the answer is the host's own table,
/// and the request changes nothing in it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RowStandingRequest {
    /// The switch address the host-side registration handed the box.
    pub switch_address: std::net::Ipv4Addr,
    /// The box id the same registration handed back: the row is answered
    /// as standing only when it is this box's own row. `None`, from a
    /// record that carries no id, is never answered as standing.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "boxes::box_id_hex::option"
    )]
    pub box_id: Option<BoxId>,
}

/// A name to hold in the host's zone without a row behind it
/// ([`BoxControlRequest::HoldBoxName`]): the interim a `host_ip` box's
/// name answers NODATA — the box exists, no address to tell — instead
/// of NXDOMAIN. Answered with [`BoxControlReply::NameHeld`]; idempotent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldBoxNameRequest {
    /// The box's name, as the session's create names it: the label the
    /// zone holds under the apex, normalized there.
    pub name: String,
    /// The session the hold is for. A hold records it, and a release that
    /// carries it frees only that session's holds, wherever a rename moved
    /// them, never a newer session's under the same name. `None` from a
    /// client that predates the field: the release is by name alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<boxes::SessionId>,
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
    #[serde(with = "boxes::box_id_hex")]
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
    #[serde(with = "boxes::box_id_hex")]
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
    #[serde(with = "boxes::box_id_hex")]
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
    /// Hold a `host_ip` box's name in the host's zone with no row behind
    /// it ([`HoldBoxNameRequest`]): the interim that answers NODATA until
    /// the node's bind mirror lands. Served on the host's control socket
    /// only, answered with [`BoxControlReply::NameHeld`].
    HoldBoxName(HoldBoxNameRequest),
    /// Release a name [`BoxControlRequest::HoldBoxName`] holds: the box's
    /// session is gone, so the name answers nothing again. Answered with
    /// [`BoxControlReply::NameHeld`]; a name no hold kept is the goal
    /// state already holding.
    ReleaseBoxName(HoldBoxNameRequest),
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
    /// A creator's request for its box's row back ([`ResumeBoxRequest`],
    /// NET-138): served on the host's control socket only, answered with
    /// [`BoxControlReply::Registered`].
    ResumeBox(ResumeBoxRequest),
    /// The in-VM daemon's read of whether its box's row stands
    /// ([`RowStandingRequest`]): carried on the daemon's own control
    /// channel, answered with [`BoxControlReply::RowStanding`].
    RowStanding(RowStandingRequest),
    /// The in-VM daemon's read of whether the Box Egress Proxy's listener is
    /// live on the host (BEP-062): carried on the daemon's own control
    /// channel, answered with [`BoxControlReply::ProxyListening`]. A read,
    /// never a report: the proxy runs on the host, outside the VM, so the
    /// guest can only ask. The DNS gate of a `dns` or `both` box answers a
    /// steered name with the proxy's address only while the answer is
    /// `true`, and SERVFAIL otherwise.
    ProxyListening,
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

/// The hostname proxy's terminal publish outcome the status reply carries
/// beside the answerer's state (T93): the port the failure is about, and
/// its named cause. A sibling of [`ZoneAnswererStatus`] on
/// [`AnswererStatusReply`], never a replacement for it — the answerer's
/// state is a fact about the machine's zone answerer and the proxy's
/// publish outcome a fact about the proxy, and one reply can carry both
/// without either substituting for the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDown {
    /// The port the supervisor reserved and the guest could not publish.
    pub port: u16,
    /// What kept the proxy from serving on that port.
    pub cause: ProxyDownCause,
}

/// The answerer-status verb's answer (T93): the machine's zone-answerer
/// state as the daemon holds it ([`ZoneAnswererStatus`]), with the
/// hostname proxy's publish outcome — when the supervisor reached a cause
/// that names one — riding beside it as [`Self::proxy_down`] rather than
/// in place of it. The proxy-down cause is a fact about the proxy, never
/// a state of the answerer: substituting it for the answerer's state
/// dropped the zone-answerer facts entirely, leaving the CLI unable to
/// name who answers the zone or to probe for native DNS while the proxy
/// was down or its publish unconfirmed.
///
/// The wire shape is the status's own flat document — `state` at the top
/// level — with `proxy_down` an optional sibling key: a client that
/// predates the field ignores it (unknown fields are not refused), and a
/// client that knows it reads `None` from a daemon that predates it. The
/// older substituting shape — `state: "proxy_not_serving"` naming no
/// answerer fact — stays a variant a new client still parses, for the
/// daemons that still send it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnswererStatusReply {
    /// The machine's zone-answerer state, flattened so `state` stays at
    /// the document's top level, exactly where every reader of the
    /// status verb looks for it.
    #[serde(flatten)]
    pub answerer: ZoneAnswererStatus,
    /// Why this VM's hostname proxy is not serving, when the supervisor
    /// reached a cause that names it: the port the failure is about and
    /// its cause. `None` in every state where the status says nothing
    /// about the proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_down: Option<ProxyDown>,
}

impl<'de> Deserialize<'de> for AnswererStatusReply {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Manual on purpose: `flatten` inside an untagged variant's
        // payload is a shape serde cannot deserialize (it buffers into a
        // private format the untagged machinery rejects), so the reply
        // splits instead — the document whole, the sibling key out, the
        // rest through the status's own tagged shape, and the sibling
        // parsed as the fact it names.
        let whole = serde_json_lenient::Value::deserialize(deserializer)?;
        let mut object = match whole {
            serde_json_lenient::Value::Object(map) => map,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "the answerer status is a JSON object; got {other}"
                )));
            }
        };
        // The sibling is read leniently: a cause this client does not know
        // (a newer daemon's variant) reads as no proxy fact, never as a
        // decode failure that would drop the answerer's state with it —
        // the displacement the sibling exists to remove.
        let proxy_down = object
            .remove("proxy_down")
            .and_then(|value| serde_json_lenient::from_value::<Option<ProxyDown>>(value).ok())
            .flatten();
        let answerer = serde_json_lenient::from_value(serde_json_lenient::Value::Object(object))
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            answerer,
            proxy_down,
        })
    }
}

/// The addresses a successful registration hands back
/// ([`boxes::BoxAddresses`]): the box's switch address and its published
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
/// [`PortRecorded`](Self::PortRecorded) its `proto`,
/// [`NameHeld`](Self::NameHeld) its `held` — so no document of
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
        #[serde(with = "boxes::box_id_hex")]
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
    /// A hold or a release was answered: the name back, `held` saying
    /// which — `true` a hold the table now keeps, `false` a release that
    /// freed one (or found none).
    NameHeld {
        /// The name the hold or the release was about.
        name: String,
        /// The marker: whether the table holds the name now.
        held: bool,
    },
    /// The verb failed: `error` is a sentence naming why, for the client to
    /// warn with.
    Error { error: String },
    /// The answerer-status read succeeded: the state of the machine's
    /// zone answerer as the daemon holds it, with the hostname proxy's
    /// publish outcome riding beside it as a sibling rather than in
    /// place of it ([`AnswererStatusReply`] — T93). The flat `state` key
    /// stays where every reader of the status verb looks for it, so an
    /// older client still parses the answerer state and merely misses
    /// the sibling.
    Status(AnswererStatusReply),
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
    /// The row-standing read's answer: whether the host holds a row at the
    /// switch address asked about. `row_standing` is required — the marker
    /// that keeps this document from decoding as any other reply.
    RowStanding {
        /// The switch address that was asked about.
        switch_address: std::net::Ipv4Addr,
        /// Whether a row stands at it.
        row_standing: bool,
    },
    /// The proxy-listening read's answer: whether the Box Egress Proxy's
    /// listener is live on the host. `false` when the host runs no proxy.
    /// `listening` is required — the marker that keeps this document from
    /// decoding as any other reply.
    ProxyListening {
        /// Whether the proxy's listener is live.
        listening: bool,
    },
}

/// The request for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    /// Out-of-band session config.
    pub config: BoxConfig,
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

impl CreateSessionRequest {
    /// A create request for a box named `name` over `project_path`, with
    /// the given network mode and policy. Everything else takes the value
    /// a plain create sends: no handed addresses or box id, no task
    /// addresses, hooks on, no attrs, no sealed deliveries, no root
    /// certificate, the session verb, no project root, and no version
    /// assertion.
    pub fn new(
        name: impl Into<String>,
        project_path: paths::HostAbsPath,
        network: NetworkMode,
        policy: BoxPolicy,
    ) -> Self {
        Self {
            config: BoxConfig {
                name: Some(name.into()),
                project_path,
                network,
                policy,
                task_addresses: Vec::new(),
                box_id: None,
                box_addresses: None,
                hooks_enabled: default_hooks_enabled(),
                attrs: Default::default(),
                sealed_deliveries: Vec::new(),
                root_certificate: None,
                creating_verb: CreatingVerb::default(),
                project_root: None,
            },
            must_match_version: None,
        }
    }
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
    /// ([`boxes::EGRESS_DEFAULT_PHASE`]), but the opt-out is set on the
    /// daemon alone. Carried here — on the reply the activation path
    /// already holds — so `min session activate` can keep its in-force note
    /// (NET-074) off a deployment that opted out: its bare boxes keep
    /// allow-all, and a note saying deny-all would be false there. (The
    /// field first carried the announcement, NET-076, now retired; it stays
    /// for client and daemon skew.)
    ///
    /// `None` from a daemon that predates the field — and a daemon that
    /// predates it cannot have the opt-out flag either, so a client reading
    /// `None` reads it as not opted out.
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
    pub contribution: boxes::wire::request::WireContribution,
}

/// The response for a [`ConfigureLoadout`] RPC.
///
/// Both variants are part of the Phase 2 flow and reachable on the
/// wire: `Materialized` when the daemon's composer finalizes in one
/// shot (the session record is now
/// [`Materializing`](boxes::BoxState::Materializing), not
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
    /// [`Materializing`](boxes::BoxState::Materializing).
    /// The client still has to upload the composition's patches
    /// and call `FinalizeSession` before the session becomes
    /// attachable.
    Materialized,
    /// Items need client-side gating. The session stays in
    /// [`Pending`](boxes::BoxState::Pending); the client
    /// follows up with `SubmitVerdict` carrying the same id.
    Pending {
        /// Pending items the client must gate.
        response: boxes::wire::request::ContributionResponse,
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
    /// Destroy the session only if it has not finished activating (record
    /// not yet `Active`), decided by the session itself after any finalize
    /// already in flight: the destroy a client sends to clean up an
    /// activation it gave up on (inbox#690). Absent, as from a client that
    /// predates it, the destroy is unconditional, as it always was.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub only_if_unfinalized: bool,
}

/// How a [`DestroySession`] for an id the daemon holds no record of opens:
/// the daemon formats that refusal as this lead followed by the quoted id.
/// The client matches on it to tell an already-destroyed session (the
/// loser of two concurrent destroys) from a destroy that failed, so both
/// sides read the one constant rather than each spelling the text.
pub const UNKNOWN_SESSION_ID_LEAD: &str = "no session with ID";

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
    /// The destroy was `only_if_unfinalized` and the session had finished:
    /// it was kept, and is live. Only ever set in answer to such a request,
    /// so a client that predates the flag never sees it.
    pub kept: bool,
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
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    kept: bool,
}

impl From<DestroySessionResponseWire> for DestroySessionResponse {
    fn from(wire: DestroySessionResponseWire) -> Self {
        match wire {
            DestroySessionResponseWire::Unit(()) => Self::default(),
            DestroySessionResponseWire::Fields(f) => Self {
                hook_failures: f.hook_failures,
                kept: f.kept,
            },
        }
    }
}

impl From<DestroySessionResponse> for DestroySessionResponseWire {
    fn from(resp: DestroySessionResponse) -> Self {
        if resp.hook_failures.is_empty() && !resp.kept {
            Self::Unit(())
        } else {
            Self::Fields(DestroySessionResponseFields {
                hook_failures: resp.hook_failures,
                kept: resp.kept,
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
/// [`BoxStep::Materialized`](boxes::wire::request::BoxStep::Materialized);
/// the client still has to upload patches and call
/// `FinalizeSession` before the session is attachable.
/// A `Fault` reply carries a structured
/// [`WireError`](boxes::wire::errors::WireError) —
/// `UnknownSessionId` for a verdict against no stashed session,
/// `WrongState` if the record isn't `Pending`, or an
/// `InvalidContribution` / `Internal` reflecting a failed
/// `resume_from_verdict`.
pub struct SubmitVerdict;

impl OneshotSshRpc for SubmitVerdict {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SubmitVerdict");
    type Request<'a> = boxes::wire::request::ContributionVerdict;
    type Response = Errorable<boxes::wire::request::BoxStep>;
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
// `PortMapping`, `EgressPolicy`, `IngressPolicy`, `BoxPolicy`, and the
// effective halves (`EffectiveEgress`, `EffectiveBoxPolicy`) are defined
// in `boxes` and re-exported above, so the only live per-session store
// (`boxes::Record`) can carry the policy configured at launch without a
// `boxes` → `minimald-rpc` dependency cycle. The RPC method types below
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
    type Response = Errorable<BoxPolicy>;
}

/// An RPC to read the *effective* networking policy for a session: the same
/// record [`GetSessionPolicy`] serves, with its egress half resolved to what
/// the gate enforces (NET-075) — the answer `min session policy` renders.
///
/// A separate response rather than a field on [`BoxPolicy`], so the
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
    type Response = Errorable<EffectiveBoxPolicy>;
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
/// A separate response rather than a field on [`EffectiveBoxPolicy`], for
/// the same reason the effective halves are separate from the strict
/// [`BoxPolicy`] at all: the declaration is a fact about the launch, and
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
/// A separate reply rather than a field on [`EffectiveBoxPolicy`] because
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
pub struct BoxRuntimeFacts {
    /// The session these facts are about: the record the daemon read them
    /// from. Required, so the daemon's error reply never decodes as facts.
    pub id: SessionId,
    /// The per-box egress enforcement the session's box actually runs under
    /// (NET-079): the box's own launch record —
    /// [`Record::host_ip_enforcement`](boxes::Record) — lowered to `none`
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
    type Response = Errorable<BoxRuntimeFacts>;
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
    type Response = Errorable<Vec<boxes::wire::primitives::WireProvenancedHook>>;
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
mod tests;
