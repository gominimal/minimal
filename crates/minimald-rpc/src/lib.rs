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

pub mod trace;

pub use sessions::{EgressPolicy, IngressPolicy, IpProto, NetworkMode, PortMapping, SessionPolicy};

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
    pub attrs: Option<RunningSessionAttrs>,
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
    /// Whether the session runs the lifecycle hooks composed into it.
    /// Cleared by `min session activate --no-hooks`, and persisted onto
    /// the session record so the later attach/detach/destroy
    /// transitions — which run from processes that never saw the
    /// activating command — honour the same choice. Defaults to `true`
    /// so a client that predates the field gets hooks, not silence.
    #[serde(default = "default_hooks_enabled")]
    pub hooks_enabled: bool,
    /// Free-form attributes (typed by the caller).
    #[serde(default)]
    pub attrs: std::collections::BTreeMap<String, String>,
}

/// Serde default for [`SessionConfig::hooks_enabled`]. See
/// [`sessions::Record::hooks_enabled`] for why this cannot be a bare
/// `#[serde(default)]`.
fn default_hooks_enabled() -> bool {
    true
}

/// The request for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    /// Out-of-band session config.
    pub config: SessionConfig,
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
}

/// One hook that ran, as reported back to the client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RanHook {
    /// Where it was declared, e.g. ``user loadout `dev` ``.
    pub declared_by: String,
    /// The hook's own description, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DestroySessionResponse;

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
// `PortMapping`, `EgressPolicy`, `IngressPolicy`, and `SessionPolicy` are
// defined in `sessions` and re-exported above, so the only live per-session
// store (`sessions::Record`) can carry the policy configured at launch without
// a `sessions` → `minimald-rpc` dependency cycle. The RPC method types below
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
// mTLS client certificate issuance (R4.4 / `minimal login`).
// ---------------------------------------------------------------------------

/// An RPC that signs and returns a fresh client certificate for use with the
/// HTTPS reverse proxy's mTLS authentication (R4.4). The caller supplies a
/// subject common name; the daemon generates a key pair, signs the certificate
/// with its internal CA, and returns PEM-encoded certificate and private key.
/// The CA certificate PEM is also returned so the client can add it to
/// its trust store.
pub struct IssueClientCert;

/// Request for the [`IssueClientCert`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueClientCertRequest {
    /// Subject common name for the client certificate (e.g. the OS username).
    pub subject_cn: String,
}

/// Response for the [`IssueClientCert`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IssueClientCertResponse {
    /// PEM-encoded client certificate signed by the daemon's CA.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 private key matching the certificate.
    pub key_pem: String,
    /// PEM-encoded CA certificate, so the client can trust the HTTPS proxy's
    /// server certificate.
    pub ca_cert_pem: String,
}

impl OneshotSshRpc for IssueClientCert {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "IssueClientCert");
    type Request<'a> = IssueClientCertRequest;
    type Response = Errorable<IssueClientCertResponse>;
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
        };
        let json = serde_json_lenient::to_string(&policy).unwrap();
        assert!(json.contains("\"egress\":null"), "got: {json}");
        assert!(json.contains("\"port_mappings\":[]"), "got: {json}");
        assert!(
            json.contains("\"dynamic_allowed_range\":null"),
            "got: {json}"
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
                ingress: None
            })
        );
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
                // The non-default (`--no-hooks`): `true` is the serde
                // default, so a fixture using it would round-trip green
                // even if the field never reached the wire.
                hooks_enabled: false,
                attrs: [("color".to_string(), "blue".to_string())]
                    .into_iter()
                    .collect(),
            },
        };
        assert_eq!(round_trip(&req), req);
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
        };
        assert_eq!(round_trip(&resp), resp);
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
}
