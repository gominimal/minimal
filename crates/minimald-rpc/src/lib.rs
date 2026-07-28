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
    /// Free-form attributes (typed by the caller).
    #[serde(default)]
    pub attrs: std::collections::BTreeMap<String, String>,
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

/// The response for a [`FinalizeSession`] RPC — a unit-shaped ack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeSessionResponse;

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
// GitHub-integrated sessions (spec 10): daemon-held auth, mediated repo access,
// PR on exit.
//
// SECURITY (hard rule): no request or response type in this section may be
// capable of carrying GitHub token material. Only the daemon ever holds the
// user/refresh token; it never crosses this wire. Fields here carry logins,
// grant *identifiers*, branch/base names, public URLs (PR links, install
// links), scope labels, and human-readable *scrubbed* status/error lines — but
// never a token, and no field that could be spliced into a credentialed URL.
//
// Repositories and scopes cross the wire as PLAIN STRINGS so this crate gains
// no new dependency. The single grammars live in the `github` crate
// (`github::RepoSpec` for `owner/repo[@branch[:base]]`, `github::Scope` for
// permission labels such as `contents:write`); both sides parse at the edges.
// Parsing is deliberately NOT duplicated here.
//
// Every type is `#[non_exhaustive]` and `#[serde(default)]` per field so new
// fields can be added without breaking old peers, and old-shape payloads
// (missing the new fields) still decode. Method responses are `Errorable`-
// wrapped like the other RPCs, so transport/daemon errors surface as
// `Errorable::Err { error }` distinct from the in-band domain states.
// ---------------------------------------------------------------------------

/// An RPC that begins the GitHub App **device flow** on the daemon (R1.1).
///
/// The daemon requests a device+user code from GitHub and returns the
/// verification URL and `user_code` for the `min` CLI to display, plus a
/// `login_id` handle the client polls with [`GithubPollLogin`]. When no GitHub
/// App client id is configured on the daemon, this answers with
/// `Errorable::Err` carrying an actionable, non-secret message.
pub struct GithubBeginLogin;

/// Request for the [`GithubBeginLogin`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubBeginLoginRequest {
    /// Requested permission scopes as plain labels (e.g. `contents:write`),
    /// parsed at the edges via `github::Scope`. Empty applies the daemon's
    /// least-privilege defaults (R5.1).
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl GithubBeginLoginRequest {
    #[must_use]
    pub fn new(scopes: Vec<String>) -> Self {
        Self { scopes }
    }
}

/// Response for the [`GithubBeginLogin`] RPC: the device-flow prompt data.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubBeginLoginResponse {
    /// The URL the user opens in a browser to enter their `user_code`.
    #[serde(default)]
    pub verification_uri: String,
    /// The short code the user types at `verification_uri`.
    #[serde(default)]
    pub user_code: String,
    /// Opaque handle identifying this in-flight login; passed back to
    /// [`GithubPollLogin`].
    #[serde(default)]
    pub login_id: String,
    /// Minimum seconds the client must wait between [`GithubPollLogin`] calls,
    /// per GitHub's device-flow `interval`.
    #[serde(default)]
    pub poll_interval_secs: u64,
    /// Seconds until the device code expires and the login must be restarted.
    #[serde(default)]
    pub expires_in_secs: u64,
}

impl GithubBeginLoginResponse {
    #[must_use]
    pub fn new(
        verification_uri: String,
        user_code: String,
        login_id: String,
        poll_interval_secs: u64,
        expires_in_secs: u64,
    ) -> Self {
        Self {
            verification_uri,
            user_code,
            login_id,
            poll_interval_secs,
            expires_in_secs,
        }
    }
}

impl OneshotSshRpc for GithubBeginLogin {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubBeginLogin");
    type Request<'a> = GithubBeginLoginRequest;
    type Response = Errorable<GithubBeginLoginResponse>;
}

/// An RPC to poll an in-flight device-flow login for completion (R1.1).
pub struct GithubPollLogin;

/// Request for the [`GithubPollLogin`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubPollLoginRequest {
    /// The [`GithubBeginLoginResponse::login_id`] to poll.
    #[serde(default)]
    pub login_id: String,
}

impl GithubPollLoginRequest {
    #[must_use]
    pub fn new(login_id: String) -> Self {
        Self { login_id }
    }
}

/// In-band domain state of a polled device-flow login.
///
/// These are the flow's own states, distinct from transport errors (which the
/// `Errorable` wrapper carries). `Pending` means keep polling; `Complete`
/// means the daemon stored a grant; `Failed`/`Expired` are terminal.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GithubPollLoginResponse {
    /// The user has not yet approved; poll again after the interval.
    Pending,
    /// The login completed and a grant was stored. Carries the authenticated
    /// GitHub `login` and the daemon-assigned `grant_id` (never a token).
    Complete {
        #[serde(default)]
        login: String,
        #[serde(default)]
        grant_id: String,
    },
    /// The login failed terminally (e.g. access denied). `message` is an
    /// actionable, non-secret description.
    Failed {
        #[serde(default)]
        message: String,
    },
    /// The device code expired before approval; the user must restart login.
    Expired,
}

impl OneshotSshRpc for GithubPollLogin {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubPollLogin");
    type Request<'a> = GithubPollLoginRequest;
    type Response = Errorable<GithubPollLoginResponse>;
}

/// An RPC for `min github status` self-diagnosis (R1.4 / R8.2): identity,
/// token validity/expiry, per-repo App-installation state, and the per-session
/// repo/branch/scope table.
pub struct GithubStatus;

/// Request for the [`GithubStatus`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubStatusRequest {
    /// When set, include the per-session repo/branch/scope table for this
    /// session in the response.
    #[serde(default)]
    pub session_id: Option<SessionId>,
    /// Additional `owner/repo` strings to report App-installation state for,
    /// beyond any the session declares. Parsed at the edges via
    /// `github::RepoSpec`.
    #[serde(default)]
    pub repos: Vec<String>,
}

impl GithubStatusRequest {
    #[must_use]
    pub fn new(session_id: Option<SessionId>, repos: Vec<String>) -> Self {
        Self { session_id, repos }
    }
}

/// The authenticated GitHub identity behind a grant (metadata only).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubIdentity {
    /// The authenticated GitHub login (username).
    #[serde(default)]
    pub login: String,
    /// The daemon-assigned grant identifier (never a token).
    #[serde(default)]
    pub grant_id: String,
}

impl GithubIdentity {
    #[must_use]
    pub fn new(login: String, grant_id: String) -> Self {
        Self { login, grant_id }
    }
}

/// Per-repo GitHub App installation state (R1.5): whether the App is installed
/// on the repo/org, and if not, where to install it.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoInstallationStatus {
    /// The `owner/repo` this entry describes.
    #[serde(default)]
    pub repo: String,
    /// Whether the GitHub App is installed with access to this repo.
    #[serde(default)]
    pub installed: bool,
    /// Where to install/configure the App when `installed` is false; a public
    /// github.com URL, never credentialed.
    #[serde(default)]
    pub install_url: Option<String>,
}

impl RepoInstallationStatus {
    #[must_use]
    pub fn new(repo: String, installed: bool, install_url: Option<String>) -> Self {
        Self {
            repo,
            installed,
            install_url,
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

/// One row of the per-session repo/branch/scope table (R8.2).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRepoStatus {
    /// The `owner/repo` this row describes.
    #[serde(default)]
    pub repo: String,
    /// The working branch prepared for this repo in the session.
    #[serde(default)]
    pub branch: String,
    /// The base branch the working branch was created from, if applicable.
    #[serde(default)]
    pub base: Option<String>,
    /// The resolved permission scopes for this repo, as plain labels.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl SessionRepoStatus {
    #[must_use]
    pub fn new(repo: String, branch: String, base: Option<String>, scopes: Vec<String>) -> Self {
        Self {
            repo,
            branch,
            base,
            scopes,
        }
    }
}

/// Response for the [`GithubStatus`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubStatusResponse {
    /// The active identity, or `None` when the daemon holds no usable grant.
    #[serde(default)]
    pub identity: Option<GithubIdentity>,
    /// Whether the current user token is valid (refreshable counts as valid).
    #[serde(default)]
    pub token_valid: bool,
    /// When the current user token expires, if known.
    #[serde(default)]
    pub token_expires_at: Option<chrono::DateTime<Utc>>,
    /// Per-repo App-installation state for the requested/known repos.
    #[serde(default)]
    pub installations: Vec<RepoInstallationStatus>,
    /// The per-session repo/branch/scope table, when a session was requested.
    #[serde(default)]
    pub session_repos: Vec<SessionRepoStatus>,
}

impl GithubStatusResponse {
    #[must_use]
    pub fn new(
        identity: Option<GithubIdentity>,
        token_valid: bool,
        token_expires_at: Option<chrono::DateTime<Utc>>,
        installations: Vec<RepoInstallationStatus>,
        session_repos: Vec<SessionRepoStatus>,
    ) -> Self {
        Self {
            identity,
            token_valid,
            token_expires_at,
            installations,
            session_repos,
        }
    }
}

impl OneshotSshRpc for GithubStatus {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubStatus");
    type Request<'a> = GithubStatusRequest;
    type Response = Errorable<GithubStatusResponse>;
}

/// An RPC to list stored auth grants as METADATA only — the reuse-or-mint
/// substrate (R1.3 / R6.4). No token material crosses the wire.
pub struct GithubListAuths;

/// Request for the [`GithubListAuths`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubListAuthsRequest {}

impl GithubListAuthsRequest {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

/// Metadata describing one stored auth grant (never a token).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantMetadata {
    /// The daemon-assigned grant identifier.
    #[serde(default)]
    pub grant_id: String,
    /// The GitHub login this grant authenticates as.
    #[serde(default)]
    pub login: String,
    /// When the grant was first stored, if known.
    #[serde(default)]
    pub created_at: Option<chrono::DateTime<Utc>>,
    /// The permission scopes bound to this grant, as plain labels.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The `owner/repo` strings this grant is scoped to.
    #[serde(default)]
    pub repos: Vec<String>,
    /// Whether the grant's token is currently valid (refreshable counts).
    #[serde(default)]
    pub token_valid: bool,
    /// When the grant's user token expires, if known.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

impl GrantMetadata {
    #[must_use]
    pub fn new(
        grant_id: String,
        login: String,
        created_at: Option<chrono::DateTime<Utc>>,
        scopes: Vec<String>,
        repos: Vec<String>,
        token_valid: bool,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Self {
        Self {
            grant_id,
            login,
            created_at,
            scopes,
            repos,
            token_valid,
            expires_at,
        }
    }
}

/// Response for the [`GithubListAuths`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubListAuthsResponse {
    /// The stored grants, metadata only.
    #[serde(default)]
    pub grants: Vec<GrantMetadata>,
}

impl GithubListAuthsResponse {
    #[must_use]
    pub fn new(grants: Vec<GrantMetadata>) -> Self {
        Self { grants }
    }
}

impl OneshotSshRpc for GithubListAuths {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubListAuths");
    type Request<'a> = GithubListAuthsRequest;
    type Response = Errorable<GithubListAuthsResponse>;
}

/// An RPC to forget a stored auth grant (`min github logout`).
pub struct GithubLogout;

/// Request for the [`GithubLogout`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubLogoutRequest {
    /// The grant to forget. The daemon rejects an empty id rather than
    /// guessing (fail-closed).
    #[serde(default)]
    pub grant_id: String,
}

impl GithubLogoutRequest {
    #[must_use]
    pub fn new(grant_id: String) -> Self {
        Self { grant_id }
    }
}

/// Response for the [`GithubLogout`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubLogoutResponse {
    /// Whether a grant was found and removed (`false` = nothing matched).
    #[serde(default)]
    pub removed: bool,
}

impl GithubLogoutResponse {
    #[must_use]
    pub fn new(removed: bool) -> Self {
        Self { removed }
    }
}

impl OneshotSshRpc for GithubLogout {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubLogout");
    type Request<'a> = GithubLogoutRequest;
    type Response = Errorable<GithubLogoutResponse>;
}

/// An RPC to pre-prime one or more repos into a session's workspace (R2):
/// clone + checkout-or-create each branch using the daemon-held token.
pub struct GithubPrimeRepos;

/// Request for the [`GithubPrimeRepos`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubPrimeReposRequest {
    /// The session whose workspace receives the primed repos.
    #[serde(default = "SessionId::nil")]
    pub session_id: SessionId,
    /// The repos to prepare, as `owner/repo[@branch[:base]]` strings parsed at
    /// the edges via `github::RepoSpec`.
    #[serde(default)]
    pub repos: Vec<String>,
    /// The grant whose token authorizes the clone/fetch.
    #[serde(default)]
    pub grant_id: String,
}

impl GithubPrimeReposRequest {
    #[must_use]
    pub fn new(session_id: SessionId, repos: Vec<String>, grant_id: String) -> Self {
        Self {
            session_id,
            repos,
            grant_id,
        }
    }
}

/// How a single repo's branch was prepared (R2.2 checkout-or-create), or why
/// it failed. `#[non_exhaustive]` so new outcomes can be added later.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RepoPrimeOutcome {
    /// The requested branch existed on the remote and was checked out.
    CheckedOut,
    /// The requested branch did not exist and was created from the base.
    Created,
    /// Priming this repo failed; `message` is actionable and non-secret and
    /// the repo's directory was rolled back (R2.6).
    Failed {
        #[serde(default)]
        message: String,
    },
}

/// The result of priming a single repo.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoPrimeResult {
    /// The `owner/repo` this result describes.
    #[serde(default)]
    pub repo: String,
    /// The working branch that was prepared.
    #[serde(default)]
    pub branch: String,
    /// The base branch used when the working branch had to be created.
    #[serde(default)]
    pub base: Option<String>,
    /// What happened for this repo.
    pub outcome: RepoPrimeOutcome,
}

impl RepoPrimeResult {
    #[must_use]
    pub fn new(
        repo: String,
        branch: String,
        base: Option<String>,
        outcome: RepoPrimeOutcome,
    ) -> Self {
        Self {
            repo,
            branch,
            base,
            outcome,
        }
    }
}

/// Response for the [`GithubPrimeRepos`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubPrimeReposResponse {
    /// Per-repo results, in request order.
    #[serde(default)]
    pub results: Vec<RepoPrimeResult>,
}

impl GithubPrimeReposResponse {
    #[must_use]
    pub fn new(results: Vec<RepoPrimeResult>) -> Self {
        Self { results }
    }
}

impl OneshotSshRpc for GithubPrimeRepos {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubPrimeRepos");
    type Request<'a> = GithubPrimeReposRequest;
    type Response = Errorable<GithubPrimeReposResponse>;
}

/// An RPC for an explicit, never-automatic push through the daemon (R3.4).
pub struct GithubPush;

/// Request for the [`GithubPush`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubPushRequest {
    /// The session whose workspace holds the repo.
    #[serde(default = "SessionId::nil")]
    pub session_id: SessionId,
    /// The `owner/repo` within the session to push.
    #[serde(default)]
    pub repo: String,
    /// The branch to push; `None` pushes the repo's current branch.
    #[serde(default)]
    pub branch: Option<String>,
}

impl GithubPushRequest {
    #[must_use]
    pub fn new(session_id: SessionId, repo: String, branch: Option<String>) -> Self {
        Self {
            session_id,
            repo,
            branch,
        }
    }
}

/// Response for the [`GithubPush`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubPushResponse {
    /// The `owner/repo` that was pushed.
    #[serde(default)]
    pub repo: String,
    /// The branch that was pushed.
    #[serde(default)]
    pub branch: String,
    /// Whether any refs were updated (`false` = already up to date).
    #[serde(default)]
    pub pushed: bool,
    /// A human-readable, token-scrubbed summary of what git reported.
    #[serde(default)]
    pub summary: String,
}

impl GithubPushResponse {
    #[must_use]
    pub fn new(repo: String, branch: String, pushed: bool, summary: String) -> Self {
        Self {
            repo,
            branch,
            pushed,
            summary,
        }
    }
}

impl OneshotSshRpc for GithubPush {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubPush");
    type Request<'a> = GithubPushRequest;
    type Response = Errorable<GithubPushResponse>;
}

/// An RPC to open (or surface an existing) pull request (R4): the daemon
/// creates it with the user token so it is authored by the real user.
pub struct GithubCreatePr;

/// Request for the [`GithubCreatePr`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubCreatePrRequest {
    /// The session whose workspace holds the repo.
    #[serde(default = "SessionId::nil")]
    pub session_id: SessionId,
    /// The `owner/repo` to open the PR against.
    #[serde(default)]
    pub repo: String,
    /// The head branch; `None` uses the repo's current branch.
    #[serde(default)]
    pub head: Option<String>,
    /// The base branch; `None` uses the branch's bound base / repo default.
    #[serde(default)]
    pub base: Option<String>,
    /// The PR title.
    #[serde(default)]
    pub title: String,
    /// The PR body (may be pre-populated from a repo PR template client-side).
    #[serde(default)]
    pub body: String,
    /// Whether to open the PR as a draft.
    #[serde(default)]
    pub draft: bool,
}

impl GithubCreatePrRequest {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        repo: String,
        head: Option<String>,
        base: Option<String>,
        title: String,
        body: String,
        draft: bool,
    ) -> Self {
        Self {
            session_id,
            repo,
            head,
            base,
            title,
            body,
            draft,
        }
    }
}

/// Response for the [`GithubCreatePr`] RPC: the created-or-existing PR (R4.5).
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubCreatePrResponse {
    /// The public PR URL (github.com), never credentialed.
    #[serde(default)]
    pub url: String,
    /// The PR number.
    #[serde(default)]
    pub number: u64,
    /// Whether an open PR already existed for this head (surfaced, not
    /// duplicated).
    #[serde(default)]
    pub already_existed: bool,
}

impl GithubCreatePrResponse {
    #[must_use]
    pub fn new(url: String, number: u64, already_existed: bool) -> Self {
        Self {
            url,
            number,
            already_existed,
        }
    }
}

impl OneshotSshRpc for GithubCreatePr {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GithubCreatePr");
    type Request<'a> = GithubCreatePrRequest;
    type Response = Errorable<GithubCreatePrResponse>;
}

/// An RPC to read a session's per-repo git state for the exit-PR prompt (R4.6):
/// each repo's branch/base, commits ahead of base, and any existing PR URL.
pub struct GetSessionGitState;

/// Request for the [`GetSessionGitState`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetSessionGitStateRequest {
    /// The session to inspect.
    #[serde(default = "SessionId::nil")]
    pub session_id: SessionId,
}

impl GetSessionGitStateRequest {
    #[must_use]
    pub fn new(session_id: SessionId) -> Self {
        Self { session_id }
    }
}

/// The git state of one repo in a session (R4.6).
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoGitState {
    /// The `owner/repo` this entry describes.
    #[serde(default)]
    pub repo: String,
    /// The current working branch.
    #[serde(default)]
    pub branch: String,
    /// The base branch the working branch tracks, if known.
    #[serde(default)]
    pub base: Option<String>,
    /// Commits on `branch` ahead of `base` — i.e. PR-able work.
    #[serde(default)]
    pub ahead: u32,
    /// The public URL of an already-open PR for this branch, if any (R4.5).
    #[serde(default)]
    pub existing_pr_url: Option<String>,
}

impl RepoGitState {
    #[must_use]
    pub fn new(
        repo: String,
        branch: String,
        base: Option<String>,
        ahead: u32,
        existing_pr_url: Option<String>,
    ) -> Self {
        Self {
            repo,
            branch,
            base,
            ahead,
            existing_pr_url,
        }
    }
}

/// Response for the [`GetSessionGitState`] RPC.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetSessionGitStateResponse {
    /// Per-repo git state, one entry per primed repo.
    #[serde(default)]
    pub repos: Vec<RepoGitState>,
}

impl GetSessionGitStateResponse {
    #[must_use]
    pub fn new(repos: Vec<RepoGitState>) -> Self {
        Self { repos }
    }
}

impl OneshotSshRpc for GetSessionGitState {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "GetSessionGitState");
    type Request<'a> = GetSessionGitStateRequest;
    type Response = Errorable<GetSessionGitStateResponse>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::wire::request::{ContributionResponse, WireContribution};

    /// An empty request body must decode with the documented defaults so a
    /// bare `{}` probe (or an older client) still gets a full bundle.
    #[test]
    fn diag_bundle_request_defaults_from_empty_object() {
        let req: DiagBundleRequest = serde_json::from_str("{}").expect("deserialize");
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

    #[test]
    fn policy_types_are_present_and_serializable() {
        // PortMapping construction and round-trip
        let mapping = PortMapping {
            external_port: 8080,
            internal_port: 80,
            proto: IpProto::Tcp,
        };
        let json = serde_json::to_string(&mapping).unwrap();
        let rt: PortMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, mapping);

        // IngressPolicy default and round-trip
        let ingress = IngressPolicy {
            port_mappings: vec![mapping],
            dynamic_allowed_range: Some((10000, 20000)),
        };
        let json = serde_json::to_string(&ingress).unwrap();
        let rt: IngressPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt, ingress);

        // EgressPolicy default serializes without error
        let egress = EgressPolicy::default();
        let json = serde_json::to_string(&egress).unwrap();
        let _: EgressPolicy = serde_json::from_str(&json).unwrap();

        // SessionPolicy with null egress and default ingress matches expected CLI output
        let policy = SessionPolicy {
            egress: None,
            ingress: Some(IngressPolicy::default()),
        };
        let json = serde_json::to_string(&policy).unwrap();
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
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn create_session_request_round_trips() {
        let req = CreateSessionRequest {
            config: SessionConfig {
                name: Some("my-session".into()),
                project_path: paths::HostAbsPath::try_new("/home/u/proj").unwrap(),
                network: NetworkMode::OwnIp,
                policy: SessionPolicy::default(),
                attrs: [("color".to_string(), "blue".to_string())]
                    .into_iter()
                    .collect(),
            },
        };
        assert_eq!(round_trip(&req), req);
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
            serde_json::from_str(r#"{"sessions":[]}"#).expect("deserialize");
        assert!(resp.resource_pool.is_none());
        assert!(resp.sessions.is_empty());
    }

    /// A daemon that predates `project_path` and `status` on
    /// `ListSessionsEntry` omits both fields; the client must accept that
    /// response (project_path → `None`, status → `Active`) rather than fail
    /// deserialization.
    #[test]
    fn list_sessions_entry_accepts_response_without_project_path_and_status() {
        let resp: ListSessionsResponse = serde_json::from_str(
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
        let raw = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
        });
        let req: ConfigureLoadoutRequest = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(req.contribution, WireContribution::default());
    }

    #[test]
    fn configure_loadout_response_materialized_round_trips() {
        let resp = ConfigureLoadoutResponse::Materialized;
        assert_eq!(round_trip(&resp), resp);
        let json = serde_json::to_string(&resp).unwrap();
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
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""kind":"pending""#), "got: {json}");
    }

    // -----------------------------------------------------------------------
    // GitHub-integrated sessions (spec 10) RPC wire types.
    // -----------------------------------------------------------------------

    fn sid() -> SessionId {
        SessionId::parse_str("00000000-0000-0000-0000-000000000001").unwrap()
    }

    #[test]
    fn github_begin_login_round_trips() {
        let req = GithubBeginLoginRequest::new(vec!["contents:write".into()]);
        assert_eq!(round_trip(&req), req);

        let resp: Errorable<GithubBeginLoginResponse> =
            Errorable::Ok(GithubBeginLoginResponse::new(
                "https://github.com/login/device".into(),
                "ABCD-1234".into(),
                "login-abc".into(),
                5,
                900,
            ));
        assert_eq!(round_trip(&resp), resp);

        // The client-id-unset failure surfaces via the `Errorable` wrapper.
        // Note: `Errorable` is `#[serde(untagged)]` with `Ok` tried first, and
        // every response field here is `#[serde(default)]`, so an `{"error":..}`
        // payload round-trips into `Ok(default)` rather than `Err` — the same
        // accepted property the unit-struct/optional responses in this file
        // already have. We therefore assert the error's construction and
        // serialized shape, not a round-trip.
        let err: Errorable<GithubBeginLoginResponse> = Err::<GithubBeginLoginResponse, _>(
            "GitHub App client id is not configured",
        )
        .into();
        assert!(err.err().is_some());
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("client id is not configured"), "got: {json}");
    }

    /// A daemon that predates the `expires_in_secs` field still decodes.
    #[test]
    fn github_begin_login_response_accepts_old_shape() {
        let raw = serde_json::json!({
            "verification_uri": "https://github.com/login/device",
            "user_code": "ABCD-1234",
            "login_id": "login-abc",
            "poll_interval_secs": 5,
        });
        let resp: GithubBeginLoginResponse = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(resp.expires_in_secs, 0);
    }

    /// Wholly empty payloads decode to defaults (missing everything).
    #[test]
    fn github_begin_login_request_accepts_empty() {
        let req: GithubBeginLoginRequest = serde_json::from_str("{}").expect("deserialize");
        assert!(req.scopes.is_empty());
    }

    #[test]
    fn github_poll_login_states_round_trip() {
        for resp in [
            GithubPollLoginResponse::Pending,
            GithubPollLoginResponse::Complete {
                login: "octocat".into(),
                grant_id: "grant-1".into(),
            },
            GithubPollLoginResponse::Failed {
                message: "access denied".into(),
            },
            GithubPollLoginResponse::Expired,
        ] {
            let wrapped: Errorable<GithubPollLoginResponse> = Errorable::Ok(resp.clone());
            assert_eq!(round_trip(&wrapped), wrapped);
        }

        let json =
            serde_json::to_string(&GithubPollLoginResponse::Pending).unwrap();
        assert!(json.contains(r#""kind":"pending""#), "got: {json}");
    }

    /// A `complete` variant emitted before `grant_id` existed still decodes.
    #[test]
    fn github_poll_complete_accepts_old_shape() {
        let raw = serde_json::json!({ "kind": "complete", "login": "octocat" });
        let resp: GithubPollLoginResponse = serde_json::from_value(raw).expect("deserialize");
        match resp {
            GithubPollLoginResponse::Complete { login, grant_id } => {
                assert_eq!(login, "octocat");
                assert_eq!(grant_id, "");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn github_status_round_trips() {
        let req = GithubStatusRequest::new(Some(sid()), vec!["octocat/api".into()]);
        assert_eq!(round_trip(&req), req);

        let resp: Errorable<GithubStatusResponse> = Errorable::Ok(GithubStatusResponse::new(
            Some(GithubIdentity::new("octocat".into(), "grant-1".into())),
            true,
            Some(Utc::now()),
            vec![RepoInstallationStatus::new(
                "octocat/api".into(),
                false,
                Some("https://github.com/apps/minimal/installations/new".into()),
            )],
            vec![SessionRepoStatus::new(
                "octocat/api".into(),
                "feat/x".into(),
                Some("main".into()),
                vec!["contents:write".into(), "pull_requests:write".into()],
            )],
        ));
        assert_eq!(round_trip(&resp), resp);
    }

    /// Old status payloads without the newer collections still parse.
    #[test]
    fn github_status_response_accepts_old_shape() {
        let raw = serde_json::json!({ "token_valid": false });
        let resp: GithubStatusResponse = serde_json::from_value(raw).expect("deserialize");
        assert!(resp.identity.is_none());
        assert!(!resp.token_valid);
        assert!(resp.installations.is_empty());
        assert!(resp.session_repos.is_empty());
        assert!(resp.token_expires_at.is_none());
    }

    /// Requesting status without a session id defaults it to `None`.
    #[test]
    fn github_status_request_accepts_missing_session() {
        let req: GithubStatusRequest = serde_json::from_str("{}").expect("deserialize");
        assert!(req.session_id.is_none());
        assert!(req.repos.is_empty());
    }

    #[test]
    fn github_list_auths_round_trips() {
        let req = GithubListAuthsRequest::new();
        assert_eq!(round_trip(&req), req);

        let resp: Errorable<GithubListAuthsResponse> =
            Errorable::Ok(GithubListAuthsResponse::new(vec![GrantMetadata::new(
                "grant-1".into(),
                "octocat".into(),
                Some(Utc::now()),
                vec!["contents:write".into()],
                vec!["octocat/api".into()],
                true,
                Some(Utc::now()),
            )]));
        assert_eq!(round_trip(&resp), resp);
    }

    /// Grant metadata must carry no token material; a legacy shape with only
    /// the identifier and login still decodes.
    #[test]
    fn grant_metadata_accepts_old_shape() {
        let raw = serde_json::json!({ "grant_id": "grant-1", "login": "octocat" });
        let m: GrantMetadata = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(m.grant_id, "grant-1");
        assert!(m.scopes.is_empty());
        assert!(m.repos.is_empty());
        assert!(!m.token_valid);
    }

    #[test]
    fn github_logout_round_trips() {
        let req = GithubLogoutRequest::new("grant-1".into());
        assert_eq!(round_trip(&req), req);
        let resp: Errorable<GithubLogoutResponse> =
            Errorable::Ok(GithubLogoutResponse::new(true));
        assert_eq!(round_trip(&resp), resp);
    }

    #[test]
    fn github_prime_repos_round_trips() {
        let req = GithubPrimeReposRequest::new(
            sid(),
            vec!["octocat/api@feat/x:main".into(), "octocat/web@feat/x".into()],
            "grant-1".into(),
        );
        assert_eq!(round_trip(&req), req);

        let resp: Errorable<GithubPrimeReposResponse> =
            Errorable::Ok(GithubPrimeReposResponse::new(vec![
                RepoPrimeResult::new(
                    "octocat/api".into(),
                    "feat/x".into(),
                    Some("main".into()),
                    RepoPrimeOutcome::Created,
                ),
                RepoPrimeResult::new(
                    "octocat/web".into(),
                    "feat/x".into(),
                    None,
                    RepoPrimeOutcome::CheckedOut,
                ),
                RepoPrimeResult::new(
                    "octocat/broken".into(),
                    "feat/x".into(),
                    None,
                    RepoPrimeOutcome::Failed {
                        message: "App not installed on octocat/broken".into(),
                    },
                ),
            ]));
        assert_eq!(round_trip(&resp), resp);
    }

    /// A prime request that predates `grant_id` still decodes (empty grant).
    #[test]
    fn github_prime_repos_request_accepts_old_shape() {
        let raw = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "repos": ["octocat/api@feat/x"],
        });
        let req: GithubPrimeReposRequest = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(req.session_id, sid());
        assert_eq!(req.grant_id, "");
    }

    #[test]
    fn github_push_round_trips() {
        let req = GithubPushRequest::new(sid(), "octocat/api".into(), Some("feat/x".into()));
        assert_eq!(round_trip(&req), req);
        let resp: Errorable<GithubPushResponse> = Errorable::Ok(GithubPushResponse::new(
            "octocat/api".into(),
            "feat/x".into(),
            true,
            "feat/x -> feat/x (fast-forward)".into(),
        ));
        assert_eq!(round_trip(&resp), resp);
    }

    #[test]
    fn github_create_pr_round_trips() {
        let req = GithubCreatePrRequest::new(
            sid(),
            "octocat/api".into(),
            Some("feat/x".into()),
            Some("main".into()),
            "Add feature x".into(),
            "Body from template".into(),
            true,
        );
        assert_eq!(round_trip(&req), req);
        let resp: Errorable<GithubCreatePrResponse> = Errorable::Ok(GithubCreatePrResponse::new(
            "https://github.com/octocat/api/pull/42".into(),
            42,
            false,
        ));
        assert_eq!(round_trip(&resp), resp);
    }

    /// An older create-pr request without `draft`/`base` still decodes.
    #[test]
    fn github_create_pr_request_accepts_old_shape() {
        let raw = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "repo": "octocat/api",
            "title": "t",
            "body": "b",
        });
        let req: GithubCreatePrRequest = serde_json::from_value(raw).expect("deserialize");
        assert!(!req.draft);
        assert!(req.base.is_none());
        assert!(req.head.is_none());
    }

    #[test]
    fn get_session_git_state_round_trips() {
        let req = GetSessionGitStateRequest::new(sid());
        assert_eq!(round_trip(&req), req);
        let resp: Errorable<GetSessionGitStateResponse> =
            Errorable::Ok(GetSessionGitStateResponse::new(vec![RepoGitState::new(
                "octocat/api".into(),
                "feat/x".into(),
                Some("main".into()),
                3,
                Some("https://github.com/octocat/api/pull/42".into()),
            )]));
        assert_eq!(round_trip(&resp), resp);
    }

    /// Unknown fields are tolerated (no `deny_unknown_fields`), so a newer peer
    /// can add fields without breaking an older decoder.
    #[test]
    fn github_types_tolerate_unknown_fields() {
        let raw = serde_json::json!({
            "verification_uri": "https://github.com/login/device",
            "user_code": "ABCD-1234",
            "login_id": "login-abc",
            "poll_interval_secs": 5,
            "expires_in_secs": 900,
            "some_future_field": {"nested": true},
        });
        let resp: GithubBeginLoginResponse = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(resp.user_code, "ABCD-1234");

        let raw = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "repo": "octocat/api",
            "ahead_by": 99,
        });
        let req: GetSessionGitStateRequest = serde_json::from_value(raw).expect("deserialize");
        assert_eq!(req.session_id, sid());
    }

    /// The RPC subsystem names are stable and carry the shared prefix. A drift
    /// here is a wire-compat break.
    #[test]
    fn github_rpc_names_are_stable() {
        assert_eq!(GithubBeginLogin::NAME, "minimald-v1-GithubBeginLogin");
        assert_eq!(GithubPollLogin::NAME, "minimald-v1-GithubPollLogin");
        assert_eq!(GithubStatus::NAME, "minimald-v1-GithubStatus");
        assert_eq!(GithubListAuths::NAME, "minimald-v1-GithubListAuths");
        assert_eq!(GithubLogout::NAME, "minimald-v1-GithubLogout");
        assert_eq!(GithubPrimeRepos::NAME, "minimald-v1-GithubPrimeRepos");
        assert_eq!(GithubPush::NAME, "minimald-v1-GithubPush");
        assert_eq!(GithubCreatePr::NAME, "minimald-v1-GithubCreatePr");
        assert_eq!(GetSessionGitState::NAME, "minimald-v1-GetSessionGitState");
    }
}
