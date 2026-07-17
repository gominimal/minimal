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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsEntry {
    pub id: SessionId,
    pub name: Option<String>,
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
    /// Absolute host path the session is built from.
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
/// — the record's `project_path` is a path on the client's machine,
/// which the daemon generally can't read. So the client creates the
/// session, populates its workspace, and only then configures the
/// loadout.
pub struct ConfigureLoadout;

/// The request for a [`ConfigureLoadout`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigureLoadoutRequest {
    /// The session to configure, from [`CreateSessionResponse::id`].
    pub session_id: SessionId,
    /// Client-side Phase 1 contribution. Defaulted (empty) by
    /// callers that aren't composing a session, which take the
    /// empty-contribution fast path to [`ConfigureLoadoutResponse::Ready`].
    #[serde(default)]
    pub contribution: sessions::wire::request::WireContribution,
}

/// The response for a [`ConfigureLoadout`] RPC.
///
/// Both variants are part of the Phase 2 flow and reachable on the
/// wire: `Ready` when the daemon's composer finalizes in one shot,
/// `Pending` when it collects items the client must gate before
/// composition completes (the client follows up via `SubmitVerdict`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigureLoadoutResponse {
    /// No items need user gating; the session is finalized and
    /// callers can immediately use it.
    Ready,
    /// Items need client-side gating. The session stays in flight;
    /// the client follows up with `SubmitVerdict` carrying the same
    /// id.
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
/// [`ContributionVerdict`]. Terminal — the daemon promotes the
/// record `Pending → Active` and replies with
/// [`SessionStep::Active`](sessions::wire::request::SessionStep::Active).
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

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::wire::request::{ContributionResponse, WireContribution};

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
    fn configure_loadout_response_ready_round_trips() {
        let resp = ConfigureLoadoutResponse::Ready;
        assert_eq!(round_trip(&resp), resp);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains(r#""kind":"ready""#), "got: {json}");
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
}
