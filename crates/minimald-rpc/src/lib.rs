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

pub use sessions::{EgressPolicy, IngressPolicy, IpProto, NetworkMode, PortMapping, SessionPolicy};

/// Shared gvproxy-switch primitives (subnet arithmetic, MAC derivation, wire
/// constants, `-config` rendering) used by both `minimald` and `minvmd`.
pub mod switch;

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

/// The response to the [`ListSessions`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSessionsResponse {
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

/// An RPC to create a new session based on the given record.
pub struct CreateSession;

/// The request for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub record: sessions::Record,
}

/// The response for a [`CreateSession`] RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionResponse {
    pub id: SessionId,
}

impl OneshotSshRpc for CreateSession {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "CreateSession");
    type Request<'a> = CreateSessionRequest;
    type Response = Errorable<CreateSessionResponse>;
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

// ---------------------------------------------------------------------------
// Session-creation flow (multi-round contribution composition).
//
// Distinct from the simpler [`CreateSession`] above: that one takes a
// fully-formed [`sessions::Record`]; the flow below composes the record
// by walking client contributions and daemon-side closures across one or
// more rounds. Each call returns a [`SessionStep`]: either the next round
// of pending items or a protocol-level fault.
//
// TODO: these three RPCs are the building blocks for what is eventually
// going to subsume `CreateSession` — once the multi-round flow lands on
// the daemon, the terminal `SessionStep` will assemble a `sessions::Record`
// and the single-shot `CreateSession` becomes redundant. Keeping them
// separate for now so the existing `CreateSession` callers stay working
// while the contribution flow is built out.

/// An RPC to open a new session and receive the first round of items
/// the client must resolve.
pub struct SessionCreate;

impl OneshotSshRpc for SessionCreate {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SessionCreate");
    type Request<'a> = sessions::wire::request::SessionCreateRequest;
    type Response = Errorable<sessions::wire::request::SessionStep>;
}

/// An RPC to submit the client's verdicts for one round and receive the
/// next round (or a `complete` signal in [`sessions::wire::request::ContributionResponse`]).
pub struct SubmitVerdict;

impl OneshotSshRpc for SubmitVerdict {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SubmitVerdict");
    type Request<'a> = sessions::wire::request::ContributionVerdict;
    type Response = Errorable<sessions::wire::request::SessionStep>;
}

/// An RPC to abort an in-flight session-creation flow.
pub struct SessionAbort;

impl OneshotSshRpc for SessionAbort {
    const NAME: &'static str = constcat::concat!(RPC_SUBSYSTEM_PREFIX, "SessionAbort");
    type Request<'a> = sessions::wire::request::Abort;
    type Response = Errorable<()>;
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
}
