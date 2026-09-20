//! Session primitives: lifecycle hooks and loadouts that describe the runtime
//! shape of a Minimal session.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use paths::HostAbsPath;

pub mod client;
pub mod core;
pub mod daemon;
pub mod keys;
pub mod store;
pub mod terminal;
pub mod wire;

/// The network isolation mode for a `PTask` (session).
///
/// Defaults to [`NetworkMode::HostNet`] for backwards compatibility with
/// existing sessions that predate this field.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network namespace; all network syscalls fail or see no interfaces.
    NoNet,
    /// Share the host (or VM) network namespace. Current default.
    #[default]
    HostNet,
    /// Own IP via the gvproxy switch: new netns + tap + switch attachment.
    OwnIp,
}

/// An IP transport protocol, used in egress/ingress policy rules.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpProto {
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for IpProto {
    /// Renders the lowercase transport name, matching the `snake_case` serde
    /// representation so structured log fields agree with the wire format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        })
    }
}

// ---------------------------------------------------------------------------
// Networking policy types (Unit 2: egress, ingress, dynamic port mapping).
//
// These are the wire types `minimald-rpc` exposes; they live here (and are
// re-exported up to `minimald-rpc`) so that `Record` — the only live
// per-session store — can carry the policy configured at launch directly,
// without a dependency cycle (`minimald-rpc` depends on `sessions`, not the
// reverse). They are deliberately *not* `#[non_exhaustive]`: they are
// constructed by literal at the config↔wire mapping sites across crates.
// ---------------------------------------------------------------------------

/// A single static ingress port mapping for an `OwnIp` `PTask`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortMapping {
    /// Host-side port that forwards inbound connections into the `PTask`.
    pub external_port: u16,
    /// `PTask`-side port that receives forwarded connections.
    pub internal_port: u16,
    /// Transport protocol for this mapping.
    pub proto: IpProto,
}

/// Effective egress policy for a box with an address of its own (`OwnIp`) or
/// the host's (`HostNet`).
///
/// Each allow field is `None` to mean allow-all for that dimension. Absent
/// `egress` config on a session is equivalent to all-`None` (allow-all).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EgressPolicy {
    /// Allowed destination CIDR prefixes; `None` means allow-all subnets.
    pub allow_subnets: Option<Vec<String>>,
    /// Allowed destination DNS hostnames; `None` means allow-all hosts.
    pub allow_dns_hosts: Option<Vec<String>>,
    /// Allowed IP protocols; `None` means allow all protocols.
    pub allow_protocols: Option<Vec<IpProto>>,
    /// Denied destination CIDR prefixes; `None` means nothing is denied by the
    /// box's own declaration. The box's half of the denied ranges: a destination
    /// matched here is refused whatever the allow fields say.
    pub deny_subnets: Option<Vec<String>>,
}

impl EgressPolicy {
    /// Returns the first `allow_subnets` entry that is not a syntactically valid
    /// CIDR prefix, or `None` when every entry parses (or none are configured).
    ///
    /// Used at launch to name a misconfigured destination subnet where it can be
    /// fixed — by [`Record::validate_policy`] for per-`PTask` egress and by
    /// `minvmd`'s `VmConfig::validate_for` for VM-wide egress — rather than
    /// letting an unparseable CIDR surface opaquely when #553's egress-enforcement
    /// layer parses it.
    #[must_use]
    pub fn first_invalid_subnet(&self) -> Option<&str> {
        self.allow_subnets
            .as_deref()
            .into_iter()
            .flatten()
            .map(String::as_str)
            .find(|cidr| !is_valid_cidr(cidr))
    }

    /// Returns the first `deny_subnets` entry that is not a syntactically valid
    /// CIDR prefix, or `None` when every entry parses (or none are configured).
    ///
    /// Separate from [`first_invalid_subnet`](Self::first_invalid_subnet) so the
    /// error names the field the operator wrote. A deny entry that fails to parse
    /// is the worse of the two misconfigurations — the rule it describes would
    /// simply not be applied — so it is named at launch rather than dropped.
    #[must_use]
    pub fn first_invalid_deny_subnet(&self) -> Option<&str> {
        self.deny_subnets
            .as_deref()
            .into_iter()
            .flatten()
            .map(String::as_str)
            .find(|cidr| !is_valid_cidr(cidr))
    }
}

/// Effective ingress policy for an `OwnIp` `PTask`.
///
/// Default (empty `port_mappings`, no `dynamic_allowed_range`) is deny-all-external.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IngressPolicy {
    /// Static port mappings applied at `PTask` launch.
    pub port_mappings: Vec<PortMapping>,
    /// Inclusive port range within which dynamic port-mapping requests are
    /// accepted; `None` means dynamic mapping is disallowed.
    ///
    /// Stored on the [`Record`] and returned verbatim by `GetSessionPolicy`,
    /// but **not yet enforced**: dynamic port-mapping is split to #553. Until
    /// then a set range is recorded configuration only, with no runtime effect.
    pub dynamic_allowed_range: Option<(u16, u16)>,
}

impl IngressPolicy {
    /// Whether this ingress policy configures any forwarding at all (a static
    /// mapping or a dynamic range). An empty policy is the deny-all default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.port_mappings.is_empty() && self.dynamic_allowed_range.is_none()
    }
}

/// The networking policy for a session: its egress and ingress configuration.
///
/// `None` for a dimension means it was not configured (allow-all egress; the
/// deny-all-external ingress default). Stored on [`Record`] as the policy
/// configured at launch and returned verbatim by the `GetSessionPolicy` RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
// Every field is an `Option`, so without this an unrelated JSON object would
// decode as an all-`None` policy. That matters because `GetSessionPolicy`'s
// response is an `#[serde(untagged)]` `Errorable<SessionPolicy>`: the daemon's
// `{"error":"no session found"}` reply must fall through to the `Err` arm, not
// masquerade as a valid empty policy (a silent false negative on a
// security-introspection command).
#[serde(deny_unknown_fields)]
pub struct SessionPolicy {
    /// Egress policy; `None` when no explicit egress config is present.
    pub egress: Option<EgressPolicy>,
    /// Ingress policy; `None` when no explicit ingress config is present.
    pub ingress: Option<IngressPolicy>,
}

impl SessionPolicy {
    /// Builds a policy from its egress and ingress halves.
    #[must_use]
    pub fn new(egress: Option<EgressPolicy>, ingress: Option<IngressPolicy>) -> Self {
        Self { egress, ingress }
    }
}

/// Why a session's networking policy is incompatible with its network mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// An egress policy was declared on a [`NetworkMode::NoNet`] `PTask` — a
    /// `none` box, which has no network for the declaration to describe.
    ///
    /// Own-address (`OwnIp`) and host-address (`HostNet`) boxes both accept an
    /// `egress` section: the host-address cohort has an enforcement identity of
    /// its own, so its declaration is meaningful even though it shares the host's
    /// addresses. `NoNet` is the one mode where there is nothing to enforce.
    #[error(
        "egress policy is not valid on a no-net PTask: a none box has no \
         network for the rules to describe — drop the egress section, or give \
         the box the host's address or one of its own"
    )]
    EgressOnNoNetBox,
    /// An ingress policy was set on a `PTask` that is not [`NetworkMode::OwnIp`].
    #[error("ingress policy is only valid for an own-IP PTask, not {mode:?}")]
    IngressRequiresOwnIp { mode: NetworkMode },
    /// An ingress port mapping used a transport gvproxy's forwarder cannot
    /// expose. gvproxy only forwards TCP and UDP, so any other protocol (e.g.
    /// ICMP) must be rejected at validation time rather than silently mapped.
    #[error(
        "ingress port mapping uses unsupported protocol {proto:?}; \
         gvproxy's static forwarder supports only TCP and UDP"
    )]
    UnsupportedIngressProtocol { proto: IpProto },
    /// An ingress port mapping published a host port below 1024. minimald
    /// refuses to configure gvproxy to publish a privileged host port, since
    /// binding one requires elevated privilege the rootless switch does not
    /// hold; choosing a port >= 1024 is the remediation.
    #[error(
        "ingress port mapping publishes privileged host port {external_port}; \
         minimald refuses to publish host ports below 1024 — choose an \
         external_port >= 1024"
    )]
    PrivilegedPort { external_port: u16 },
    /// An egress `allow_subnets` entry is not a syntactically valid CIDR prefix
    /// (e.g. `10.0.0/8` or `not-a-cidr`). Rejected at launch so a misconfigured
    /// subnet is named where it can be fixed, rather than surfacing opaquely
    /// when #553's egress-enforcement layer parses it.
    #[error("egress allow_subnets entry {cidr:?} is not a valid CIDR prefix")]
    InvalidSubnet { cidr: String },
    /// An egress `deny_subnets` entry is not a syntactically valid CIDR prefix.
    /// Rejected at launch for the same reason as [`Self::InvalidSubnet`], and
    /// more urgently: an unparseable deny entry describes a rule that would not
    /// be applied, so dropping it silently would widen the box's reach.
    #[error("egress deny_subnets entry {cidr:?} is not a valid CIDR prefix")]
    InvalidDenySubnet { cidr: String },
    /// An ingress `dynamic_allowed_range` was given with its lower bound above
    /// its upper bound (e.g. `(8443, 8000)`). The range is inclusive, so a
    /// reversed pair describes no ports; rejected at launch so the misconfig is
    /// named where it can be fixed, rather than persisting on the `Record` until
    /// #553's dynamic-port-mapping layer consumes it.
    #[error(
        "ingress dynamic_allowed_range lower bound {lo} exceeds upper bound \
         {hi}; the range is inclusive — set lo <= hi"
    )]
    InvalidDynamicRange { lo: u16, hi: u16 },
    /// An ingress `dynamic_allowed_range` lower bound is a privileged host port
    /// (< 1024). The lower bound is the smallest host port a runtime mapping
    /// request may publish, so the same rootless-privilege constraint that
    /// rejects a static mapping's privileged `external_port` applies. Rejected at
    /// launch so the misconfig is named where it can be fixed, rather than
    /// surfacing opaquely when #553's dynamic-port-mapping layer consumes it.
    #[error(
        "ingress dynamic_allowed_range lower bound {lo} is a privileged host \
         port; minimald refuses to publish host ports below 1024 — set a lower \
         bound >= 1024"
    )]
    PrivilegedDynamicRange { lo: u16 },
}

/// Whether `s` is a syntactically valid CIDR prefix (`<addr>/<prefix-len>`) for
/// either IPv4 or IPv6. Only the address syntax and the prefix-length range are
/// checked; host bits below the prefix are permitted, matching how the strings
/// are written in config.
fn is_valid_cidr(s: &str) -> bool {
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => prefix <= 32,
        Ok(std::net::IpAddr::V6(_)) => prefix <= 128,
        Err(_) => false,
    }
}

/// A session ID, a newtype over a UUID.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(Uuid);

impl SessionId {
    #[must_use]
    pub fn nil() -> Self {
        Self(Uuid::nil())
    }

    /// Parses the given UUID as a session ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the given string is not a UUID.
    pub fn parse_str(s: &str) -> Result<Self, uuid::Error> {
        Uuid::parse_str(s).map(Self)
    }
}

impl AsRef<Uuid> for SessionId {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Lifecycle status of a [`Record`].
///
/// `Pending` covers a session whose composition is still in flight —
/// an id has been allocated and a stub record persisted, but the
/// composition pipeline hasn't yet produced a finalized
/// `Composition`. Mirrors the wire word
/// [`CreateSessionResponse::Pending`] the daemon returns when the
/// client must gate items before composition completes. `Active`
/// is the finalized, ready-to-use state.
///
/// Defaults to `Active` so on-disk records predating this field
/// (which were always finalized at create time) deserialize
/// correctly.
///
/// The store records the status verbatim; state-machine transitions
/// (e.g. `Pending → Active`) are enforced by the manager actor,
/// not here. Prefer `match` arms over `status == Active` equality
/// so new variants surface as compile errors.
///
/// [`CreateSessionResponse::Pending`]: ../minimald_rpc/enum.CreateSessionResponse.html#variant.Pending
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Composition is in flight; the record is a stub awaiting the
    /// `SubmitVerdict` round-trip to finalize. Accepts the legacy
    /// on-disk spelling `"draft"` so records written before the
    /// rename continue to load.
    #[serde(alias = "draft")]
    Pending,
    /// Composition finalized but the session isn't attachable yet:
    /// the client is still uploading the composition's patches to
    /// the daemon-side workspace. Transitions to [`Self::Active`]
    /// when the client calls `FinalizeSession` — which the daemon
    /// gates on the patches-ready marker being present. Attach
    /// refuses `Materializing` sessions.
    ///
    /// A daemon restart wipes the in-memory composition, so any
    /// `Materializing` record left on disk after restart is
    /// unresumable; the manager reaps them at startup for the same
    /// reason it reaps unresumable `Pending` records.
    Materializing,
    /// Composition complete and every side-channel upload is on
    /// disk; the record is ready to apply and the session is
    /// attachable.
    #[default]
    Active,
}

/// Default for [`Record::hooks_enabled`] (and for the matching field on
/// `minimald_rpc::SessionConfig`): hooks are on unless the user opted
/// out. A bare `#[serde(default)]` would give `false`, silently
/// disabling hooks on every record written before the field existed.
fn hooks_enabled_default() -> bool {
    true
}

/// Deserialize a session name, collapsing an empty string to `None`.
///
/// An empty-string name could reach storage before the rename/activate
/// boundary rejected empty names, leaving `null` and `""` as two on-disk
/// spellings of "no name". Loading both as `None` gives every surface a
/// single representation: `null | non-empty string`.
fn deserialize_optional_name<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = Option::<String>::deserialize(deserializer)?;
    Ok(name.filter(|name| !name.is_empty()))
}

/// The on-disk row/record pertaining to a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Unique ID describing this session.
    #[serde(default = "SessionId::nil")]
    pub id: SessionId,
    /// The name a user assigned to this session, if
    /// one was specifically assigned.
    ///
    /// When no name was manually assigned, the user should
    /// be presented with a short name of the form:
    /// <user>-<project/repo-name>-<uuid-suffix>.
    #[serde(deserialize_with = "deserialize_optional_name")]
    pub name: Option<String>,

    /// The username of the creating user, at creation time.
    pub username: Option<String>,
    /// The absolute path upon which this session was built from.
    pub project_path: HostAbsPath,

    /// The network isolation mode for this session.
    ///
    /// Defaults to [`NetworkMode::HostNet`] when absent (existing sessions).
    #[serde(default)]
    pub network: NetworkMode,

    /// The networking policy (egress + ingress) configured for this session at
    /// launch (R2.6). Defaults to an all-`None` policy for sessions that
    /// predate this field or specify none.
    #[serde(default)]
    pub policy: SessionPolicy,

    /// Lifecycle status. Defaults to [`SessionStatus::Active`] for
    /// on-disk records predating this field — those records were
    /// always finalized at create time.
    #[serde(default)]
    pub status: SessionStatus,

    /// Whether this session runs the lifecycle hooks composed into it.
    /// Cleared by `min session activate --no-hooks`.
    ///
    /// Persisted on the record rather than applied only to the
    /// composition because the attach, detach, and destroy transitions
    /// fire from processes that never saw the activating command line —
    /// a later `min session attach` has no other way to know the user
    /// opted out. Defaults to `true` for records that predate the field;
    /// hooks have never executed, so no existing session gains
    /// behaviour from that default.
    #[serde(default = "hooks_enabled_default")]
    pub hooks_enabled: bool,

    /// Free-form attributes.
    pub attrs: BTreeMap<String, String>,
}

impl Record {
    /// Validates that this record's networking policy is compatible with its
    /// network mode. An `egress` section is accepted on a box with an address of
    /// its own ([`NetworkMode::OwnIp`]) and on one that carries the host's
    /// ([`NetworkMode::HostNet`]), whose cohort the host classifies as a source
    /// identity of its own; it is rejected on a `none` box
    /// ([`NetworkMode::NoNet`]), which has no network for the rules to describe.
    /// Ingress remains own-address only: forwarding into a box needs an address
    /// to forward to. Returns an error naming the first incompatible section.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EgressOnNoNetBox`] when an egress policy is
    /// declared on a `NoNet` `PTask`, or [`PolicyError::IngressRequiresOwnIp`]
    /// when a non-empty ingress policy is set on a non-`OwnIp` one. Returns
    /// [`PolicyError::UnsupportedIngressProtocol`] for an ingress mapping whose
    /// transport gvproxy's forwarder cannot expose, or
    /// [`PolicyError::PrivilegedPort`] for one that publishes a host port below
    /// 1024. Wherever an egress policy is accepted, returns
    /// [`PolicyError::InvalidSubnet`] or [`PolicyError::InvalidDenySubnet`] when
    /// an `allow_subnets` or `deny_subnets` entry is not a valid CIDR prefix. For
    /// an `OwnIp` `PTask`, returns [`PolicyError::InvalidDynamicRange`] when the
    /// ingress `dynamic_allowed_range` lower bound exceeds its upper bound, or
    /// [`PolicyError::PrivilegedDynamicRange`] when that lower bound is a
    /// privileged host port (< 1024).
    pub fn validate_policy(&self) -> Result<(), PolicyError> {
        // gvproxy's static forwarder only exposes TCP and UDP, so an ingress
        // mapping with any other transport is a configuration error wherever it
        // appears — reject it before the mode check so it never reaches the
        // forwarder as a silently-defaulted protocol.
        if let Some(proto) = self.policy.ingress.as_ref().and_then(|ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|mapping| mapping.proto)
                .find(|proto| !matches!(proto, IpProto::Tcp | IpProto::Udp))
        }) {
            return Err(PolicyError::UnsupportedIngressProtocol { proto });
        }
        // minimald refuses to publish a privileged host port (< 1024): binding
        // one needs elevated privilege the rootless switch lacks, so reject it
        // at validation time with a remediation rather than letting the expose
        // fail opaquely against gvproxy.
        if let Some(external_port) = self.policy.ingress.as_ref().and_then(|ingress| {
            ingress
                .port_mappings
                .iter()
                .map(|mapping| mapping.external_port)
                .find(|&port| port < 1024)
        }) {
            return Err(PolicyError::PrivilegedPort { external_port });
        }
        // An egress declaration is accepted on a box with an address of its own
        // and on one carrying the host's, and rejected on a none box, which has
        // no network for the rules to describe. Wherever it is accepted its
        // subnet lists must parse, so a misconfigured CIDR is named at launch
        // rather than surfacing opaquely when the enforcement layer parses it.
        if let Some(egress) = self.policy.egress.as_ref() {
            if self.network == NetworkMode::NoNet {
                return Err(PolicyError::EgressOnNoNetBox);
            }
            if let Some(bad) = egress.first_invalid_subnet() {
                return Err(PolicyError::InvalidSubnet {
                    cidr: bad.to_owned(),
                });
            }
            if let Some(bad) = egress.first_invalid_deny_subnet() {
                return Err(PolicyError::InvalidDenySubnet {
                    cidr: bad.to_owned(),
                });
            }
        }
        if self.network == NetworkMode::OwnIp {
            // A reversed dynamic range (lo > hi) describes no ports under the
            // inclusive semantics, and a privileged lower bound (< 1024) names a
            // host port the rootless switch cannot publish — the same constraint
            // the static-mapping privileged-port check enforces. Reject either at
            // launch rather than letting a misconfig persist on the Record until
            // #553's dynamic port-mapping layer consumes it.
            if let Some((lo, hi)) = self
                .policy
                .ingress
                .as_ref()
                .and_then(|ingress| ingress.dynamic_allowed_range)
            {
                if lo > hi {
                    return Err(PolicyError::InvalidDynamicRange { lo, hi });
                }
                if lo < 1024 {
                    return Err(PolicyError::PrivilegedDynamicRange { lo });
                }
            }
            return Ok(());
        }
        if self
            .policy
            .ingress
            .as_ref()
            .is_some_and(|ingress| !ingress.is_empty())
        {
            return Err(PolicyError::IngressRequiresOwnIp { mode: self.network });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with(network: NetworkMode, policy: SessionPolicy) -> Record {
        Record {
            id: SessionId::nil(),
            name: None,
            username: None,
            project_path: HostAbsPath::try_new("/p").unwrap(),
            network,
            policy,
            status: SessionStatus::default(),
            hooks_enabled: true,
            attrs: BTreeMap::new(),
        }
    }

    /// A record written before `hooks_enabled` existed loads with hooks
    /// **on**. A bare `#[serde(default)]` would yield `false` and
    /// silently disable hooks for every pre-existing session — the kind
    /// of regression that looks like "hooks just don't work" rather
    /// than an error.
    #[test]
    fn record_predating_hooks_enabled_defaults_to_on() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": null,
            "username": null,
            "project_path": "/p",
            "attrs": {}
        }"#;
        let r: Record = serde_json_lenient::from_str(json).expect("legacy record must still load");
        assert!(r.hooks_enabled);
    }

    /// An explicit `false` survives deserialization rather than being
    /// overwritten by the default.
    #[test]
    fn record_honours_explicit_hooks_disabled() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "name": null,
            "username": null,
            "project_path": "/p",
            "hooks_enabled": false,
            "attrs": {}
        }"#;
        let r: Record = serde_json_lenient::from_str(json).expect("record must load");
        assert!(!r.hooks_enabled);
    }

    /// The four egress fields a box spec may declare, all populated, as the
    /// acceptance tests read them back.
    fn four_field_egress() -> EgressPolicy {
        EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into()]),
            allow_dns_hosts: Some(vec!["api.example.com".into()]),
            allow_protocols: Some(vec![IpProto::Tcp, IpProto::Udp]),
            deny_subnets: Some(vec!["10.1.0.0/16".into()]),
        }
    }

    /// A box spec's `egress` section carries all four fields —
    /// `allow_subnets`, `allow_protocols`, `allow_dns_hosts` and
    /// `deny_subnets` — and each one survives the parse. `deny_subnets` is
    /// the field with no predecessor: before it existed the key parsed to
    /// nothing at all, so a spec that wrote it got silence instead of the
    /// rule it asked for.
    #[test]
    fn spec_accepts_egress_fields() {
        let spec = r#"{
            "egress": {
                "allow_subnets": ["10.0.0.0/8", "192.168.0.0/16"],
                "allow_protocols": ["tcp", "udp"],
                "allow_dns_hosts": ["api.example.com"],
                "deny_subnets": ["10.1.0.0/16"]
            },
            "ingress": null
        }"#;
        let policy: SessionPolicy =
            serde_json_lenient::from_str(spec).expect("a four-field egress section must parse");
        let egress = policy.egress.as_ref().expect("egress section");
        assert_eq!(
            egress.allow_subnets.as_deref(),
            Some(&["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()][..])
        );
        assert_eq!(
            egress.allow_protocols.as_deref(),
            Some(&[IpProto::Tcp, IpProto::Udp][..])
        );
        assert_eq!(
            egress.allow_dns_hosts.as_deref(),
            Some(&["api.example.com".to_string()][..])
        );
        assert_eq!(
            egress.deny_subnets.as_deref(),
            Some(&["10.1.0.0/16".to_string()][..])
        );
        // Declared on a box with an address of its own, the whole section is
        // accepted: parsing it is not enough if launch then refuses it.
        assert!(
            record_with(NetworkMode::OwnIp, policy)
                .validate_policy()
                .is_ok()
        );
    }

    /// A record written before `deny_subnets` existed — an `egress` section
    /// with only the three allow fields — still loads, with no deny rule.
    #[test]
    fn egress_without_deny_subnets_still_parses() {
        let spec = r#"{
            "egress": { "allow_subnets": ["10.0.0.0/8"] },
            "ingress": null
        }"#;
        let policy: SessionPolicy =
            serde_json_lenient::from_str(spec).expect("a pre-deny_subnets section must parse");
        let egress = policy.egress.expect("egress section");
        assert_eq!(egress.deny_subnets, None);
        assert_eq!(egress.allow_dns_hosts, None);
    }

    /// A `none` box has no network for egress rules to describe, so declaring
    /// them on one is a validation error rather than a silently inert section.
    #[test]
    fn egress_on_none_box_is_validation_error() {
        let record = record_with(
            NetworkMode::NoNet,
            SessionPolicy::new(Some(four_field_egress()), None),
        );
        assert_eq!(record.validate_policy(), Err(PolicyError::EgressOnNoNetBox));
        // Even an empty section is a declaration, and still refused.
        let record = record_with(
            NetworkMode::NoNet,
            SessionPolicy::new(Some(EgressPolicy::default()), None),
        );
        assert_eq!(record.validate_policy(), Err(PolicyError::EgressOnNoNetBox));
    }

    /// A box carrying the host's address accepts an `egress` section: the
    /// host-address cohort is classified as a source identity of its own, so
    /// the declaration is what the deny-all story for those boxes is built on.
    /// This is the rule that used to reject it.
    #[test]
    fn egress_on_host_ip_box_accepted() {
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(Some(four_field_egress()), None),
        );
        assert!(
            record.validate_policy().is_ok(),
            "egress on a host-address box must be accepted, got {:?}",
            record.validate_policy()
        );
        // Accepted, but still parsed: a malformed CIDR is named here too, not
        // only on an own-address box.
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(
                Some(EgressPolicy {
                    allow_subnets: Some(vec!["10.0.0/8".into()]),
                    ..EgressPolicy::default()
                }),
                None,
            ),
        );
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::InvalidSubnet {
                cidr: "10.0.0/8".into()
            })
        );
    }

    #[test]
    fn invalid_egress_deny_subnet_is_rejected() {
        // An unparseable deny entry describes a rule that would not be applied,
        // which would widen the box's reach; it is named at launch, and named as
        // a deny entry so the operator knows which list to fix.
        let egress = EgressPolicy {
            deny_subnets: Some(vec!["10.0.0.0/8".into(), "nope".into()]),
            ..EgressPolicy::default()
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(Some(egress), None));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::InvalidDenySubnet {
                cidr: "nope".into()
            })
        );
    }

    #[test]
    fn ingress_mappings_on_host_net_are_rejected() {
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        };
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(None, Some(ingress)),
        );
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::IngressRequiresOwnIp {
                mode: NetworkMode::HostNet
            })
        );
    }

    #[test]
    fn icmp_ingress_on_host_net_returns_protocol_error_not_mode_error() {
        // The protocol check precedes the mode check, so an ICMP mapping on a
        // non-OwnIp PTask surfaces as UnsupportedIngressProtocol rather than
        // IngressRequiresOwnIp. This test pins that ordering.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 8080,
                internal_port: 80,
                proto: IpProto::Icmp,
            }],
            dynamic_allowed_range: None,
        };
        assert_eq!(
            record_with(
                NetworkMode::HostNet,
                SessionPolicy::new(None, Some(ingress))
            )
            .validate_policy(),
            Err(PolicyError::UnsupportedIngressProtocol {
                proto: IpProto::Icmp
            })
        );
    }

    #[test]
    fn privileged_port_ingress_on_host_net_returns_port_error_not_mode_error() {
        // The privileged-port check likewise precedes the mode check, so a
        // host port below 1024 on a non-OwnIp PTask surfaces as PrivilegedPort
        // rather than IngressRequiresOwnIp. This test pins that ordering.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 80,
                internal_port: 8080,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        };
        assert_eq!(
            record_with(
                NetworkMode::HostNet,
                SessionPolicy::new(None, Some(ingress))
            )
            .validate_policy(),
            Err(PolicyError::PrivilegedPort { external_port: 80 })
        );
    }

    #[test]
    fn icmp_ingress_mapping_is_rejected_even_on_own_ip() {
        // gvproxy's forwarder only exposes TCP/UDP, so an ICMP mapping is a
        // configuration error even on an OwnIp PTask (where ingress is allowed).
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Icmp,
            }],
            dynamic_allowed_range: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::UnsupportedIngressProtocol {
                proto: IpProto::Icmp
            })
        );
    }

    #[test]
    fn privileged_external_port_is_rejected_even_on_own_ip() {
        // The spec's Security Considerations require minimald to refuse to
        // publish a host port below 1024; that is a configuration error even on
        // an OwnIp PTask, where ingress is otherwise allowed.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 80,
                internal_port: 8080,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::PrivilegedPort { external_port: 80 })
        );
    }

    #[test]
    fn unprivileged_external_port_is_allowed_on_own_ip() {
        // The boundary value 1024 is allowed: the rule rejects ports *below*
        // 1024, so 1024 itself is the first acceptable host port.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 1024,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert!(record.validate_policy().is_ok());
    }

    #[test]
    fn egress_on_own_ip_is_allowed() {
        let record = record_with(
            NetworkMode::OwnIp,
            SessionPolicy::new(Some(EgressPolicy::default()), None),
        );
        assert!(record.validate_policy().is_ok());
    }

    #[test]
    fn invalid_egress_subnet_is_rejected_on_own_ip() {
        // An allow_subnets entry that is not a valid CIDR prefix is rejected at
        // launch, naming the offending string, rather than being stored verbatim
        // and surfacing only when #553's enforcement parses it.
        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "not-a-cidr".into()]),
            ..EgressPolicy::default()
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(Some(egress), None));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::InvalidSubnet {
                cidr: "not-a-cidr".into()
            })
        );
    }

    #[test]
    fn valid_egress_subnets_are_accepted_on_own_ip() {
        // Both IPv4 and IPv6 CIDR prefixes pass the syntactic check.
        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "fd00::/8".into()]),
            ..EgressPolicy::default()
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(Some(egress), None));
        assert!(record.validate_policy().is_ok());
    }

    #[test]
    fn reversed_dynamic_range_is_rejected_on_own_ip() {
        // A dynamic_allowed_range whose lower bound exceeds its upper bound
        // describes no ports under the inclusive semantics, so it is rejected at
        // launch rather than being stored verbatim and surfacing only when
        // #553's dynamic port-mapping layer consumes it.
        let ingress = IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some((8443, 8000)),
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::InvalidDynamicRange { lo: 8443, hi: 8000 })
        );
    }

    #[test]
    fn privileged_dynamic_range_lower_bound_is_rejected_on_own_ip() {
        // A dynamic_allowed_range whose lower bound is below 1024 names a
        // privileged host port the rootless switch cannot publish — the same
        // constraint the static-mapping privileged-port check enforces — so it is
        // rejected at launch rather than surfacing opaquely when #553's dynamic
        // port-mapping layer consumes it. The bound is checked after the
        // reversed-range guard, so a well-ordered but privileged range is caught.
        for range in [(512u16, 1023u16), (80, 8080)] {
            let ingress = IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some(range),
            };
            let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
            assert_eq!(
                record.validate_policy(),
                Err(PolicyError::PrivilegedDynamicRange { lo: range.0 })
            );
        }
    }

    #[test]
    fn ordered_dynamic_range_is_accepted_on_own_ip() {
        // A well-ordered range passes; equal bounds are the single-port boundary
        // case and are likewise accepted under the inclusive semantics.
        for range in [(8000, 8443), (9000, 9000)] {
            let ingress = IngressPolicy {
                port_mappings: vec![],
                dynamic_allowed_range: Some(range),
            };
            let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
            assert!(record.validate_policy().is_ok());
        }
    }

    #[test]
    fn empty_policy_on_host_net_is_allowed() {
        // An all-`None` policy (the default) is fine on any mode: it configures
        // nothing, so there is nothing to reject.
        let record = record_with(NetworkMode::HostNet, SessionPolicy::default());
        assert!(record.validate_policy().is_ok());
        // An empty (deny-all-external) ingress is likewise not a configuration.
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(None, Some(IngressPolicy::default())),
        );
        assert!(record.validate_policy().is_ok());
    }

    /// On-disk records that predate the `status` field must
    /// deserialize as `Active`. This guarantees existing session
    /// stores keep working after the schema change.
    #[test]
    fn record_without_status_field_deserializes_as_active() {
        // Build a JSON document deliberately missing the `status`
        // field, with the rest of the fields set to plausible values.
        let raw = serde_json_lenient::json!({
            "id": SessionId::nil(),
            "name": null,
            "username": null,
            "project_path": "/p",
            "attrs": {},
        });
        let parsed: Record = serde_json_lenient::from_value(raw).expect("deserialize");
        assert_eq!(parsed.status, SessionStatus::Active);
    }

    /// A name persisted as an empty string predates the rename/activate
    /// validation that now rejects empty names. It must load as `None` so
    /// `null` is the single representation of "no name" on every surface.
    #[test]
    fn record_with_empty_name_deserializes_as_none() {
        let raw = serde_json_lenient::json!({
            "id": SessionId::nil(),
            "name": "",
            "username": null,
            "project_path": "/p",
            "attrs": {},
        });
        let parsed: Record = serde_json_lenient::from_value(raw).expect("deserialize");
        assert_eq!(parsed.name, None);
    }

    #[test]
    fn session_status_default_is_active() {
        assert_eq!(SessionStatus::default(), SessionStatus::Active);
    }

    /// Records persisted before the `Draft` → `Pending` rename used
    /// the string `"draft"`. The serde alias keeps those records
    /// readable; regression guard for accidentally dropping the
    /// alias on a future rename.
    #[test]
    fn legacy_draft_string_deserializes_as_pending() {
        let parsed: SessionStatus =
            serde_json_lenient::from_value(serde_json_lenient::json!("draft"))
                .expect("deserialize");
        assert_eq!(parsed, SessionStatus::Pending);
    }

    /// The canonical serialized form is `"pending"`; the alias is
    /// read-only.
    #[test]
    fn pending_serializes_as_pending_not_draft() {
        let s = serde_json_lenient::to_string(&SessionStatus::Pending).expect("serialize");
        assert_eq!(s, "\"pending\"");
    }
}
