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
pub mod store;
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

/// Effective egress policy for an `OwnIp` `PTask`.
///
/// Each field is `None` to mean allow-all for that dimension. Absent `egress`
/// config on a session is equivalent to all-`None` (allow-all).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EgressPolicy {
    /// Allowed destination CIDR prefixes; `None` means allow-all subnets.
    pub allow_subnets: Option<Vec<String>>,
    /// Allowed destination DNS hostnames; `None` means allow-all hosts.
    pub allow_dns_hosts: Option<Vec<String>>,
    /// Allowed IP protocols; `None` means allow all protocols.
    pub allow_protocols: Option<Vec<IpProto>>,
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
    /// An egress policy was set on a `PTask` that is not [`NetworkMode::OwnIp`].
    #[error("egress policy is only valid for an own-IP PTask, not {mode:?}")]
    EgressRequiresOwnIp { mode: NetworkMode },
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

/// The on-disk row/record pertaining to a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Free-form attributes.
    pub attrs: BTreeMap<String, String>,
}

impl Record {
    /// Validates that this record's networking policy is compatible with its
    /// network mode (R2.1/R2.3): egress and ingress are only meaningful for an
    /// [`NetworkMode::OwnIp`] `PTask`, since `NoNet` has no network and `HostNet`
    /// shares the host's, neither of which minimald can apply per-session
    /// policy to. Returns an error naming the first incompatible section.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EgressRequiresOwnIp`] when an egress policy is set
    /// on a non-`OwnIp` `PTask`, or [`PolicyError::IngressRequiresOwnIp`] when a
    /// non-empty ingress policy is. Returns
    /// [`PolicyError::UnsupportedIngressProtocol`] for an ingress mapping whose
    /// transport gvproxy's forwarder cannot expose, or
    /// [`PolicyError::PrivilegedPort`] for one that publishes a host port below
    /// 1024. For an `OwnIp` `PTask`, returns [`PolicyError::InvalidSubnet`] when
    /// an egress `allow_subnets` entry is not a valid CIDR prefix.
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
        // For an OwnIp PTask egress/ingress are allowed; the only remaining
        // check is that each egress allow_subnets entry is a syntactically valid
        // CIDR prefix, so a misconfigured subnet is named at launch rather than
        // surfacing opaquely when #553's enforcement layer parses it.
        if self.network == NetworkMode::OwnIp {
            if let Some(bad) = self
                .policy
                .egress
                .as_ref()
                .and_then(|egress| egress.allow_subnets.as_deref())
                .into_iter()
                .flatten()
                .find(|cidr| !is_valid_cidr(cidr))
            {
                return Err(PolicyError::InvalidSubnet { cidr: bad.clone() });
            }
            return Ok(());
        }
        if self.policy.egress.is_some() {
            return Err(PolicyError::EgressRequiresOwnIp { mode: self.network });
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
            attrs: BTreeMap::new(),
        }
    }

    #[test]
    fn egress_on_host_net_is_rejected() {
        // R2.1: an egress section is only valid for an own-IP PTask.
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(Some(EgressPolicy::default()), None),
        );
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::EgressRequiresOwnIp {
                mode: NetworkMode::HostNet
            })
        );
    }

    #[test]
    fn egress_on_no_net_is_rejected() {
        let record = record_with(
            NetworkMode::NoNet,
            SessionPolicy::new(Some(EgressPolicy::default()), None),
        );
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::EgressRequiresOwnIp {
                mode: NetworkMode::NoNet
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
}
