//! Session primitives: lifecycle hooks and loadouts that describe the runtime
//! shape of a Minimal session.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

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

impl NetworkMode {
    /// The word naming this mode in the CLI's `--network` values and the
    /// spec: `none`, `host_ip`, `own_ip`. It is not the serde form: the
    /// derive serializes `no_net`, `host_net`, `own_ip`, so the two differ
    /// for [`NetworkMode::NoNet`] and [`NetworkMode::HostNet`]. Policy
    /// refusals and the daemon's `network_mode` log field use this word,
    /// never Rust `Debug`. Deliberately not `Display`, so a format string
    /// cannot pick one spelling by accident.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            NetworkMode::NoNet => "none",
            NetworkMode::HostNet => "host_ip",
            NetworkMode::OwnIp => "own_ip",
        }
    }
}

/// An IP transport protocol, used in egress/ingress policy rules.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

/// The hostnames NET-068's integration test exercises. Kept in `sessions` so
/// the `minimald` unit fixture and the `minvmd` integration test share one
/// list and cannot drift.
///
/// Docker Hub serves image blobs through a 307 redirect that lands on either
/// of its CDNs, `production.cloudflare.docker.com` or
/// `production.cloudfront.docker.com`, so a container pull needs both.
#[doc(hidden)]
pub const NET068_TOOLCHAIN_EGRESS_HOSTS: &[&str] = &[
    "github.com",
    "codeload.github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "registry-1.docker.io",
    "auth.docker.io",
    "production.cloudflare.docker.com",
    "production.cloudfront.docker.com",
];

/// Effective egress policy for a session.
///
/// Each `allow_*` field is `None` to mean allow-all for that dimension, and
/// `deny_subnets` is `None` to mean nothing is denied. Absent `egress` config
/// on a session is equivalent to all-`None` (allow-all). A `deny_subnets`
/// entry is subtractive: it carves a range out of what the `allow_*` fields
/// admit, so a rule set is effective only where it is not also denied.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EgressPolicy {
    /// Allowed destination CIDR prefixes; `None` means allow-all subnets.
    pub allow_subnets: Option<Vec<String>>,
    /// Allowed destination DNS hostnames; `None` means allow-all hosts.
    pub allow_dns_hosts: Option<Vec<String>>,
    /// Allowed IP protocols; `None` means allow all protocols.
    pub allow_protocols: Option<Vec<IpProto>>,
    /// Denied destination CIDR prefixes, subtracted from the allowed set;
    /// `None` means nothing is denied.
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
        first_invalid_cidr(self.allow_subnets.as_ref())
    }

    /// [`Self::first_invalid_subnet`] for `deny_subnets`, so a denied range is
    /// held to the same syntactic check as an allowed one: both are parsed by
    /// #553's egress-enforcement layer, so both are named at launch when they
    /// do not parse.
    #[must_use]
    pub fn first_invalid_deny_subnet(&self) -> Option<&str> {
        first_invalid_cidr(self.deny_subnets.as_ref())
    }

    /// Returns the first `allow_dns_hosts` entry that is not a valid DNS
    /// hostname, or `None` when every entry is valid (or none are configured).
    ///
    /// Used at launch to name a hostname that can never match the DNS gate's
    /// exact-match lookup — a name with whitespace, an over-long label, or a
    /// character outside `[A-Za-z0-9-_.]` — where it can be fixed, rather than
    /// storing it verbatim as an allow rule that admits nothing.
    #[must_use]
    pub fn first_invalid_dns_host(&self) -> Option<&str> {
        self.allow_dns_hosts
            .as_ref()
            .into_iter()
            .flatten()
            .map(String::as_str)
            .find(|host| !is_valid_dns_host(host))
    }

    /// The deny-all section: `Some(vec![])` on every `allow_*` dimension —
    /// the one [`crate::core::egress::EgressRules::from_policy`] shape that
    /// admits nothing — with nothing denied, because there is nothing left
    /// to subtract from. The materialized form of
    /// [`EffectiveEgress::DenyAll`], built as a real section so the gate
    /// compiles the default through the same path a declared one takes.
    ///
    /// The resolver carve-out (NET-079) is not in the section: it lives in
    /// the verdict, which admits the resolver Minimal owns for a box at
    /// DNS's port whatever the rules say.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            allow_subnets: Some(Vec::new()),
            allow_dns_hosts: Some(Vec::new()),
            allow_protocols: Some(Vec::new()),
            deny_subnets: None,
        }
    }

    /// Whether this section is the deny-all shape: every `allow_*` dimension
    /// present and empty. `deny_subnets` is not read — it subtracts from
    /// what the `allow_*` fields admit, and there is nothing there to
    /// subtract from. The one predicate the in-VM classifier and the
    /// host-side registry share, so the box each treats as deny-all is one
    /// shape.
    #[must_use]
    pub fn admits_nothing(&self) -> bool {
        self.allow_subnets.as_ref().is_some_and(Vec::is_empty)
            && self.allow_dns_hosts.as_ref().is_some_and(Vec::is_empty)
            && self.allow_protocols.as_ref().is_some_and(Vec::is_empty)
    }
}

/// The first entry of an optional CIDR list that is not a syntactically valid
/// prefix, or `None` when every entry parses (or the list is unset/empty).
fn first_invalid_cidr(entries: Option<&Vec<String>>) -> Option<&str> {
    entries
        .into_iter()
        .flatten()
        .map(String::as_str)
        .find(|cidr| !is_valid_cidr(cidr))
}

/// How dynamic ingress requests from inside a box are decided.
///
/// A request to publish a port from inside the box (e.g. `min net expose`)
/// is either allowed automatically, denied, or routed to a prompt for the
/// attached human. The default for an absent declaration is deny-all.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DynamicIngress {
    /// Dynamic ingress requests are published without prompting.
    Allow,
    /// Dynamic ingress requests are refused (the default when no setting is
    /// declared).
    #[default]
    Deny,
    /// Dynamic ingress requests prompt the attached human. If nobody is
    /// attached, the request is refused.
    Ask,
}

impl fmt::Display for DynamicIngress {
    /// Renders the lowercase mode name, matching the `snake_case` serde
    /// representation so the TUI and any structured log fields agree with the
    /// wire format.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        })
    }
}

/// Effective ingress policy for an `OwnIp` `PTask`.
///
/// Default (empty `port_mappings`, no `dynamic_allowed_range`, no
/// `dynamic_ingress`) is deny-all-external.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct IngressPolicy {
    /// Static port mappings applied at `PTask` launch.
    pub port_mappings: Vec<PortMapping>,
    /// Inclusive port range within which dynamic port-mapping requests are
    /// accepted; `None` means dynamic mapping is disallowed.
    ///
    /// Enforced on the listen-publication surface (NET-016, NET-017): under
    /// a [`DynamicIngress::Allow`] stance, a port a process in the box
    /// *listens* on is published on the box's address while it falls inside
    /// this range — inclusively at both ends — and withdrawn when the
    /// listener closes. The decision is the shared one in
    /// [`core::egress::IngressRules`], which the daemon's listener watcher
    /// applies and the Kani harness exhausts. Stored on the [`Record`] and
    /// returned verbatim by `GetSessionPolicy`.
    pub dynamic_allowed_range: Option<(u16, u16)>,
    /// How dynamic port-mapping requests from inside the box are decided.
    /// `None` means the default deny-all applies.
    ///
    /// The gate on the whole listen-publication surface (NET-016, NET-138):
    /// only `allow` publishes a port because a process listens on it. `ask`
    /// routes the request to the attached human — listening alone is never
    /// the human's yes — and `deny`, like an absent setting, keeps every
    /// listening port unpublished.
    pub dynamic_ingress: Option<DynamicIngress>,
}

impl IngressPolicy {
    /// Whether this ingress policy configures any forwarding at all (a static
    /// mapping, a dynamic range, or a non-default dynamic-ingress setting). An
    /// empty policy is the deny-all default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.port_mappings.is_empty()
            && self.dynamic_allowed_range.is_none()
            && self
                .dynamic_ingress
                .is_none_or(|d| d == DynamicIngress::Deny)
    }
}

/// A box's declaration of a credentialed upstream (NET-134): the fact that
/// the Box Egress Proxy — the node-local listener a box's credentialed
/// traffic is steered through — is this box's infrastructure, reached at the
/// proxy's own address on the switch whatever the box's egress rules say.
///
/// The declaration carries no fields of its own yet, and that is the point:
/// the steering table and the credential grants that derive a box's
/// credentialed upstream set are the Box Egress Proxy document's field
/// schema, and this is the minimum of it the networking requirement binds
/// here — the fact itself, which is all the host-side row needs to hold the
/// box's lane open to the proxy's address. A policy that carries `Some`
/// declaration puts its box on a credentialed lane; one that carries `None`
/// declares nothing, and its box's frames to the proxy's address are refused
/// under the box-to-host default-deny, never decided by its egress rules.
/// When the proxy document lands it extends this declaration, and the row
/// the fact fills is already waiting for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
// An empty table today, so an unknown field would be one the proxy document
// has not bound here yet — refused like every other field the policy schemas
// do not know (the same `deny_unknown_fields` [`SessionPolicy`] carries),
// rather than silently ignored into a shape no reader can tell from the
// minimum.
#[serde(deny_unknown_fields)]
pub struct CredentialedUpstream {}

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
    /// The box's declaration of a credentialed upstream (NET-134): `Some`
    /// marks the Box Egress Proxy's listener as this box's infrastructure —
    /// the one destination its egress rules never decide — while `None`, the
    /// absent declaration every policy without one carries, is no lane: the
    /// proxy's address stays refused under the box-to-host default-deny.
    /// Skipped when `None`, so a policy that declares nothing serializes
    /// exactly as it did before this field existed — the shape every stored
    /// record and every reading client already holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentialed_upstream: Option<CredentialedUpstream>,
}

impl SessionPolicy {
    /// Builds a policy from its egress and ingress halves, carrying no
    /// credentialed-upstream declaration (NET-134): the lane a box asks the
    /// proxy for is its declaration's own, never a default.
    #[must_use]
    pub fn new(egress: Option<EgressPolicy>, ingress: Option<IngressPolicy>) -> Self {
        Self {
            egress,
            ingress,
            credentialed_upstream: None,
        }
    }
}

// ---------------------------------------------------------------------------
// The deny-all egress default's rollout (NET-074..NET-077).
//
// An absent `egress` section used to mean allow-all on every dimension
// (03-spec R2.1). The deny-all default replaces that for an own-address box:
// once in force it reaches nothing outside itself, an opt-out keeps the
// shipped default, and the release before it only announces the change.
// ---------------------------------------------------------------------------

/// Which release the deny-all egress default is in (NET-074..NET-077): a
/// build-time fact, not configuration, because it is decided by which build
/// is running. Every path that needs it — the session gate, the session-start
/// log line, `min session policy`, the activate announcement — reads
/// [`EGRESS_DEFAULT_PHASE`] rather than a flag nobody could set differently
/// within one build.
///
/// Deliberately not `#[non_exhaustive]`: a future phase (a default retired
/// after its soak, say) must break the exhaustive matches over this enum,
/// forcing each one to say what the new phase means for it, rather than
/// falling into a wildcard arm that silently keeps the old answer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EgressDefaultPhase {
    /// The coming default is announced at activate (NET-076); an absent
    /// `egress` section still allows all.
    Announced,
    /// The default binds: an own-address box created with no `egress`
    /// section reaches nothing outside itself (NET-074) and shows
    /// `deny all` in `min session policy` (NET-075), the opt-out excepted
    /// (NET-077).
    InForce,
}

/// The phase this build ships: the coming default is announced (NET-076),
/// so an absent `egress` section still allows all and `activate` prints the
/// change it will bring. The release that turns the default in force is a
/// plan fact, and no plan has named one yet; when one does, this constant is
/// the whole cutover — every reader of it (the session gate, the
/// session-start line, `min session policy`, the activate notice) follows.
pub const EGRESS_DEFAULT_PHASE: EgressDefaultPhase = EgressDefaultPhase::Announced;

/// The egress a box's traffic is actually held to: its declared section when
/// it has one, otherwise the default [`effective_egress`] resolves for an
/// absent one. This is what the gate enforces and what `min session policy`
/// shows; the declaration itself stays untouched on the record, so the
/// strict [`SessionPolicy`] a client reads back is exactly what the box was
/// launched with.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveEgress {
    /// An absent `egress` section under the in-force default (NET-074):
    /// nothing outside the box is reachable, the resolver Minimal owns for
    /// it excepted (NET-079).
    DenyAll,
    /// The shipped default (03-spec R2.1): every dimension allows all. What
    /// an absent section keeps before the default is in force, behind the
    /// daemon's opt-out (NET-077), and on any box without an address of its
    /// own.
    #[default]
    AllowAll,
    /// The box declared its own egress section; carried verbatim.
    Declared(EgressPolicy),
}

impl EffectiveEgress {
    /// The one-line verdict the egress block prints in place of its rows,
    /// or `None` when the section has rule rows to list. A default is marked
    /// as one (`deny-all (default)`, `allow-all (default)`); a declared
    /// deny-all ([`EgressPolicy::admits_nothing`]) prints unmarked, because
    /// the box chose it. The single source for `min session policy` and the
    /// TUI's detail pane, so the two never spell a verdict differently.
    #[must_use]
    pub fn summary_label(&self) -> Option<&'static str> {
        match self {
            Self::DenyAll => Some("deny-all (default)"),
            Self::AllowAll => Some("allow-all (default)"),
            Self::Declared(egress) if egress.admits_nothing() => Some("deny-all"),
            Self::Declared(_) => None,
        }
    }
}

/// The answer `GetEffectiveSessionPolicy` serves and `min session policy`
/// renders (NET-075) — the shape that can carry
/// [`EffectiveEgress::DenyAll`] without rewriting the strict
/// [`SessionPolicy`] declaration. The ingress half is carried verbatim:
/// ingress has no rollout default.
///
/// The egress here is not an `Option`: an absent section has already been
/// resolved into [`EffectiveEgress::DenyAll`] or [`EffectiveEgress::AllowAll`],
/// so a reader cannot mistake "no declaration" for "no rules".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
// Same reason as the attribute on `SessionPolicy`: the response rides an
// `#[serde(untagged)]` `Errorable`, and the daemon's `{"error": "..."}` reply
// must fall through to the `Err` arm rather than decode as a valid policy —
// a silent false negative on a security-introspection command. Its `egress`
// is required, not an `Option`, so the error reply falls through on its own.
// The strictness is also the wire contract with an older `min`: an old client
// rejects a key it has no field for, so a fact that did not exist when it was
// built must ride its own reply (`GetSessionRuntimeFacts`, the way live
// ingress rides `GetLiveIngress`) rather than a new field here.
#[serde(deny_unknown_fields)]
pub struct EffectiveSessionPolicy {
    /// The effective egress: the declaration, or the default the rollout
    /// phase and the daemon's opt-out leave in force.
    pub egress: EffectiveEgress,
    /// Ingress policy; `None` when no explicit ingress config is present.
    pub ingress: Option<IngressPolicy>,
}

/// Resolves the effective egress of a box (NET-074/NET-077): a declared
/// section is carried verbatim whatever the phase — a box that says what it
/// wants gets what it said — and an absent `egress` section is the default's
/// to decide. Deny-all once [`EgressDefaultPhase::InForce`], on an
/// own-address box ([`NetworkMode::OwnIp`]) whose daemon has not opted out;
/// the shipped allow-all of 03-spec R2.1 in every other case: before the
/// default is in force, behind the opt-out, or for a box that shares its
/// host's namespace (or has no network at all) and so owns no address of its
/// own to deny from.
///
/// `opt_out` is the daemon's deny-all opt-out flag (NET-077); the caller
/// threads it in from the daemon's configuration, because it is the daemon —
/// not the client asking about a session — that knows whether it set the
/// flag.
#[must_use]
pub fn effective_egress(
    declared: Option<&EgressPolicy>,
    network: NetworkMode,
    phase: EgressDefaultPhase,
    opt_out: bool,
) -> EffectiveEgress {
    match declared {
        Some(section) => EffectiveEgress::Declared(section.clone()),
        None => match (phase, network) {
            (EgressDefaultPhase::InForce, NetworkMode::OwnIp) if !opt_out => {
                EffectiveEgress::DenyAll
            }
            _ => EffectiveEgress::AllowAll,
        },
    }
}

/// Reads the deny-all opt-out (NET-077) off its raw environment spelling:
/// the one parse the VM host daemon (`MINVMD_EGRESS_DENY_ALL_OPT_OUT`) and
/// the guest daemon (the boot token it is handed) share, so the two can
/// never read the same value differently. Only `1`, `true`, `yes` or `on`
/// opt out, case-insensitive and trimmed; absent or anything else fails
/// closed to the build's egress default.
#[must_use]
pub fn egress_deny_all_opt_out_from_raw(raw: Option<&str>) -> bool {
    raw.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// The lowest host port a dynamic ingress range may start at: below it a
/// port is privileged, and the rootless switch cannot publish one. One
/// definition for the launch check ([`Record::validate_policy`]) and the
/// CLI's `--dynamic-range` flag, so the two can never disagree.
pub const MIN_DYNAMIC_INGRESS_PORT: u16 = 1024;

/// The refusal for a non-empty `ingress` on a box that is not own-IP: a
/// dynamic declaration (a range or a non-deny stance) names the dynamic
/// fields, otherwise the refusal names the port mappings. The dynamic check
/// comes first, in the same order as the CLI's refusals, so a policy carrying
/// both gets the same first complaint from either surface.
fn ingress_requires_own_ip(ingress: &IngressPolicy, mode: NetworkMode) -> PolicyError {
    let dynamic = ingress.dynamic_allowed_range.is_some()
        || ingress
            .dynamic_ingress
            .is_some_and(|d| d != DynamicIngress::Deny);
    if dynamic {
        PolicyError::DynamicIngressRequiresOwnIp { mode }
    } else {
        PolicyError::IngressRequiresOwnIp { mode }
    }
}

/// Why a session's networking policy is incompatible with its network mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// An egress policy was set on a [`NetworkMode::NoNet`] `PTask`. An
    /// own-address (`OwnIp`) and a host-address (`HostNet`) box both carry a
    /// network their egress rules can bound; a none box has none, so there is
    /// nothing to enforce the declaration on and it is rejected. Names the
    /// mode word, not the `Debug` name, as the ingress variants below do.
    #[error(
        "egress rules need network mode own_ip or host_ip (this box is {}): a none box \
         has no network to apply them to",
        .mode.word()
    )]
    EgressRequiresNetwork { mode: NetworkMode },
    /// A static ingress port mapping was set on a `PTask` that is not
    /// [`NetworkMode::OwnIp`]. Names the policy fields and the mode word, not
    /// CLI flags: every client reads this refusal, and the CLI names its own
    /// flags in a refusal of its own before the request is sent.
    #[error(
        "ingress port mappings need network mode own_ip (this box is {}): only an own-IP \
         box has a published address to apply them to",
        .mode.word()
    )]
    IngressRequiresOwnIp { mode: NetworkMode },
    /// A dynamic ingress declaration (a non-deny `dynamic_ingress` stance or a
    /// `dynamic_allowed_range`), with or without a static mapping, was set on a `PTask`
    /// that is not [`NetworkMode::OwnIp`]. Neutral wording, as for
    /// [`PolicyError::IngressRequiresOwnIp`].
    #[error(
        "ingress dynamic_ingress and dynamic_allowed_range need network mode own_ip (this \
         box is {}): only an own-IP box has a published address to apply them to",
        .mode.word()
    )]
    DynamicIngressRequiresOwnIp { mode: NetworkMode },
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
    /// Held to the same launch-time check as an `allow_subnets` entry, since
    /// both are parsed by #553's egress-enforcement layer.
    #[error("egress deny_subnets entry {cidr:?} is not a valid CIDR prefix")]
    InvalidDenySubnet { cidr: String },
    /// An egress `allow_dns_hosts` entry is not a valid DNS hostname: empty,
    /// contains whitespace, a label longer than 63 bytes or empty, a total
    /// length over 253, or characters outside `[A-Za-z0-9-_.]`. Rejected at
    /// launch so a name that can never match is named where it can be fixed,
    /// rather than stored verbatim as an allow rule that admits nothing.
    #[error(
        "egress allow_dns_hosts entry {host:?} is not a valid DNS hostname \
         (wildcards are not supported; write an internationalized name in its \
         punycode xn-- form)"
    )]
    InvalidDnsHost { host: String },
    /// An ingress `dynamic_allowed_range` was given with its lower bound above
    /// its upper bound (e.g. `(8443, 8000)`). The range is inclusive, so a
    /// reversed pair describes no ports; rejected at launch so the misconfig is
    /// named where it can be fixed, rather than persisting on the `Record` as
    /// a permit the listen-publication surface (NET-016) would silently read
    /// as permitting nothing.
    #[error(
        "ingress dynamic_allowed_range lower bound {lo} exceeds upper bound \
         {hi}; the range is inclusive — set lo <= hi"
    )]
    InvalidDynamicRange { lo: u16, hi: u16 },
    /// An ingress `dynamic_allowed_range` lower bound is a privileged host port
    /// (< 1024). The lower bound is the smallest host port a listen-published
    /// port may publish (NET-016), so the same rootless-privilege constraint
    /// that rejects a static mapping's privileged `external_port` applies.
    /// Rejected at launch so the misconfig is named where it can be fixed,
    /// rather than surfacing as a publication the forwarder cannot bind.
    #[error(
        "ingress dynamic_allowed_range lower bound {lo} is a privileged host \
         port; minimald refuses to publish host ports below 1024 — set a lower \
         bound >= 1024"
    )]
    PrivilegedDynamicRange { lo: u16 },
    /// An ingress port mapping publishes the same host port on the same
    /// transport more than once. gvproxy's static forwarder binds one forward
    /// per transport and host port, so the duplicate is rejected at launch
    /// rather than failing opaquely at attach. The same host port on TCP and
    /// on UDP is two distinct binds and is allowed.
    #[error(
        "ingress port mapping publishes {proto:?} host port {external_port} \
         more than once; each host port may appear in at most one ingress \
         mapping per protocol"
    )]
    DuplicateIngressPort { external_port: u16, proto: IpProto },
    /// An ingress port mapping targets box port 0. Port 0 is reserved and
    /// cannot receive forwarded connections, so it is rejected at launch
    /// rather than failing opaquely at attach.
    #[error(
        "ingress port mapping targets box port 0; port 0 is reserved — \
         choose an internal_port >= 1"
    )]
    InvalidIngressPort { internal_port: u16 },
}

/// The static ingress mapping checks [`Record::validate_policy`] runs before
/// its mode check, so a malformed mapping is named wherever it appears.
fn validate_port_mappings(mappings: &[PortMapping]) -> Result<(), PolicyError> {
    // gvproxy's static forwarder only exposes TCP and UDP, so an ingress
    // mapping with any other transport is a configuration error wherever it
    // appears — reject it before the mode check so it never reaches the
    // forwarder as a silently-defaulted protocol.
    if let Some(proto) = mappings
        .iter()
        .map(|mapping| mapping.proto)
        .find(|proto| !matches!(proto, IpProto::Tcp | IpProto::Udp))
    {
        return Err(PolicyError::UnsupportedIngressProtocol { proto });
    }
    // minimald refuses to publish a privileged host port (< 1024): binding
    // one needs elevated privilege the rootless switch lacks, so reject it
    // at validation time with a remediation rather than letting the expose
    // fail opaquely against gvproxy.
    if let Some(external_port) = mappings
        .iter()
        .map(|mapping| mapping.external_port)
        .find(|&port| port < 1024)
    {
        return Err(PolicyError::PrivilegedPort { external_port });
    }
    // A host port may be published at most once per transport: gvproxy's
    // static forwarder keys each forward by protocol and host address, so a
    // second mapping of the same host port on the same transport fails to
    // bind. It is rejected at launch rather than failing opaquely at attach.
    // TCP and UDP on one host port are distinct binds and both stand.
    let mut seen = std::collections::HashSet::new();
    if let Some(mapping) = mappings
        .iter()
        .find(|mapping| !seen.insert((mapping.external_port, mapping.proto)))
    {
        return Err(PolicyError::DuplicateIngressPort {
            external_port: mapping.external_port,
            proto: mapping.proto,
        });
    }
    // Box port 0 is reserved and cannot receive forwarded connections, so
    // a mapping targeting it is rejected at launch rather than failing
    // opaquely at attach.
    if let Some(internal_port) = mappings
        .iter()
        .map(|mapping| mapping.internal_port)
        .find(|&port| port == 0)
    {
        return Err(PolicyError::InvalidIngressPort { internal_port });
    }
    Ok(())
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

/// Whether `s` is a valid DNS hostname for an egress `allow_dns_hosts` entry:
/// non-empty, no whitespace, every label non-empty and at most 63 bytes, the
/// whole name at most 253 bytes, every character in `[A-Za-z0-9-_.]`, and no
/// label starting or ending with a hyphen (RFC 1035), since no query name can
/// carry one.
/// One trailing dot is tolerated because the DNS gate strips it before
/// matching, so `example.com.` and `example.com` name the same host.
fn is_valid_dns_host(s: &str) -> bool {
    if s.chars().any(char::is_whitespace) {
        return false;
    }
    let name = s.strip_suffix('.').unwrap_or(s);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

/// The normalized (host-bits-masked) form of a syntactically valid CIDR
/// prefix, or `None` when `s` is not a valid prefix or already has no host
/// bits set. `10.0.0.1/8` normalizes to `10.0.0.0/8`; `10.0.0.0/8` is
/// already normalized and yields `None`, so callers can print a notice only
/// when the user's string is read as a different network than they wrote.
/// IPv6 prefixes also yield `None`: the egress rules compile only IPv4
/// subnets, so an IPv6 entry is never read as any network.
#[must_use]
pub fn normalized_cidr(s: &str) -> Option<String> {
    let (addr, prefix) = s.split_once('/')?;
    let prefix = prefix.parse::<u8>().ok()?;
    let ip = addr.parse::<std::net::IpAddr>().ok()?;
    let normalized = match ip {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return None;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let masked = u32::from(v4) & mask;
            if masked == u32::from(v4) {
                return None;
            }
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(masked))
        }
        std::net::IpAddr::V6(_) => return None,
    };
    Some(format!("{normalized}/{prefix}"))
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

/// The pair of addresses a VM host daemon allocates for a box and hands
/// back to its creator (T66): where the box lives on the switch, and where
/// it is published on the guest's loopback.
///
/// One type because the pair is one fact — handed together over the
/// registration, carried together in the create request, recorded together
/// on the session record — and every consumer of one half needs to be able
/// to say it came from a host allocation, not a local draw.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BoxAddresses {
    /// The box's address on the switch: the lease its frames must carry
    /// (NET-084) and the key the host-side box table's row is filed under.
    pub switch_address: Ipv4Addr,
    /// The box's address on the guest's loopback, from the slice the host
    /// switch publishes at.
    pub loopback_address: Ipv4Addr,
}

/// The per-box egress enforcement state a host-address session's verdict runs
/// under (NET-079): `per_box` when the session's own launch placed its box in
/// a classifier leaf of the host's cgroup tree — the state a host that can
/// decide per box gives the host-address boxes it launches — and `none` when
/// the launch did not, because the host cannot decide per box at all, or
/// because the box got no leaf to be decided on, and the box runs with the
/// host's address and no verdict of its own.
///
/// Defined here — beside the [`Record`] field that carries a box's own launch
/// outcome — rather than in the RPC crate that first spelled it, because the
/// record is a session-plane type that crate already depends on; the RPC
/// crate re-exports it under the path its clients spell, so no wire form
/// changes.
///
/// The default is `none` — a daemon that has not read its host, or one whose
/// host cannot decide, both spell the state the boxes on it run in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIpEnforcement {
    /// The box's launch placed it in a classifier leaf: its egress verdict is
    /// decided on that leaf of its own.
    PerBox,
    /// The box runs with the host's address and no verdict of its own.
    #[default]
    None,
}

impl HostIpEnforcement {
    /// The machine spelling the stringly surfaces carry — the create
    /// response, the session runtime-facts reply, the daemon's log lines —
    /// so a script that greps one surface for the state finds the same word
    /// on every other.
    #[must_use]
    pub fn machine_str(self) -> &'static str {
        match self {
            Self::PerBox => "per_box",
            Self::None => "none",
        }
    }
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

    /// The addresses the VM host daemon handed this box's registration at
    /// activation (T66): the switch address the attach path configures the
    /// tap with instead of drawing its own, and the published loopback
    /// address the host side names the box by. Persisted so a re-attach —
    /// including after a daemon restart — attaches with the same address
    /// the host table still holds a row for; drawing a fresh one would
    /// silently orphan the row and drop the box to the egress gate's
    /// unregistered-source interim. Defaults to `None` for records that
    /// predate the field (every pre-T66 session): those boxes self-allocate
    /// exactly as they always have.
    #[serde(default)]
    pub box_addresses: Option<BoxAddresses>,

    /// The per-box egress enforcement this session's own launch placed its
    /// host-address box under (NET-079): `per_box` when the launch placed the
    /// box in a classifier leaf of the host's cgroup tree, `none` when it did
    /// not — the box's own record of its launch, kept on the session record
    /// rather than in `attrs` so no client can assert it, and daemon-owned
    /// from its first write: the create strips the key for every mode and
    /// only a launch ever sets this field.
    ///
    /// The reading surfaces show this record, not the host's current state:
    /// a box launched unenforced stays `none` for its life even after a later
    /// launch decides per box, because the outcome is a fact about the launch
    /// that produced it and never about the host as it stands now. Only the
    /// display halves lower it — a host whose table has since stopped
    /// deciding reads as `none` for every box on it — never raise it.
    ///
    /// `None` for a session that is not host-address (its verdict is decided
    /// on address leases, never on the host's cgroup tree) and for a
    /// host-address box that has not launched yet, whose reads fall back to
    /// the host's state. Defaults to `None` for records that predate the
    /// field: pre-existing sessions had no launch to record, and their reads
    /// answer over the host's state exactly as they did before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip_enforcement: Option<HostIpEnforcement>,

    /// Whether a launch has bound this box's host-side row (NET-138): set,
    /// and persisted, by the first host launch of a box that carries
    /// [`Self::box_addresses`]. The row lives exactly as long as that
    /// launch's switch attachment and is never registered again, so once
    /// this is set, any host other than that first launch's is rowless —
    /// including every host after a daemon restart. Daemon-owned, like
    /// [`Self::host_ip_enforcement`]. Defaults to `false` for records that
    /// predate the field and for a registered box that has not launched yet.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub host_row_bound: bool,

    /// Free-form attributes.
    pub attrs: BTreeMap<String, String>,
}

impl Record {
    /// [`Record::validate_policy`] plus the checks a record must pass only
    /// when it is created: added after records were already stored, they
    /// would strand an existing session if they ran on every launch.
    ///
    /// # Errors
    ///
    /// Any error [`Record::validate_policy`] returns, or
    /// [`PolicyError::InvalidDnsHost`] when an egress `allow_dns_hosts` entry
    /// is not a valid DNS hostname.
    pub fn validate_new_policy(&self) -> Result<(), PolicyError> {
        self.validate_policy()?;
        if let Some(bad) = self
            .policy
            .egress
            .as_ref()
            .and_then(EgressPolicy::first_invalid_dns_host)
        {
            return Err(PolicyError::InvalidDnsHost {
                host: bad.to_owned(),
            });
        }
        Ok(())
    }

    /// Validates that this record's networking policy is compatible with its
    /// network mode (R2.1/R2.3, as amended for host-address egress): an egress
    /// policy is accepted on an [`NetworkMode::OwnIp`] and on a
    /// [`NetworkMode::HostNet`] `PTask` — both carry a network their egress
    /// rules can bound (NET-120) — and rejected only on `NoNet`, which has no
    /// network to enforce it on (NET-065). An ingress policy stays
    /// `OwnIp`-only, since the switch's static forwarder is the only ingress
    /// surface minimald can apply per-session. Returns an error naming the
    /// first incompatible section.
    ///
    /// Runs on every launch, so it holds only checks every stored record
    /// already passed when it was created; a check added later goes in
    /// [`Record::validate_new_policy`] instead, so an upgrade never strands a
    /// session that was accepted before it.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::EgressRequiresNetwork`] when an egress policy is
    /// set on a none (`NoNet`) `PTask`, or
    /// [`PolicyError::DynamicIngressRequiresOwnIp`] when a dynamic ingress
    /// declaration, or [`PolicyError::IngressRequiresOwnIp`] when only a static
    /// ingress mapping, is set on anything but an `OwnIp` `PTask`. Returns
    /// [`PolicyError::UnsupportedIngressProtocol`] for an ingress mapping whose
    /// transport gvproxy's forwarder cannot expose,
    /// [`PolicyError::PrivilegedPort`] for one that publishes a host port below
    /// 1024, [`PolicyError::DuplicateIngressPort`] for a host port published
    /// twice on one transport, or [`PolicyError::InvalidIngressPort`] for one
    /// that targets box port 0. For a `PTask` that accepts egress, returns
    /// [`PolicyError::InvalidSubnet`] when an egress `allow_subnets` entry is
    /// not a valid CIDR prefix, [`PolicyError::InvalidDenySubnet`] when a
    /// `deny_subnets` entry is not, [`PolicyError::InvalidDynamicRange`] when
    /// the ingress `dynamic_allowed_range` lower bound exceeds its upper bound,
    /// or [`PolicyError::PrivilegedDynamicRange`] when that lower bound is a
    /// privileged host port (< 1024). Does not validate `dynamic_ingress`, which
    /// is accepted on an `OwnIp` `PTask` and serialized verbatim.
    pub fn validate_policy(&self) -> Result<(), PolicyError> {
        if let Some(ingress) = &self.policy.ingress {
            validate_port_mappings(&ingress.port_mappings)?;
        }
        // A none box has no network: there is nothing to enforce an egress or
        // ingress declaration on, so both are configuration errors (NET-065).
        if self.network == NetworkMode::NoNet {
            if self.policy.egress.is_some() {
                return Err(PolicyError::EgressRequiresNetwork { mode: self.network });
            }
            if let Some(ingress) = self.policy.ingress.as_ref().filter(|i| !i.is_empty()) {
                return Err(ingress_requires_own_ip(ingress, self.network));
            }
            return Ok(());
        }
        // An own-address and a host-address box both carry a network their
        // egress rules can bound (NET-120 accepts the declaration on a
        // host-address box), so the syntactic checks run for both: every
        // allow and deny entry must be a valid CIDR prefix, so a misconfigured
        // subnet is named at launch rather than surfacing opaquely when
        // #553's enforcement layer parses it.
        if let Some(bad) = self
            .policy
            .egress
            .as_ref()
            .and_then(EgressPolicy::first_invalid_subnet)
        {
            return Err(PolicyError::InvalidSubnet {
                cidr: bad.to_owned(),
            });
        }
        if let Some(bad) = self
            .policy
            .egress
            .as_ref()
            .and_then(EgressPolicy::first_invalid_deny_subnet)
        {
            return Err(PolicyError::InvalidDenySubnet {
                cidr: bad.to_owned(),
            });
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
                if lo < MIN_DYNAMIC_INGRESS_PORT {
                    return Err(PolicyError::PrivilegedDynamicRange { lo });
                }
            }
            return Ok(());
        }
        // Host-address box: egress is accepted, but ingress still requires an
        // own address — the switch's forwarder is the only per-session ingress
        // surface, and a host-address box shares its host's namespace.
        if let Some(ingress) = self.policy.ingress.as_ref().filter(|i| !i.is_empty()) {
            return Err(ingress_requires_own_ip(ingress, self.network));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verdict strings `min session policy` and the TUI pane both print.
    #[test]
    fn effective_egress_summary_labels_are_pinned() {
        assert_eq!(
            EffectiveEgress::DenyAll.summary_label(),
            Some("deny-all (default)")
        );
        assert_eq!(
            EffectiveEgress::AllowAll.summary_label(),
            Some("allow-all (default)")
        );
        assert_eq!(
            EffectiveEgress::Declared(EgressPolicy::deny_all()).summary_label(),
            Some("deny-all")
        );
        let rules = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            ..EgressPolicy::deny_all()
        };
        assert_eq!(EffectiveEgress::Declared(rules).summary_label(), None);
    }

    /// `word()` pins the CLI and spec vocabulary, and stays distinct from
    /// the serde form where the two spellings differ: a refactor that
    /// routed either through the other would rename a log field or a wire
    /// value.
    #[test]
    fn network_mode_word_is_the_cli_word_not_the_serde_form() {
        assert_eq!(NetworkMode::NoNet.word(), "none");
        assert_eq!(NetworkMode::HostNet.word(), "host_ip");
        assert_eq!(NetworkMode::OwnIp.word(), "own_ip");
        for mode in [NetworkMode::NoNet, NetworkMode::HostNet] {
            let serde = serde_json_lenient::to_string(&mode).unwrap();
            assert_ne!(mode.word(), serde.trim_matches('"'), "{mode:?}");
        }
    }

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
            box_addresses: None,
            host_ip_enforcement: None,
            host_row_bound: false,
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

    /// NET-134: the session policy gains a box's declaration of a
    /// credentialed upstream — the minimum of the proxy document's field
    /// schema — and that is all it needs to gain. The declaration parses from
    /// the wire it rides to the host (`Some`), a policy written before the
    /// field existed parses as no declaration (`None`), and a field the
    /// minimum does not hold is refused rather than ignored: the proxy
    /// document extends this declaration when it lands, and until then
    /// nothing may smuggle a steering setting through it.
    #[test]
    fn credentialed_upstream_declaration_parses() {
        let declared: SessionPolicy = serde_json_lenient::from_str(
            r#"{"egress":null,"ingress":null,"credentialed_upstream":{}}"#,
        )
        .expect("a policy carrying the declaration must parse");
        assert_eq!(
            declared.credentialed_upstream,
            Some(CredentialedUpstream {}),
            "the declaration is carried on the policy, not swallowed"
        );
        // And it round-trips with the policy that carries it, so the host
        // the registration reaches reads the same lane the client declared.
        let json = serde_json_lenient::to_string(&declared).unwrap();
        let round_tripped: SessionPolicy = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(round_tripped, declared);

        // A policy written before the field existed declares nothing: the
        // absent declaration is the default, the JSON such a policy already
        // serialized to still parses, and serializing it back changes
        // nothing — the field rides additively, never as a migration.
        let legacy: SessionPolicy =
            serde_json_lenient::from_str(r#"{"egress":null,"ingress":null}"#)
                .expect("a policy predating the field must still parse");
        assert_eq!(
            legacy.credentialed_upstream, None,
            "no declaration in the JSON is no lane, not an error"
        );
        let json = serde_json_lenient::to_string(&legacy).unwrap();
        assert!(
            !json.contains("credentialed_upstream"),
            "a policy with no declaration serializes exactly as it did before \
             the field existed, got: {json}"
        );

        // The minimum holds no fields of its own: a steering setting the
        // proxy document will bind is refused until that document lands,
        // never silently dropped from a declaration that cannot carry it.
        assert!(
            serde_json_lenient::from_str::<SessionPolicy>(
                r#"{"egress":null,"ingress":null,"credentialed_upstream":{"steering":"dns"}}"#
            )
            .is_err(),
            "a field the minimum does not hold is refused, not ignored"
        );
    }

    #[test]
    fn egress_on_host_ip_box_accepted() {
        // NET-120: an egress section is valid on a host-address box too — its
        // declaration is enforced on the box's own cgroup — superseding the
        // shipped R2.1 rule that rejected it there.
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(
                Some(EgressPolicy {
                    allow_subnets: Some(vec!["10.0.0.0/8".into()]),
                    deny_subnets: Some(vec!["192.168.0.0/16".into()]),
                    ..EgressPolicy::default()
                }),
                None,
            ),
        );
        assert!(record.validate_policy().is_ok());
    }

    /// NET-077: the opt-out's parse fails closed — only the truthy set opts
    /// out; absent or anything else keeps the build's egress default.
    #[test]
    fn the_egress_opt_out_fails_closed() {
        assert!(!egress_deny_all_opt_out_from_raw(None));
        for value in ["1", "true", "TRUE", "yes", "on", " On "] {
            assert!(egress_deny_all_opt_out_from_raw(Some(value)), "{value:?}");
        }
        for value in ["", "0", "no", "off", "false", "garbage", "1x", "enabled"] {
            assert!(!egress_deny_all_opt_out_from_raw(Some(value)), "{value:?}");
        }
    }

    /// NET-074/NET-075/NET-076/NET-077: what an absent `egress` section
    /// resolves to, by rollout phase, opt-out, and network mode — and that
    /// the deny-all arm is not a label but the section whose compiled rules
    /// admit nothing.
    #[test]
    fn effective_egress_by_phase_and_opt_out() {
        use crate::core::egress::EgressRules;

        // The address of the resolver Minimal owns for a box: the switch
        // gateway, whose value only shapes the carve-out's key.
        let resolver = [100, 64, 0, 1];
        // The box's lease, whose value only shapes the source check
        // (NET-084), proven in `core::egress`; what is asserted here is the
        // egress dimensions the deny-all arm materializes to.
        let lease = [100, 64, 0, 9];
        let declared = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into()]),
            ..EgressPolicy::default()
        };

        // A declared section is carried verbatim in every phase, opted out
        // or not, on every mode: the default only fills an absent section.
        for phase in [EgressDefaultPhase::Announced, EgressDefaultPhase::InForce] {
            for opt_out in [false, true] {
                for network in [NetworkMode::OwnIp, NetworkMode::HostNet, NetworkMode::NoNet] {
                    assert_eq!(
                        effective_egress(Some(&declared), network, phase, opt_out),
                        EffectiveEgress::Declared(declared.clone()),
                        "a declared egress section must survive phase {phase:?}, \
                         opt_out {opt_out}, mode {network:?} untouched",
                    );
                }
            }
        }

        // The one case the default rewrites: an own-address box with no
        // `egress` section, once the default is in force, unless the daemon
        // opted out (NET-077) — and still allow-all while the default is
        // only announced (NET-076's other half).
        assert_eq!(
            effective_egress(None, NetworkMode::OwnIp, EgressDefaultPhase::InForce, false),
            EffectiveEgress::DenyAll,
            "in force without the opt-out, an own-address box with no egress \
             section denies all (NET-074)",
        );
        assert_eq!(
            effective_egress(None, NetworkMode::OwnIp, EgressDefaultPhase::InForce, true),
            EffectiveEgress::AllowAll,
            "the opt-out keeps the shipped allow-all default (NET-077)",
        );
        assert_eq!(
            effective_egress(
                None,
                NetworkMode::OwnIp,
                EgressDefaultPhase::Announced,
                false
            ),
            EffectiveEgress::AllowAll,
            "while the default is only announced, an absent section still \
             allows all (NET-076)",
        );

        // The default scopes to own-address boxes: a box that shares its
        // host's namespace owns no address of its own to deny from, and a
        // none box has no network to deny on.
        for network in [NetworkMode::HostNet, NetworkMode::NoNet] {
            assert_eq!(
                effective_egress(None, network, EgressDefaultPhase::InForce, false),
                EffectiveEgress::AllowAll,
                "an absent section on a {network:?} box keeps the shipped default",
            );
        }

        // The deny-all arm materializes to the section that compiles to
        // rules admitting nothing: `Some(vec![])` on every allow dimension,
        // nothing denied — the shape `EgressRules::from_policy` builds and
        // `verdict` holds every external destination against, the resolver
        // carve-out excepted.
        assert_eq!(
            EgressRules::from_policy(Some(&EgressPolicy::deny_all()), resolver, lease),
            EgressRules::new(Some(Vec::new()), Some(Vec::new()), None, resolver, lease),
            "the deny-all section must compile to rules that admit nothing",
        );
    }

    #[test]
    fn admits_nothing_reads_the_deny_all_shape() {
        // The deny-all predicate is the one shape the egress gate refuses:
        // every `allow_*` dimension present and empty. An absent dimension
        // is allow-all for that dimension, and one non-empty list admits
        // something, so neither is deny-all.
        assert!(EgressPolicy::deny_all().admits_nothing());
        assert!(!EgressPolicy::default().admits_nothing());
        assert!(
            !EgressPolicy {
                allow_subnets: Some(vec!["10.0.0.0/8".into()]),
                ..EgressPolicy::default()
            }
            .admits_nothing()
        );
        assert!(
            !EgressPolicy {
                allow_dns_hosts: Some(vec!["example.com".into()]),
                ..EgressPolicy::default()
            }
            .admits_nothing()
        );
        assert!(
            !EgressPolicy {
                allow_protocols: Some(vec![IpProto::Tcp]),
                ..EgressPolicy::default()
            }
            .admits_nothing()
        );
        // Two dimensions present and empty is not enough: the third, absent
        // or non-empty, still admits something.
        assert!(
            !EgressPolicy {
                allow_subnets: Some(vec![]),
                allow_dns_hosts: Some(vec![]),
                ..EgressPolicy::default()
            }
            .admits_nothing()
        );
        assert!(
            !EgressPolicy {
                allow_subnets: Some(vec![]),
                allow_dns_hosts: Some(vec![]),
                allow_protocols: Some(vec![IpProto::Tcp]),
                ..EgressPolicy::default()
            }
            .admits_nothing()
        );
        // `deny_subnets` is not read: the deny-all shape stays deny-all
        // with a subtraction set.
        assert!(
            EgressPolicy {
                deny_subnets: Some(vec!["10.0.0.0/8".into()]),
                ..EgressPolicy::deny_all()
            }
            .admits_nothing()
        );
    }

    #[test]
    fn egress_on_none_box_is_validation_error() {
        // NET-065: a none box has no network, so there is nothing to enforce
        // an egress declaration on. It is the only mode that rejects egress.
        let record = record_with(
            NetworkMode::NoNet,
            SessionPolicy::new(Some(EgressPolicy::default()), None),
        );
        let err = record.validate_policy().unwrap_err();
        assert_eq!(
            err,
            PolicyError::EgressRequiresNetwork {
                mode: NetworkMode::NoNet
            }
        );
        // The refusal names the mode word, not the `Debug` name.
        assert_eq!(
            err.to_string(),
            "egress rules need network mode own_ip or host_ip (this box is none): a none box \
             has no network to apply them to"
        );
    }

    #[test]
    fn spec_accepts_egress_fields() {
        // NET-060: the box spec accepts all four egress fields —
        // allow_subnets, allow_protocols, allow_dns_hosts and deny_subnets —
        // on an own-address box and on a host-address box alike.
        let egress = EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "fd00::/8".into()]),
            allow_protocols: Some(vec![IpProto::Tcp, IpProto::Udp]),
            allow_dns_hosts: Some(vec!["github.com".into()]),
            deny_subnets: Some(vec!["169.254.169.254/32".into()]),
        };
        for network in [NetworkMode::OwnIp, NetworkMode::HostNet] {
            let record = record_with(network, SessionPolicy::new(Some(egress.clone()), None));
            assert!(
                record.validate_policy().is_ok(),
                "all four egress fields must validate on {network:?}"
            );
        }
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
            dynamic_ingress: None,
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
    fn own_ip_refusals_name_the_fields_that_caused_them() {
        // A static mapping names the port mappings; a dynamic-only declaration
        // names the dynamic fields. Both name the box's mode as a word and no
        // CLI flag.
        let static_ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let err = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(None, Some(static_ingress)),
        )
        .validate_policy()
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "ingress port mappings need network mode own_ip (this box is host_ip): only an \
             own-IP box has a published address to apply them to"
        );

        let range_only = IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some((8000, 8443)),
            dynamic_ingress: None,
        };
        let err = record_with(
            NetworkMode::NoNet,
            SessionPolicy::new(None, Some(range_only)),
        )
        .validate_policy()
        .unwrap_err();
        assert_eq!(
            err,
            PolicyError::DynamicIngressRequiresOwnIp {
                mode: NetworkMode::NoNet
            }
        );
        assert_eq!(
            err.to_string(),
            "ingress dynamic_ingress and dynamic_allowed_range need network mode own_ip (this \
             box is none): only an own-IP box has a published address to apply them to"
        );

        // A static mapping alongside a dynamic declaration names the dynamic
        // fields first, matching the CLI's check order.
        let mixed = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: Some(DynamicIngress::Allow),
        };
        assert_eq!(
            record_with(NetworkMode::HostNet, SessionPolicy::new(None, Some(mixed)))
                .validate_policy(),
            Err(PolicyError::DynamicIngressRequiresOwnIp {
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
            dynamic_ingress: None,
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
            dynamic_ingress: None,
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
            dynamic_ingress: None,
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
            dynamic_ingress: None,
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
            dynamic_ingress: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert!(record.validate_policy().is_ok());
    }

    #[test]
    fn duplicate_host_port_is_rejected() {
        // Publishing the same host port twice on one transport — even to
        // different box ports — is rejected, since gvproxy's static forwarder
        // cannot bind the same host port and protocol to two destinations.
        let ingress = IngressPolicy {
            port_mappings: vec![
                PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                },
                PortMapping {
                    external_port: 18080,
                    internal_port: 443,
                    proto: IpProto::Tcp,
                },
            ],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::DuplicateIngressPort {
                external_port: 18080,
                proto: IpProto::Tcp,
            })
        );
    }

    #[test]
    fn same_host_port_on_tcp_and_udp_is_allowed() {
        // TCP and UDP on one host port are distinct binds: gvproxy keys each
        // forward by protocol and host address, so both mappings stand.
        let ingress = IngressPolicy {
            port_mappings: vec![
                PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: IpProto::Tcp,
                },
                PortMapping {
                    external_port: 18080,
                    internal_port: 80,
                    proto: IpProto::Udp,
                },
            ],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert!(record.validate_policy().is_ok());
    }

    #[test]
    fn box_port_zero_is_rejected() {
        // Port 0 is reserved and cannot receive forwarded connections, so a
        // mapping targeting it is rejected at launch.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 0,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let record = record_with(NetworkMode::OwnIp, SessionPolicy::new(None, Some(ingress)));
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::InvalidIngressPort { internal_port: 0 })
        );
    }

    #[test]
    fn box_port_zero_check_precedes_mode_check() {
        // The box-port-0 check runs before the mode check, so a mapping
        // targeting port 0 on a non-OwnIp PTask surfaces as
        // InvalidIngressPort rather than IngressRequiresOwnIp.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 0,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        assert_eq!(
            record_with(
                NetworkMode::HostNet,
                SessionPolicy::new(None, Some(ingress))
            )
            .validate_policy(),
            Err(PolicyError::InvalidIngressPort { internal_port: 0 })
        );
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
    fn invalid_egress_deny_subnet_is_rejected() {
        // A deny_subnets entry is held to the same syntactic check as an
        // allow_subnets entry, and the check runs on a host-address box too —
        // both modes accept egress, so both parse the same rules.
        for network in [NetworkMode::OwnIp, NetworkMode::HostNet] {
            let egress = EgressPolicy {
                deny_subnets: Some(vec!["10.0.0.0/8".into(), "not-a-cidr".into()]),
                ..EgressPolicy::default()
            };
            let record = record_with(network, SessionPolicy::new(Some(egress), None));
            assert_eq!(
                record.validate_policy(),
                Err(PolicyError::InvalidDenySubnet {
                    cidr: "not-a-cidr".into()
                })
            );
        }
    }

    #[test]
    fn invalid_egress_dns_host_is_rejected() {
        // An allow_dns_hosts entry that is not a valid DNS hostname is rejected
        // at launch, naming the offending string, rather than being stored
        // verbatim as an allow rule that can never match the DNS gate.
        for network in [NetworkMode::OwnIp, NetworkMode::HostNet] {
            for host in [
                "",
                "not a host",
                "a".repeat(64).as_str(),
                "-",
                "-foo.example.com",
                "foo-.example.com",
            ] {
                let egress = EgressPolicy {
                    allow_dns_hosts: Some(vec!["github.com".into(), host.into()]),
                    ..EgressPolicy::default()
                };
                let record = record_with(network, SessionPolicy::new(Some(egress), None));
                assert_eq!(
                    record.validate_new_policy(),
                    Err(PolicyError::InvalidDnsHost { host: host.into() })
                );
                // Launch-time validation leaves it alone: a session stored
                // before the check existed must still attach after an upgrade.
                assert_eq!(record.validate_policy(), Ok(()));
            }
        }
    }

    #[test]
    fn valid_egress_dns_hosts_are_accepted() {
        // A trailing dot is tolerated (the DNS gate strips it before matching),
        // and underscores are permitted, matching the gate's normalization.
        let egress = EgressPolicy {
            allow_dns_hosts: Some(vec![
                "github.com".into(),
                "github.com.".into(),
                "my_host.internal".into(),
            ]),
            ..EgressPolicy::default()
        };
        for network in [NetworkMode::OwnIp, NetworkMode::HostNet] {
            let record = record_with(network, SessionPolicy::new(Some(egress.clone()), None));
            assert!(record.validate_new_policy().is_ok());
        }
    }

    #[test]
    fn normalized_cidr_masks_host_bits() {
        // A prefix with host bits set is read as its masked network; a prefix
        // already normalized yields `None` so no notice is printed for it.
        assert_eq!(
            normalized_cidr("10.0.0.1/8"),
            Some("10.0.0.0/8".to_string())
        );
        assert_eq!(normalized_cidr("10.0.0.0/8"), None);
        assert_eq!(normalized_cidr("fd00::1/8"), None);
        assert_eq!(normalized_cidr("fd00::/8"), None);
        assert_eq!(normalized_cidr("not-a-cidr"), None);
    }

    #[test]
    fn egress_on_host_ip_box_rejects_ingress_mappings() {
        // Egress is accepted on a host-address box; ingress still requires an
        // own address, so a host-address record carrying both is rejected for
        // the ingress half, not for the egress it is now allowed to declare.
        let ingress = IngressPolicy {
            port_mappings: vec![PortMapping {
                external_port: 18080,
                internal_port: 80,
                proto: IpProto::Tcp,
            }],
            dynamic_allowed_range: None,
            dynamic_ingress: None,
        };
        let record = record_with(
            NetworkMode::HostNet,
            SessionPolicy::new(Some(EgressPolicy::default()), Some(ingress)),
        );
        assert_eq!(
            record.validate_policy(),
            Err(PolicyError::IngressRequiresOwnIp {
                mode: NetworkMode::HostNet
            })
        );
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
            dynamic_ingress: None,
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
                dynamic_ingress: None,
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
                dynamic_ingress: None,
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

    #[test]
    fn dynamic_ingress_setting_parses() {
        // NET-043: a box spec declaring `dynamic_ingress` allow, deny or ask
        // parses, and an unknown value is refused.
        for (json, expected) in [
            ("\"allow\"", DynamicIngress::Allow),
            ("\"deny\"", DynamicIngress::Deny),
            ("\"ask\"", DynamicIngress::Ask),
        ] {
            let parsed: DynamicIngress =
                serde_json_lenient::from_str(json).expect("{json} must parse to {expected:?}");
            assert_eq!(parsed, expected);
        }

        let err = serde_json_lenient::from_str::<DynamicIngress>("\"unknown\"").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown variant")
                && msg.contains("allow")
                && msg.contains("deny")
                && msg.contains("ask"),
            "unknown dynamic_ingress must name allowed variants: {msg}"
        );

        // A full ingress policy round-trips the setting.
        let ingress = IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: Some((8000, 8443)),
            dynamic_ingress: Some(DynamicIngress::Ask),
        };
        let json = serde_json_lenient::to_string(&ingress).unwrap();
        let rt: IngressPolicy = serde_json_lenient::from_str(&json).unwrap();
        assert_eq!(rt, ingress, "IngressPolicy must round-trip dynamic_ingress");

        // An ingress policy with only the new field is valid on an OwnIp PTask.
        let record = record_with(
            NetworkMode::OwnIp,
            SessionPolicy::new(None, Some(ingress.clone())),
        );
        assert!(
            record.validate_policy().is_ok(),
            "dynamic_ingress does not change validation"
        );

        // An explicit `deny` is the default and is treated like `None` for
        // the "ingress only on own-address" rule: it is accepted on a
        // host-address box and on a none box too (NET-065).
        let deny_ingress = IngressPolicy {
            port_mappings: vec![],
            dynamic_allowed_range: None,
            dynamic_ingress: Some(DynamicIngress::Deny),
        };
        for network in [NetworkMode::HostNet, NetworkMode::NoNet] {
            let record = record_with(
                network,
                SessionPolicy::new(None, Some(deny_ingress.clone())),
            );
            assert!(
                record.validate_policy().is_ok(),
                "dynamic_ingress = deny must be accepted on {network:?}"
            );
        }

        // A non-deny `dynamic_ingress` alone is still an ingress policy on a
        // non-own-address box and is refused there.
        for network in [NetworkMode::HostNet, NetworkMode::NoNet] {
            for mode in [DynamicIngress::Allow, DynamicIngress::Ask] {
                let ingest = IngressPolicy {
                    dynamic_ingress: Some(mode),
                    ..IngressPolicy::default()
                };
                let record = record_with(network, SessionPolicy::new(None, Some(ingest)));
                assert_eq!(
                    record.validate_policy(),
                    Err(PolicyError::DynamicIngressRequiresOwnIp { mode: network }),
                    "dynamic_ingress = {mode} must be rejected on {network:?}"
                );
            }
        }
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
