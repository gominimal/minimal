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
    /// A box spec spells it `mode = "none"`.
    #[serde(alias = "none")]
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

    /// The deny-all egress: an `allow_subnets` list with no entry in it, so no
    /// destination is declared and the box reaches nothing outside the resolver
    /// carve-out its verdict keeps. What the deny-all default gives a box with
    /// an address of its own that declared no `egress` section (NET-074).
    ///
    /// Distinct from an absent section, which is allow-all: the difference
    /// between the two is present-and-empty, not empty-or-missing.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            allow_subnets: Some(Vec::new()),
            ..Self::default()
        }
    }

    /// Whether this section declares no reachable destination at all — an
    /// `allow_subnets` list that is present and empty. What `min session policy`
    /// reads to name the box's posture `deny-all` (NET-075).
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.allow_subnets
            .as_deref()
            .is_some_and(<[String]>::is_empty)
    }
}

/// Where the deny-all default for an absent `egress` section stands in its
/// rollout.
///
/// The default is announced before it is in force: while it is only announced a
/// box with no `egress` section keeps the shipped allow-all of 03-spec R2.1 and
/// `min session activate` prints the coming change (NET-076); the release that
/// brings it into force is what makes [`InForce`](Self::InForce) the shipped
/// value of this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DenyAllWindow {
    /// Announced, not yet in force. The value this release ships.
    #[default]
    Announced,
    /// In force: an absent `egress` section on a box with an address of its own
    /// means deny-all (NET-074, NET-075), unless the opt-out flag is set.
    InForce,
}

/// Environment variable naming where the deny-all default's rollout window
/// stands: `in-force` brings it into force, anything else (including unset)
/// leaves it [announced](DenyAllWindow::Announced). Read by the daemon, which
/// applies the default, and by the CLI, which announces it, so both halves of
/// one host agree on the window they are in.
pub const DENY_ALL_WINDOW_VAR: &str = "MINIMAL_EGRESS_DENY_ALL_WINDOW";

/// Environment variable holding the deny-all opt-out flag (NET-077): set to
/// anything but `0` and a box with no `egress` section keeps the shipped
/// allow-all default even once the window is in force. A host-level flag rather
/// than a per-session one — the daemon decides what an absent section means, so
/// the box host is where the opt-out has to be legible.
pub const DENY_ALL_OPT_OUT_VAR: &str = "MINIMAL_EGRESS_DENY_ALL_OPT_OUT";

/// The deny-all default's state on this host: where its rollout window stands,
/// and whether the opt-out flag is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DenyAllDefault {
    /// Where the rollout window stands.
    pub window: DenyAllWindow,
    /// Whether the opt-out flag is set (NET-077).
    pub opted_out: bool,
}

/// Which rule decided a box's effective `egress` section, for the launch log
/// line and the policy a session's diagnostics dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPosture {
    /// The box declared an `egress` section; the default describes only what an
    /// absent one means, so a declaration is never touched.
    Declared,
    /// The box declared none and the deny-all default applied (NET-074).
    DenyAllDefault,
    /// The box declared none and keeps the shipped allow-all: the window is not
    /// in force, the opt-out flag is set, or the box has no address of its own.
    ShippedAllowAll,
}

/// A box's `egress` section once the deny-all default has had its say, and
/// which rule produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveEgress {
    /// The section the box launches under and its record carries: what it
    /// declared, the deny-all policy, or `None` for the shipped allow-all.
    pub policy: Option<EgressPolicy>,
    /// Which rule produced that section.
    pub posture: EgressPosture,
}

impl DenyAllDefault {
    /// The state these two values describe, as [`from_env`](Self::from_env)
    /// reads them from the environment. An unset or unrecognised window value
    /// is [`DenyAllWindow::Announced`], the shipped one, so a typo leaves a box
    /// with the reach it has today rather than silently taking it away; the
    /// opt-out is set by any value but `0` (an empty value counts as unset).
    #[must_use]
    pub fn from_values(window: Option<&str>, opt_out: Option<&str>) -> Self {
        Self {
            window: match window.map(str::trim) {
                Some("in-force") => DenyAllWindow::InForce,
                _ => DenyAllWindow::Announced,
            },
            opted_out: opt_out
                .map(str::trim)
                .is_some_and(|value| !value.is_empty() && value != "0"),
        }
    }

    /// The state this process's environment describes ([`DENY_ALL_WINDOW_VAR`]
    /// and [`DENY_ALL_OPT_OUT_VAR`]).
    #[must_use]
    pub fn from_env() -> Self {
        Self::from_values(
            std::env::var(DENY_ALL_WINDOW_VAR).ok().as_deref(),
            std::env::var(DENY_ALL_OPT_OUT_VAR).ok().as_deref(),
        )
    }

    /// The `egress` section a box in `mode` runs with, given the one it
    /// `declared`.
    ///
    /// A declared section comes back untouched. An absent one becomes deny-all
    /// only for a box with an address of its own, once the window is in force
    /// and the opt-out flag is not set (NET-074); every other combination keeps
    /// the shipped allow-all of 03-spec R2.1 (NET-077). A `none` box is left
    /// alone whatever the window: it has no network for a rule to describe, and
    /// [`Record::validate_policy`] refuses a section on one.
    #[must_use]
    pub fn effective_egress(
        self,
        mode: NetworkMode,
        declared: Option<EgressPolicy>,
    ) -> EffectiveEgress {
        if let Some(policy) = declared {
            return EffectiveEgress {
                policy: Some(policy),
                posture: EgressPosture::Declared,
            };
        }
        if mode == NetworkMode::OwnIp && self.window == DenyAllWindow::InForce && !self.opted_out {
            return EffectiveEgress {
                policy: Some(EgressPolicy::deny_all()),
                posture: EgressPosture::DenyAllDefault,
            };
        }
        EffectiveEgress {
            policy: None,
            posture: EgressPosture::ShippedAllowAll,
        }
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
    /// accepted; `None` leaves every unprivileged port to the box's
    /// [`dynamic_ingress`](SessionPolicy::dynamic_ingress) decision alone.
    ///
    /// Stored on the [`Record`] and returned verbatim by `GetSessionPolicy`.
    /// A set range is what the box permits beyond its declaration: it is read
    /// by [`crate::core::net_verdict::IngressRules::permits`], so a process in
    /// the box that begins listening on a port inside the range has that port
    /// published on the box's address (NET-016). It is also the bound a
    /// `min net expose <port>` request is checked against before the decision
    /// is consulted: a port outside it is refused whatever the decision says,
    /// and nothing is published for it (NET-047).
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

/// How a box answers a request, made at runtime from inside it, to publish
/// one of its ports: the `dynamic_ingress` setting a `min net expose <port>`
/// request is evaluated against (NET-043).
///
/// A box with no setting refuses every such request, the same fail-closed
/// default as its static ingress.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DynamicIngress {
    /// Publish the port, within the box's `dynamic_allowed_range` if one is
    /// set (NET-044).
    Allow,
    /// Refuse the request with a typed error (NET-044).
    Deny,
    /// Ask the attached human and apply their answer; refuse when nobody is
    /// attached to answer (NET-045).
    Ask,
}

impl fmt::Display for DynamicIngress {
    /// Renders the lowercase setting name, matching the `snake_case` serde
    /// representation so log fields agree with the config spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Ask => "ask",
        })
    }
}

/// The networking policy for a session: its egress and ingress configuration.
///
/// `None` for a dimension means it was not configured (allow-all egress; the
/// deny-all-external ingress default; every dynamic ingress request refused).
/// Stored on [`Record`] as the policy configured at launch and returned
/// verbatim by the `GetSessionPolicy` RPC.
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
    /// How a runtime request to publish a port is decided; `None` when the
    /// box declares nothing, which refuses every such request.
    pub dynamic_ingress: Option<DynamicIngress>,
}

impl SessionPolicy {
    /// Builds a policy from its egress and ingress halves, with no dynamic
    /// ingress setting.
    #[must_use]
    pub fn new(egress: Option<EgressPolicy>, ingress: Option<IngressPolicy>) -> Self {
        Self {
            egress,
            ingress,
            dynamic_ingress: None,
        }
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

// ---------------------------------------------------------------------------
// Box spec: the `[session.network]` table and the `[[session.grants]]` a
// project's `minimal.toml` declares, and the expansion that validates the
// GitHub grants against them on an un-enrolled host (box egress proxy spec:
// BEP-003, BEP-008, BEP-009, BEP-010, BEP-056). Like the policy types above,
// these are constructed by literal at the config sites, so they are not
// `#[non_exhaustive]`.
// ---------------------------------------------------------------------------

/// How a box's credentialed traffic reaches the Box Egress Proxy: the
/// `[session.network.bep] steering` field.
///
/// `Off` steers nothing: the box's requests go direct, no interception CA is
/// injected and a sealed value is never redeemed, so a grant declared under
/// it is honoured with a warning rather than refused.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Steering {
    /// The box-zone resolver answers the credentialed hostnames with the
    /// proxy's address.
    Dns,
    /// `HTTPS_PROXY`/`HTTP_PROXY` in the box environment point at the proxy.
    ProxyEnv,
    /// Both of the above.
    Both,
    /// Nothing is steered.
    Off,
}

impl Steering {
    /// The steering a box spec declaring a credentialed upstream and no
    /// `steering` resolves to (BEP-016). `dns` is the architecture's
    /// default, so a spec written today means the same thing once the
    /// box-zone resolver exists; until then an unadorned grant is refused
    /// naming the missing resolver (BEP-017).
    pub const DEFAULT: Self = Self::Dns;

    /// Whether this steering needs the host's box-zone resolver.
    #[must_use]
    pub fn steers_dns(self) -> bool {
        matches!(self, Self::Dns | Self::Both)
    }

    /// Whether this steering points `HTTPS_PROXY`/`HTTP_PROXY` at the proxy.
    #[must_use]
    pub fn steers_proxy_env(self) -> bool {
        matches!(self, Self::ProxyEnv | Self::Both)
    }
}

impl fmt::Display for Steering {
    /// Renders the `snake_case` spelling a box spec uses, so a refusal or a
    /// warning names the value as the operator wrote it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dns => "dns",
            Self::ProxyEnv => "proxy_env",
            Self::Both => "both",
            Self::Off => "off",
        })
    }
}

/// The `[session.network.bep]` table of a box spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct BepPolicy {
    /// The steering mode; `None` is resolved to the architecture's default
    /// when the box is created.
    pub steering: Option<Steering>,
    /// Set the proxy environment whatever the steering mode. Unbuildable
    /// together with `steering = "off"`, which also disables CA injection.
    #[serde(default)]
    pub proxy_env: bool,
    /// Hosts the proxy environment excludes, added to the local zone.
    #[serde(default)]
    pub no_proxy: Vec<String>,
}

impl BepPolicy {
    /// The steering a box declaring a credentialed upstream is created
    /// with: the declared value, else [`Steering::DEFAULT`] (BEP-016).
    #[must_use]
    pub fn resolved_steering(&self) -> Steering {
        self.steering.unwrap_or(Steering::DEFAULT)
    }
}

/// The proxy's address as a box under `proxy_env` steering reaches it: the
/// redemption listener's default bind, on the loopback a host-network box
/// shares with the host. An own-IP or VM-hosted box reaches the host at
/// another address; that addressing arrives with the listener's own-IP
/// attachment work and is not this constant's to guess.
///
/// The port mirrors `minvmd::net::DEFAULT_BEP_PORT`, which this crate cannot
/// import (`minvmd` depends on `sessions`, not the other way round); `minvmd`'s
/// `bep_default_listener_is_the_box_proxy_url` asserts the two agree.
pub const BEP_PROXY_URL: &str = "http://127.0.0.1:7656";

/// Where a box that stands on the switch reaches the proxy: the switch's
/// host-alias address, which gvproxy NATs to the loopback of the host it runs
/// on — the host where the proxy listens (`switch`'s rendered `nat` map).
///
/// The address is the default subnet's alias (`100.64.0.0/16` -> `.255.254`),
/// spelled here because this crate does not depend on `switch`. A host running
/// a non-default subnet needs the alias computed rather than assumed; that
/// arrives with the listener's own-IP attachment work, which is also what
/// gives such a box an attribution of its own.
pub const BEP_PROXY_URL_SWITCH: &str = "http://100.64.255.254:7656";

/// Where a box of `mode` reaches the proxy: its own loopback where it shares
/// the host's namespace, the switch's host alias where it does not.
///
/// `None` is the CLI's `--network` default, which is `host_net`.
#[must_use]
pub fn bep_proxy_url(mode: Option<NetworkMode>) -> &'static str {
    match mode {
        Some(NetworkMode::OwnIp) => BEP_PROXY_URL_SWITCH,
        _ => BEP_PROXY_URL,
    }
}

/// The local zone `NO_PROXY` always carries under `proxy_env` (BEP-012):
/// peer boxes by name, the host, and loopback, so local traffic never
/// detours through a credential proxy. The spec's `[network.bep] no_proxy`
/// entries follow these.
pub const BEP_NO_PROXY_LOCAL_ZONE: [&str; 4] = [
    ".min.internal",
    "host.min.internal",
    "localhost",
    "127.0.0.1",
];

/// Where the CLI delivers the host's interception anchor into the session
/// home, as a composition patch (relative to the sandbox home like every
/// patch destination), and where the daemon reads it back from at launch to
/// install it into the box trust store (BEP-011). The daemon holds no host
/// key material of its own — on macOS it runs inside a VM — so the anchor
/// rides the same upload the loadouts' files do.
pub const BEP_ANCHOR_PATCH_DEST: &str = ".local/share/minimal/bep/anchor.pem";

/// The box trust store directory, relative to the rootfs.
pub const BEP_TRUST_STORE_DIR: &str = "etc/ssl/certs";

/// Where the anchor is kept under [`BEP_TRUST_STORE_DIR`] in its own right:
/// what a tool pointed at one certificate is pointed at, and what a reader
/// checking whether a box was given an anchor looks for.
///
/// A file here under its own name is not itself trusted by anything. OpenSSL
/// finds an anchor in this directory only by its subject hash, and the tools
/// that matter — curl, git — read [`BEP_TRUST_BUNDLE_FILE`] instead. Trust
/// comes from being in that bundle.
pub const BEP_TRUST_STORE_FILE: &str = "minimal-bep-anchor.pem";

/// The certificate bundle under [`BEP_TRUST_STORE_DIR`] that OpenSSL-linked
/// tools actually read: the box's trust store as `curl`, `git` and every
/// OpenSSL default resolve it. An anchor is trusted by being appended to it.
pub const BEP_TRUST_BUNDLE_FILE: &str = "ca-certificates.crt";

/// The `[session.network]` table of a box spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct BoxNetwork {
    /// `mode = "none" | "host_net" | "own_ip"`. `None` leaves the mode to
    /// the CLI's `--network`.
    pub mode: Option<NetworkMode>,
    /// The `[session.network.egress]` table.
    pub egress: Option<EgressPolicy>,
    /// The `[session.network.bep]` table.
    #[serde(default)]
    pub bep: BepPolicy,
}

/// The upstream module a grant is for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantModule {
    /// GitHub, over the v1 host set [`GITHUB_HOST_SET`].
    Github,
}

impl fmt::Display for GrantModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Github => "github",
        })
    }
}

/// Where a grant's member comes from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    /// Minted from the held sign-in by the host's broker: `min` itself on an
    /// un-enrolled host, Gatehouse on an enrolled one. The grammar is the
    /// same on both sides of enrollment.
    Broker,
}

/// The kind of member a GitHub grant asks for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    /// A user token minted from the signed-in account's sign-in.
    #[default]
    User,
    /// An installation token, minted under the App's private key — which
    /// only an enrolled host holds.
    Installation,
}

impl fmt::Display for GrantMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::Installation => "installation",
        })
    }
}

/// One `[[session.grants]]` entry: a credential the box receives as a sealed
/// value in the named environment variable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The upstream module the member is for.
    pub module: GrantModule,
    /// The environment variable the box receives the sealed value in.
    pub env: crate::core::primitives::StrictVarName,
    /// Where the member comes from.
    pub source: GrantSource,
    /// The kind of member; `user` unless declared.
    #[serde(default)]
    pub mode: GrantMode,
    /// The scopes the grant asks for, as the box spec spells them
    /// ([`GITHUB_SCOPE_FULL`] for the `full` member this host mints,
    /// `github:repo:<owner>/<name>` for a narrower one). Declaring none
    /// takes the member as minted.
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl Grant {
    /// The declared scopes narrower than `full`, in declared order: empty
    /// when the grant declares nothing, or [`GITHUB_SCOPE_FULL`] alone
    /// (BEP-057).
    #[must_use]
    pub fn narrower_than_full(&self) -> Vec<String> {
        self.scopes
            .iter()
            .filter(|scope| scope.as_str() != GITHUB_SCOPE_FULL)
            .cloned()
            .collect()
    }
}

impl fmt::Display for Grant {
    /// "github grant `GITHUB_TOKEN`": how a refusal, a warning or a log line
    /// names the grant.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} grant `{}`", self.module, self.env)
    }
}

/// The scope a `full`-breadth GitHub member is declared as: the honest
/// spelling of what an un-enrolled host mints (BEP-005). Every other
/// spelling is narrower — `github:repo:<owner>/<name>` and any scope a later
/// version adds — and is read fail-closed, so an unknown spelling is never
/// taken for `full`.
pub const GITHUB_SCOPE_FULL: &str = "github:user-token";

/// The `[session.secrets]` table of a box spec.
///
/// The full-breadth acknowledgement is the operator's, held in the client
/// configuration, so a project that sets it here is ignored with a warning
/// (BEP-057): the scopes a project declares are honoured unchanged the moment
/// the host enrolls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct BoxSecrets {
    /// Set by a project asking for full-breadth minting. Ignored.
    pub acknowledge_full_breadth_unenrolled: Option<bool>,
}

/// The full-breadth acknowledgement in force for a box spec: the client
/// configuration's `[secrets] acknowledge_full_breadth_unenrolled`, and a
/// warning when the project's `[session.secrets]` sets it too (BEP-057).
///
/// Widening a declared scope is the operator's to accept, never the
/// project's to ask for, so the project's value is dropped rather than
/// merged.
#[must_use]
pub fn acknowledgement_in_force(
    client: bool,
    project: &BoxSecrets,
) -> (bool, Option<GrantWarning>) {
    let warning = project.acknowledge_full_breadth_unenrolled.map(|declared| {
        tracing::warn!(
            declared,
            in_force = client,
            "the project set `[session.secrets] acknowledge_full_breadth_unenrolled`; it is \
             ignored"
        );
        GrantWarning::ProjectAcknowledgement { declared }
    });
    (client, warning)
}

/// The GitHub module's v1 host set (Gatehouse §6.10, Module host sets): the
/// hosts a box declaring a GitHub grant must admit in its
/// `egress.allow_dns_hosts`.
pub const GITHUB_HOST_SET: [&str; 4] = [
    "github.com",
    "api.github.com",
    "uploads.github.com",
    "codeload.github.com",
];

/// The version of [`GITHUB_HOST_SET`] a member minted today binds to; the
/// proxy's module carries the same number, and a member minted under
/// another version is refused at redemption.
pub const GITHUB_HOST_SET_VERSION: u32 = 1;

/// What the grant validation runs against, beyond the spec itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrantContext<'a> {
    /// The box the spec is being expanded for, as the log lines name it.
    pub box_name: &'a str,
    /// The module's host set the grants are validated against.
    pub host_set: &'a [&'a str],
    /// Whether a GitHub sign-in is held on this host.
    pub sign_in_held: bool,
    /// Whether this host runs the box-zone resolver that `dns` steering
    /// needs to answer the credentialed hostnames with the proxy's address.
    pub resolver_present: bool,
    /// Whether the client configuration acknowledges full-breadth minting
    /// while the host is not enrolled: `[secrets]
    /// acknowledge_full_breadth_unenrolled` (BEP-057).
    pub full_breadth_acknowledged: bool,
}

/// The outcome of an admitted expansion: what the box is created with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantExpansion {
    /// The resolved steering: the spec's, else [`Steering::DEFAULT`] when a
    /// grant is declared (BEP-016). With no grant there is nothing to
    /// steer, and the spec's own value (or `off`) is reported as it stands.
    pub steering: Steering,
    /// Whether the host's interception root CA is injected into the box's
    /// trust store; `false` under `steering = "off"`.
    pub inject_ca: bool,
    /// Whether `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` are set in the box:
    /// `proxy_env` or `both` steering, or `[network.bep] proxy_env = true`
    /// (BEP-012).
    pub proxy_env: bool,
    /// What `NO_PROXY` carries when `proxy_env` is set: the local zone,
    /// then the spec's `no_proxy` entries, deduplicated in that order.
    pub no_proxy: Vec<String>,
    /// Validation warnings, one per grant declared under `steering = "off"`.
    pub warnings: Vec<GrantWarning>,
}

impl GrantExpansion {
    /// The proxy environment the box is created with (BEP-012): both proxy
    /// variables at [`BEP_PROXY_URL`] and `NO_PROXY` as a comma-joined
    /// list, or nothing when `proxy_env` is not set.
    #[must_use]
    pub fn proxy_env_vars(&self) -> Vec<(String, String)> {
        self.proxy_env_vars_at(BEP_PROXY_URL)
    }

    /// The proxy environment for a box that reaches the proxy at `url`
    /// ([`bep_proxy_url`]): both proxy variables at `url` and `NO_PROXY` as a
    /// comma-joined list, or nothing when `proxy_env` is not set.
    #[must_use]
    pub fn proxy_env_vars_at(&self, url: &str) -> Vec<(String, String)> {
        if !self.proxy_env {
            return Vec::new();
        }
        vec![
            ("HTTPS_PROXY".to_owned(), url.to_owned()),
            ("HTTP_PROXY".to_owned(), url.to_owned()),
            ("NO_PROXY".to_owned(), self.no_proxy.join(",")),
        ]
    }
}

/// The `NO_PROXY` list for a spec: [`BEP_NO_PROXY_LOCAL_ZONE`] followed by
/// the spec's own entries, each host once, in first-seen order.
fn no_proxy_list(bep: &BepPolicy) -> Vec<String> {
    let mut list: Vec<String> = Vec::new();
    for host in BEP_NO_PROXY_LOCAL_ZONE
        .iter()
        .copied()
        .chain(bep.no_proxy.iter().map(String::as_str))
    {
        if !list.iter().any(|seen| seen.eq_ignore_ascii_case(host)) {
            list.push(host.to_owned());
        }
    }
    list
}

/// A validation warning: the spec is honoured, and the operator is told what
/// that means.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantWarning {
    /// A grant under `steering = "off"`: nothing reaches the proxy, so the
    /// sealed value is delivered but never redeemed and no CA is injected.
    #[error(
        "{grant} is declared under `[session.network.bep] steering = \"off\"`: nothing is \
         steered to the proxy, so no interception CA is injected and the sealed value is \
         never redeemed"
    )]
    SteeringOff { grant: Grant },
    /// The project set the full-breadth acknowledgement. It is the
    /// operator's, held in the client configuration, so the project's value
    /// is ignored (BEP-057).
    #[error(
        "the project sets `[session.secrets] acknowledge_full_breadth_unenrolled = {declared}`, \
         which is ignored: the acknowledgement is the operator's, read from the user or \
         organization client configuration alone"
    )]
    ProjectAcknowledgement { declared: bool },
    /// The project supplied `[secret-store-rules]`. The rules bound what a
    /// referenced value may reach, which is the operator's to decide, so the
    /// project's rules are ignored (BEP-037).
    #[error(
        "the project sets `[secret-store-rules]` ({count} rule(s)), which is ignored: the rules \
         are the operator's, read from the user or organization client configuration alone"
    )]
    ProjectStoreRules { count: usize },
}

/// One reason an expansion is refused.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantRefusalCause {
    /// `network.mode = "none"` with a grant: a box with no network has
    /// nothing to reach with the credential.
    #[error("`[session.network] mode = \"none\"` gives {grant} no network to reach GitHub over")]
    NoneModeWithGrant { grant: Grant },
    /// `steering = "off"` with `proxy_env = true`: `off` injects no CA, so an
    /// environment pointing at the proxy would fail every TLS handshake.
    #[error(
        "`[session.network.bep] steering = \"off\"` and `proxy_env = true` cannot be built \
         together: `off` injects no interception CA, so an environment pointing at the proxy \
         would fail every TLS handshake"
    )]
    SteeringOffWithProxyEnv,
    /// `dns` or `both` steering on a host with no box-zone resolver: nothing
    /// would answer the credentialed hostnames with the proxy's address, so
    /// the box's requests would go direct with the sealed value in hand.
    #[error(
        "`[session.network.bep] steering = \"{steering}\"` needs the host's box-zone resolver \
         to answer the credentialed hostnames with the proxy's address, and this host has no \
         box-zone resolver; declare `steering = \"proxy_env\"` until it exists"
    )]
    NoBoxZoneResolver { steering: Steering },
    /// `mode = "installation"` on an un-enrolled host, which holds no App
    /// private key to mint one with.
    #[error(
        "{grant} declares `mode = \"installation\"`, which this host cannot mint: it is not \
         enrolled and holds no App private key"
    )]
    InstallationModeUnenrolled { grant: Grant },
    /// The grant declares scopes narrower than `full` and no acknowledgement
    /// is in force: un-enrolled, the member minted from the sign-in is
    /// `full` breadth, so honouring the declaration is impossible and
    /// widening it silently is refused (BEP-057).
    #[error(
        "{grant} declares scopes narrower than `full` ({}), and this host mints `full` members \
         only while it is not enrolled; set `[secrets] acknowledge_full_breadth_unenrolled = \
         true` in the user or organization client configuration to accept the widening",
        .narrower.join(", ")
    )]
    NarrowScopesUnacknowledged { grant: Grant, narrower: Vec<String> },
    /// The box's `egress.allow_dns_hosts` does not admit every host of the
    /// module's host set; `missing` names exactly the absent hosts.
    #[error(
        "{grant} needs `[session.network.egress] allow_dns_hosts` to admit every host of the \
         {} host set; missing: {}",
        .grant.module,
        .missing.join(", ")
    )]
    HostsOutsideEgress { grant: Grant, missing: Vec<String> },
    /// No GitHub sign-in is held: the defined error `github_sign_in_required`
    /// (BEP-003). The creation fails; nothing prompts for a sign-in.
    #[error(
        "github_sign_in_required: {grant} needs a held GitHub sign-in; run `min auth login` \
         first (the box was not created, and no sign-in was prompted for)"
    )]
    SignInRequired { grant: Grant },
    /// A store reference the client's `[secret-store-rules]` do not admit:
    /// no rule registers it, its rule denies it, or its rule asks and there
    /// is no terminal to ask at (BEP-035).
    #[error("{denial}")]
    ReferenceDenied { denial: ReferenceDenial },
    /// The box's `egress.allow_dns_hosts` does not admit every upstream the
    /// reference's rule registers; `missing` names exactly the absent hosts
    /// (BEP-036).
    #[error(
        "{reference} is registered for upstreams `[session.network.egress] allow_dns_hosts` does \
         not admit; missing: {}",
        .missing.join(", ")
    )]
    ReferenceUpstreamOutsideEgress {
        reference: StoreReference,
        missing: Vec<String>,
    },
}

/// A box spec whose GitHub grants the un-enrolled host cannot honour. The
/// expansion is refused with exit [`GrantRefusal::EXIT_CODE`], and the
/// message names every cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRefusal {
    /// Every cause found, in spec order; never empty.
    pub causes: Vec<GrantRefusalCause>,
}

impl GrantRefusal {
    /// The process exit code of a refused expansion.
    pub const EXIT_CODE: u8 = 3;
}

impl fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "refused the box spec's grants (exit {})",
            Self::EXIT_CODE
        )?;
        for cause in &self.causes {
            write!(f, "\n  - {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for GrantRefusal {}

/// Validates a box spec's grants against its `[session.network]` table and
/// the host, on an un-enrolled host.
///
/// Refused, with every cause named: a grant under `mode = "none"` (BEP-009),
/// `steering = "off"` together with `proxy_env = true` (BEP-010), a grant
/// asking for `mode = "installation"` (BEP-056), a grant declaring scopes
/// narrower than `full` with no acknowledgement in force (BEP-057), and a
/// grant whose module host set `egress.allow_dns_hosts` does not admit in
/// full — an absent `allow_dns_hosts` admits every host (BEP-008). A spec
/// that passes those is then refused with `github_sign_in_required` when no
/// sign-in is held (BEP-003). A grant under `steering = "off"` is admitted
/// with a warning, and the expansion injects no CA (BEP-010).
///
/// A spec declaring a grant and no `steering` resolves to
/// [`Steering::DEFAULT`] (BEP-016); a resolved `dns` or `both` on a host with
/// no box-zone resolver is refused naming the resolver (BEP-017). The
/// expansion says whether the proxy environment is set and what `NO_PROXY`
/// carries (BEP-012).
///
/// A spec with no grants is admitted as it stands, sign-in or not, and
/// delivers nothing: no CA, no proxy environment. A spec whose credentials are
/// store references rather than grants is expanded with
/// [`expand_for_references`], which steers it as this function steers a grant.
///
/// # Errors
///
/// [`GrantRefusal`], naming each cause.
pub fn validate_grants(
    network: &BoxNetwork,
    grants: &[Grant],
    ctx: &GrantContext<'_>,
) -> Result<GrantExpansion, GrantRefusal> {
    if grants.is_empty() {
        return Ok(GrantExpansion {
            steering: network.bep.steering.unwrap_or(Steering::Off),
            inject_ca: false,
            proxy_env: false,
            no_proxy: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let mut causes = Vec::new();
    let steering = resolve_steering(network, ctx.box_name, ctx.resolver_present, &mut causes);
    let steering_off = steering == Steering::Off;
    let mut warnings = Vec::new();
    for grant in grants {
        let before = causes.len();
        if network.mode == Some(NetworkMode::NoNet) {
            causes.push(GrantRefusalCause::NoneModeWithGrant {
                grant: grant.clone(),
            });
        }
        if grant.mode == GrantMode::Installation {
            causes.push(GrantRefusalCause::InstallationModeUnenrolled {
                grant: grant.clone(),
            });
        }
        let narrower = grant.narrower_than_full();
        if !narrower.is_empty() && !ctx.full_breadth_acknowledged {
            causes.push(GrantRefusalCause::NarrowScopesUnacknowledged {
                grant: grant.clone(),
                narrower,
            });
        }
        let missing = hosts_outside_egress(network.egress.as_ref(), ctx.host_set);
        if !missing.is_empty() {
            causes.push(GrantRefusalCause::HostsOutsideEgress {
                grant: grant.clone(),
                missing,
            });
        }
        let verdict = if causes.len() == before {
            "admitted"
        } else {
            "refused"
        };
        tracing::info!(
            box_name = ctx.box_name,
            grant = %grant,
            verdict,
            "validated a box spec grant"
        );
        if steering_off {
            tracing::warn!(
                box_name = ctx.box_name,
                grant = %grant,
                "grant declared under steering = \"off\": no CA injected, value never redeemed"
            );
            warnings.push(GrantWarning::SteeringOff {
                grant: grant.clone(),
            });
        }
    }
    if causes.is_empty() && !ctx.sign_in_held {
        causes.extend(
            grants
                .iter()
                .map(|grant| GrantRefusalCause::SignInRequired {
                    grant: grant.clone(),
                }),
        );
    }
    if !causes.is_empty() {
        return Err(GrantRefusal { causes });
    }
    Ok(steered_expansion(network, steering, warnings))
}

/// The steering the spec resolves to (BEP-016), and the causes that refuse it
/// for every box declaring a credentialed upstream: `steering = "off"`
/// together with `proxy_env = true` (BEP-010), and a resolved `dns` or `both`
/// on a host running no box-zone resolver (BEP-017). Causes are appended to
/// `causes`, so a caller collects them beside its own.
fn resolve_steering(
    network: &BoxNetwork,
    box_name: &str,
    resolver_present: bool,
    causes: &mut Vec<GrantRefusalCause>,
) -> Steering {
    let steering = network.bep.resolved_steering();
    if steering == Steering::Off && network.bep.proxy_env {
        causes.push(GrantRefusalCause::SteeringOffWithProxyEnv);
    }
    if steering.steers_dns() && !resolver_present {
        tracing::warn!(
            box_name,
            %steering,
            "steering needs the box-zone resolver, which this host does not run"
        );
        causes.push(GrantRefusalCause::NoBoxZoneResolver { steering });
    }
    steering
}

/// What an admitted credentialed box is delivered: the interception root in
/// its trust store unless steering is off (BEP-011), the proxy environment
/// when the steering or the spec's own `proxy_env` asks for it, and what
/// `NO_PROXY` carries (BEP-012).
fn steered_expansion(
    network: &BoxNetwork,
    steering: Steering,
    warnings: Vec<GrantWarning>,
) -> GrantExpansion {
    let proxy_env = steering.steers_proxy_env() || network.bep.proxy_env;
    GrantExpansion {
        steering,
        inject_ca: steering != Steering::Off,
        proxy_env,
        no_proxy: if proxy_env {
            no_proxy_list(&network.bep)
        } else {
            Vec::new()
        },
        warnings,
    }
}

/// Validates the `[session.network]` table of a box whose only credentials are
/// `[[session.references]]`.
///
/// A referenced value is redeemed at the proxy exactly as a grant's member is,
/// so a box declaring a reference declares a credentialed upstream: it is
/// steered (BEP-016), refused when that steering needs a resolver this host
/// does not run (BEP-017), given the interception root (BEP-011) and given the
/// proxy environment (BEP-012) on the same terms. [`validate_grants`] reports
/// "nothing to steer" for a spec with no grant, which is why a
/// reference-declaring spec is expanded through this function instead.
///
/// What each reference may reach, and whether it may be reached at all, is
/// [`validate_references`]'s to decide.
///
/// # Errors
///
/// [`GrantRefusal`], naming each cause.
pub fn expand_for_references(
    network: &BoxNetwork,
    box_name: &str,
    resolver_present: bool,
) -> Result<GrantExpansion, GrantRefusal> {
    let mut causes = Vec::new();
    let steering = resolve_steering(network, box_name, resolver_present, &mut causes);
    if causes.is_empty() {
        Ok(steered_expansion(network, steering, Vec::new()))
    } else {
        Err(GrantRefusal { causes })
    }
}

/// The hosts of `host_set` that `egress.allow_dns_hosts` does not admit, in
/// host-set order. An absent egress table or `allow_dns_hosts` admits every
/// host (the allow-all reading [`EgressPolicy`] documents). Hostnames compare
/// case-insensitively.
fn hosts_outside_egress(egress: Option<&EgressPolicy>, host_set: &[&str]) -> Vec<String> {
    let Some(allowed) = egress.and_then(|e| e.allow_dns_hosts.as_deref()) else {
        return Vec::new();
    };
    host_set
        .iter()
        .filter(|host| !allowed.iter().any(|a| a.eq_ignore_ascii_case(host)))
        .map(|host| (*host).to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Box spec: the `[[session.references]]` a project declares, and the
// client-owned `[secret-store-rules]` that register what each reference may
// reach and how its value is put on the wire (box egress proxy spec: BEP-034
// to BEP-037). A reference names a value the box never holds; the rules are
// the operator's, so a project that supplies them is ignored with a warning,
// exactly as the full-breadth acknowledgement is.
// ---------------------------------------------------------------------------

/// A store this host reads referenced secrets from.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretStore {
    /// The host's native store: the macOS Keychain here.
    Keychain,
}

impl fmt::Display for SecretStore {
    /// Renders the `snake_case` spelling a rule and a reference use, so a
    /// refusal names the store as the operator wrote it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Keychain => "keychain",
        })
    }
}

/// Where a `[[session.references]]` entry's value comes from: the entry's
/// `source` field, spelled out as a grant's is, so the grammar is unchanged
/// when a tenant-store deposit becomes a second value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceSource {
    /// A value held in one of this host's stores, named by identifier.
    Store,
}

/// One `[[session.references]]` entry: a stored value the box refers to by
/// identifier and never holds. The box receives a short-lived signed handle
/// in `env`; the proxy injects the value itself into the box's requests to
/// the upstream the operator's rule registers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreReference {
    /// The store the value is read from.
    pub store: SecretStore,
    /// The identifier the value is stored under.
    pub id: String,
    /// The environment variable the box receives the handle in.
    pub env: crate::core::primitives::StrictVarName,
    /// Where the value comes from.
    pub source: ReferenceSource,
}

impl fmt::Display for StoreReference {
    /// "keychain reference `anthropic-api-key`": how a refusal, a warning, a
    /// log line and `min box spec` name the reference.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} reference `{}`", self.store, self.id)
    }
}

/// What a rule does with a request matching it: the rule's `action`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Inject the value without asking. The action a rule that declares none
    /// carries.
    #[default]
    Allow,
    /// Ask the operator at the terminal first; with no terminal to ask at,
    /// the reference is denied rather than admitted unasked (BEP-035).
    Ask,
    /// Never inject the value.
    Deny,
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        })
    }
}

/// Which field of an HTTP basic-authentication credential a value fills.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BasicAuthField {
    /// The user field, what the upstream reads as the username.
    User,
    /// The password field.
    Password,
}

impl fmt::Display for BasicAuthField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::User => "user",
            Self::Password => "password",
        })
    }
}

/// How a registered value is put on the wire: the rule's `inject` table.
///
/// The proxy emits exactly the registered prefix followed by the value, or
/// fills one basic-authentication field with it; nothing else of the request
/// is rewritten.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "InjectionRepr", into = "InjectionRepr")]
pub enum Injection {
    /// `inject = { header = "x-api-key", prefix = "" }`: the prefix followed
    /// by the value, as the named header's whole value.
    Header {
        /// The header the value is written to.
        name: String,
        /// What precedes the value in the header's value.
        prefix: String,
    },
    /// `inject = { basic_auth = "password" }`: the value as one field of a
    /// basic-authentication credential.
    BasicAuth {
        /// The field the value fills.
        field: BasicAuthField,
    },
}

impl fmt::Display for Injection {
    /// "header `x-api-key`" / "`basic_auth` `password`": how a refusal and
    /// `min secret list` name the injection form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header { name, .. } => write!(f, "header `{name}`"),
            Self::BasicAuth { field } => write!(f, "basic_auth `{field}`"),
        }
    }
}

/// The on-disk shape of an [`Injection`].
///
/// A struct with `deny_unknown_fields` rather than an untagged enum, for the
/// reason [`crate::core::lifecyclehook::HookScript`]'s repr is one: a typo in
/// a security-relevant table must be an error, not a key skipped in silence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InjectionRepr {
    /// The header the value is written to, for the header form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// What precedes the value in that header; empty when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// The credential field the value fills, for the basic-auth form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuthField>,
}

/// Why an `inject` table is not one injection form.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InjectionError {
    /// Neither `header` nor `basic_auth` is declared, so nothing says where
    /// the value goes.
    #[error("an `inject` table declares neither `header` nor `basic_auth`")]
    NoForm,
    /// Both are declared: one value, one place.
    #[error(
        "an `inject` table declares both `header` and `basic_auth`; a value is injected in one \
         form"
    )]
    TwoForms,
    /// A `prefix` beside `basic_auth`, which carries no prefix.
    #[error(
        "an `inject` table declares `prefix` beside `basic_auth`; a prefix belongs to the header \
         form"
    )]
    PrefixWithoutHeader,
}

impl TryFrom<InjectionRepr> for Injection {
    type Error = InjectionError;

    fn try_from(repr: InjectionRepr) -> Result<Self, Self::Error> {
        match (repr.header, repr.basic_auth) {
            (Some(_), Some(_)) => Err(InjectionError::TwoForms),
            (None, None) => Err(InjectionError::NoForm),
            (Some(name), None) => Ok(Self::Header {
                name,
                prefix: repr.prefix.unwrap_or_default(),
            }),
            (None, Some(field)) if repr.prefix.is_none() => Ok(Self::BasicAuth { field }),
            (None, Some(_)) => Err(InjectionError::PrefixWithoutHeader),
        }
    }
}

impl From<Injection> for InjectionRepr {
    fn from(injection: Injection) -> Self {
        match injection {
            Injection::Header { name, prefix } => Self {
                header: Some(name),
                // Round-trip an undeclared prefix as undeclared.
                prefix: (!prefix.is_empty()).then_some(prefix),
                basic_auth: None,
            },
            Injection::BasicAuth { field } => Self {
                header: None,
                prefix: None,
                basic_auth: Some(field),
            },
        }
    }
}

/// One `[[secret-store-rules]]` rule of the client configuration: the stored
/// identifier it registers, the upstream authorities its value may be
/// injected into, how it is injected, and whether the operator is asked
/// first.
///
/// Client-owned by design: the rule is what bounds a reference, so a project
/// never supplies one (BEP-037).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StoreRule {
    /// The store holding the value.
    pub store: SecretStore,
    /// The identifier this rule registers.
    pub id: String,
    /// The authorities the value may be injected into, each `host` or
    /// `host:port`.
    pub upstream: Vec<String>,
    /// How the value is put on the wire.
    pub inject: Injection,
    /// Whether the value is injected outright, only after the operator is
    /// asked, or never. `allow` when omitted.
    #[serde(default)]
    pub action: RuleAction,
}

impl StoreRule {
    /// Whether this rule registers `reference`'s store and identifier.
    #[must_use]
    pub fn registers(&self, reference: &StoreReference) -> bool {
        self.store == reference.store && self.id == reference.id
    }

    /// The hosts of this rule's `upstream` authorities, each once, in
    /// declared order: what a box's `allow_dns_hosts` is read against, since
    /// it lists hostnames rather than authorities.
    #[must_use]
    pub fn upstream_hosts(&self) -> Vec<&str> {
        self.upstream
            .iter()
            .map(|authority| authority_host(authority))
            .fold(Vec::new(), |mut hosts, host| {
                if !hosts.iter().any(|seen| host.eq_ignore_ascii_case(seen)) {
                    hosts.push(host);
                }
                hosts
            })
    }
}

impl fmt::Display for StoreRule {
    /// "keychain rule `anthropic-api-key`": how a refusal and a log line
    /// name the rule.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} rule `{}`", self.store, self.id)
    }
}

/// The host part of an authority written `host` or `host:port`, for
/// comparison against `egress.allow_dns_hosts` and a module's host set,
/// which name hosts alone. A bracketed IPv6 literal loses its brackets:
/// `[::1]:443` is `::1`.
#[must_use]
pub fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
        .map_or(authority, |(host, _)| host)
}

/// The headers a `[secret-store-rules]` rule may not inject into (BEP-034):
/// the request's authority, the cookie jar, and the framing and hop-by-hop
/// headers, each of which would redirect or reframe the request the proxy
/// pinned rather than authenticate it. Compared case-insensitively; every
/// `Proxy-*` header is denied by [`INJECTION_HEADER_DENY_PREFIX`].
pub const INJECTION_HEADER_DENY_SET: [&str; 6] = [
    "host",
    ":authority",
    "cookie",
    "transfer-encoding",
    "connection",
    "upgrade",
];

/// The header-name prefix [`INJECTION_HEADER_DENY_SET`] denies as a family.
pub const INJECTION_HEADER_DENY_PREFIX: &str = "proxy-";

/// Whether `header` is one a rule may not inject into (BEP-034).
#[must_use]
pub fn is_denied_injection_header(header: &str) -> bool {
    let header = header.trim().to_ascii_lowercase();
    header.starts_with(INJECTION_HEADER_DENY_PREFIX)
        || INJECTION_HEADER_DENY_SET.contains(&header.as_str())
}

/// Whether `host` is Minimal's own infrastructure rather than an upstream
/// (BEP-034): the local zone a box never proxies
/// ([`BEP_NO_PROXY_LOCAL_ZONE`]) — peer boxes by name, the host itself, and
/// loopback. One list, so the hosts a rule may not register and the hosts
/// `NO_PROXY` carries cannot drift apart.
#[must_use]
pub fn is_minimal_infrastructure(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    BEP_NO_PROXY_LOCAL_ZONE.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        // A suffix entry (`.min.internal`) covers the apex and every name
        // under it; the others are hosts, matched whole.
        match entry.strip_prefix('.') {
            Some(apex) => host == apex || host.ends_with(entry.as_str()),
            None => host == entry,
        }
    })
}

/// Why a `[secret-store-rules]` rule is refused when the configuration is
/// read (BEP-034). The rule is never partly honoured: the configuration
/// fails to load, naming the rule and what it named.
///
/// The rule is boxed so the refusal stays small enough to return by value.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreRuleError {
    /// The rule registers a host of a configured module's host set, where
    /// the module's own sealed member governs the credential.
    #[error(
        "{rule} registers `{authority}`, a host of a configured module's host set: those hosts \
         carry the module's own sealed member, never a store value"
    )]
    ModuleHost {
        /// The refused rule.
        rule: Box<StoreRule>,
        /// The authority it registered, as the rule wrote it.
        authority: String,
    },
    /// The rule registers one of Minimal's own hostnames, which no upstream
    /// answers.
    #[error(
        "{rule} registers `{authority}`, which is Minimal's own infrastructure: a store value is \
         injected into upstream requests alone"
    )]
    MinimalInfrastructure {
        /// The refused rule.
        rule: Box<StoreRule>,
        /// The authority it registered, as the rule wrote it.
        authority: String,
    },
    /// The rule injects into a header that would redirect or reframe the
    /// request rather than authenticate it.
    #[error(
        "{rule} injects into the `{header}` header, which a rule may not name: it would redirect \
         or reframe the request the proxy pinned rather than authenticate it"
    )]
    DeniedHeader {
        /// The refused rule.
        rule: Box<StoreRule>,
        /// The header it named.
        header: String,
    },
}

/// Refuses a `[secret-store-rules]` rule that names a configured module's
/// host, Minimal's own infrastructure, or a denied injection header
/// (BEP-034).
///
/// `module_hosts` is the union of the configured modules' host sets — the
/// GitHub v1 set [`GITHUB_HOST_SET`] today. A module host is denied on every
/// port, since a store value has no business on it at all.
///
/// # Errors
///
/// [`StoreRuleError`], naming the rule and the host or header it named.
pub fn check_store_rule(rule: &StoreRule, module_hosts: &[&str]) -> Result<(), StoreRuleError> {
    let refusal = rule
        .upstream
        .iter()
        .find_map(|authority| {
            let host = authority_host(authority);
            if module_hosts.iter().any(|m| host.eq_ignore_ascii_case(m)) {
                Some(StoreRuleError::ModuleHost {
                    rule: Box::new(rule.clone()),
                    authority: authority.clone(),
                })
            } else if is_minimal_infrastructure(host) {
                Some(StoreRuleError::MinimalInfrastructure {
                    rule: Box::new(rule.clone()),
                    authority: authority.clone(),
                })
            } else {
                None
            }
        })
        .or_else(|| match &rule.inject {
            Injection::Header { name, .. } if is_denied_injection_header(name) => {
                Some(StoreRuleError::DeniedHeader {
                    rule: Box::new(rule.clone()),
                    header: name.clone(),
                })
            }
            _ => None,
        });
    tracing::info!(
        store = %rule.store,
        id = %rule.id,
        inject = %rule.inject,
        action = %rule.action,
        verdict = if refusal.is_some() { "refused" } else { "accepted" },
        "read a secret store rule"
    );
    refusal.map_or(Ok(()), Err)
}

/// The `[secret-store-rules]` in force for a box spec: the client
/// configuration's rules, and a warning when the project's `minimal.toml`
/// supplies the section too (BEP-037).
///
/// `project` is that section as the project's file carried it, never read as
/// configuration: what a rule permits is the operator's to decide, so the
/// project's rules are dropped rather than merged.
#[must_use]
pub fn store_rules_in_force<'r>(
    client: &'r [StoreRule],
    project: Option<&toml::Value>,
) -> (&'r [StoreRule], Option<GrantWarning>) {
    let warning = project.map(|section| {
        let count = section.as_array().map_or(1, Vec::len);
        tracing::warn!(
            count,
            in_force = client.len(),
            "the project set `[secret-store-rules]`; it is ignored"
        );
        GrantWarning::ProjectStoreRules { count }
    });
    (client, warning)
}

/// What the reference validation runs against, beyond the spec itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceContext<'a> {
    /// The box the spec is being expanded for, as the log lines name it.
    pub box_name: &'a str,
    /// Whether the client has a terminal to ask the operator at: a rule with
    /// `action = "ask"` denies the reference without one (BEP-035).
    pub has_tty: bool,
}

/// A store reference the client's rules admit: the rule in force for it, and
/// whether the operator is asked before its value is injected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedReference<'r> {
    /// The reference as the box spec declares it.
    pub reference: StoreReference,
    /// The rule that registers it: the authorities and the injection form
    /// the handle is minted for.
    pub rule: &'r StoreRule,
    /// Whether the operator is asked before the value is injected
    /// (`action = "ask"` with a terminal to ask at).
    pub prompt: bool,
}

/// Why a store reference is denied (BEP-035).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceDenial {
    /// No rule registers the reference's store and identifier, so nothing
    /// says what it may reach or how it is injected.
    #[error(
        "{reference} matches no `[secret-store-rules]` rule: register the identifier in the user \
         or organization client configuration before a box references it"
    )]
    NoRule {
        /// The denied reference.
        reference: StoreReference,
    },
    /// The rule registering it denies it.
    #[error("{reference} matches a `[secret-store-rules]` rule with `action = \"deny\"`")]
    RuleDenies {
        /// The denied reference.
        reference: StoreReference,
    },
    /// The rule asks, and this client has no terminal to ask at, so the
    /// reference is denied rather than admitted unasked.
    #[error(
        "{reference} matches a `[secret-store-rules]` rule with `action = \"ask\"`, and this \
         client has no terminal to ask at: run the command from a terminal, or set the rule's \
         `action` to `allow`"
    )]
    AskWithoutTty {
        /// The denied reference.
        reference: StoreReference,
    },
}

/// The rule in force for one store reference, and whether the operator is
/// asked before its value is injected.
///
/// A reference no rule registers is denied, as is one whose rule denies it,
/// and one whose rule asks while the client has no terminal to ask at
/// (BEP-035). The first rule registering the store and identifier decides.
///
/// # Errors
///
/// [`ReferenceDenial`], naming the reference and why it is denied.
pub fn decide_reference<'r>(
    reference: &StoreReference,
    rules: &'r [StoreRule],
    has_tty: bool,
) -> Result<AdmittedReference<'r>, ReferenceDenial> {
    let rule = rules
        .iter()
        .find(|rule| rule.registers(reference))
        .ok_or_else(|| ReferenceDenial::NoRule {
            reference: reference.clone(),
        })?;
    match rule.action {
        RuleAction::Deny => Err(ReferenceDenial::RuleDenies {
            reference: reference.clone(),
        }),
        RuleAction::Ask if !has_tty => Err(ReferenceDenial::AskWithoutTty {
            reference: reference.clone(),
        }),
        RuleAction::Ask | RuleAction::Allow => Ok(AdmittedReference {
            reference: reference.clone(),
            rule,
            prompt: rule.action == RuleAction::Ask,
        }),
    }
}

/// Validates a box spec's `[[session.references]]` against the client's
/// `[secret-store-rules]` and the box's own egress.
///
/// Refused, with every cause named: a reference the rules do not admit
/// (BEP-035), and a reference whose rule registers an upstream the box's
/// `egress.allow_dns_hosts` does not admit — naming exactly the absent hosts
/// (BEP-036). An absent `allow_dns_hosts` admits every host, the allow-all
/// reading [`EgressPolicy`] documents.
///
/// A spec with no reference is admitted as it stands.
///
/// # Errors
///
/// [`GrantRefusal`], naming each cause; refused with exit
/// [`GrantRefusal::EXIT_CODE`].
pub fn validate_references<'r>(
    network: &BoxNetwork,
    references: &[StoreReference],
    rules: &'r [StoreRule],
    ctx: &ReferenceContext<'_>,
) -> Result<Vec<AdmittedReference<'r>>, GrantRefusal> {
    let mut causes = Vec::new();
    let mut admitted = Vec::with_capacity(references.len());
    for reference in references {
        let verdict = match decide_reference(reference, rules, ctx.has_tty) {
            Err(denial) => {
                causes.push(GrantRefusalCause::ReferenceDenied { denial });
                "denied"
            }
            Ok(candidate) => {
                let missing =
                    hosts_outside_egress(network.egress.as_ref(), &candidate.rule.upstream_hosts());
                if missing.is_empty() {
                    admitted.push(candidate);
                    "admitted"
                } else {
                    causes.push(GrantRefusalCause::ReferenceUpstreamOutsideEgress {
                        reference: candidate.reference,
                        missing,
                    });
                    "refused"
                }
            }
        };
        tracing::info!(
            box_name = ctx.box_name,
            store = %reference.store,
            id = %reference.id,
            verdict,
            "validated a box spec store reference"
        );
    }
    if causes.is_empty() {
        Ok(admitted)
    } else {
        Err(GrantRefusal { causes })
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

    /// What an absent `egress` section means, across the rollout window and the
    /// opt-out flag: only a box with an address of its own, under a window in
    /// force with the flag unset, defaults to deny-all (NET-074). Every other
    /// cell keeps the shipped allow-all — while the default is merely announced
    /// (NET-076), whenever the flag is set (NET-077), and for a box that has no
    /// address of its own. A declared section is never touched by any of them.
    #[test]
    fn absent_egress_defaults_by_window_and_opt_out() {
        let announced = DenyAllDefault {
            window: DenyAllWindow::Announced,
            opted_out: false,
        };
        let in_force = DenyAllDefault {
            window: DenyAllWindow::InForce,
            opted_out: false,
        };

        // The one cell that takes the box's reach away.
        let effective = in_force.effective_egress(NetworkMode::OwnIp, None);
        assert_eq!(effective.posture, EgressPosture::DenyAllDefault);
        let egress = effective.policy.expect("the default declares a section");
        assert!(egress.is_deny_all(), "got {egress:?}");
        assert_eq!(egress.allow_subnets, Some(Vec::new()));
        // Deny-all by declaring no destination, not by denying every one: the
        // other three fields stay unset, so no rule is invented for the box.
        assert_eq!(egress.deny_subnets, None);
        assert_eq!(egress.allow_protocols, None);
        assert_eq!(egress.allow_dns_hosts, None);
        // The section it produces is a valid one for the mode it applies to.
        assert!(
            record_with(NetworkMode::OwnIp, SessionPolicy::new(Some(egress), None))
                .validate_policy()
                .is_ok()
        );

        // Every other cell keeps the shipped allow-all: an absent section.
        for (default, mode, why) in [
            (
                announced,
                NetworkMode::OwnIp,
                "the window is only announced",
            ),
            (
                DenyAllDefault {
                    window: DenyAllWindow::InForce,
                    opted_out: true,
                },
                NetworkMode::OwnIp,
                "the opt-out flag is set",
            ),
            (
                announced,
                NetworkMode::HostNet,
                "a host-address box is not in scope, announced",
            ),
            (
                in_force,
                NetworkMode::HostNet,
                "a host-address box is not in scope, in force",
            ),
            (in_force, NetworkMode::NoNet, "a none box has no network"),
        ] {
            let effective = default.effective_egress(mode, None);
            assert_eq!(
                effective,
                EffectiveEgress {
                    policy: None,
                    posture: EgressPosture::ShippedAllowAll,
                },
                "an absent section must keep the shipped allow-all when {why}"
            );
        }

        // A declared section is the box's own, in every cell: the default
        // describes what an absence means and nothing else.
        for default in [announced, in_force] {
            let effective = default.effective_egress(NetworkMode::OwnIp, Some(four_field_egress()));
            assert_eq!(effective.posture, EgressPosture::Declared);
            assert_eq!(effective.policy, Some(four_field_egress()));
        }

        // The two environment values the daemon and the CLI read them from:
        // only `in-force` moves the window, and any value but `0` opts out, so
        // a typo leaves a box the reach it has today.
        assert_eq!(DenyAllDefault::from_values(None, None), announced);
        assert_eq!(
            DenyAllDefault::from_values(Some("in-force"), None),
            in_force
        );
        assert_eq!(
            DenyAllDefault::from_values(Some("enforced"), None),
            announced
        );
        assert_eq!(
            DenyAllDefault::from_values(Some(" in-force "), None),
            in_force
        );
        for value in ["1", "true", "yes"] {
            assert!(
                DenyAllDefault::from_values(Some("in-force"), Some(value)).opted_out,
                "{value} must set the opt-out flag"
            );
        }
        for value in ["", "0"] {
            assert!(
                !DenyAllDefault::from_values(Some("in-force"), Some(value)).opted_out,
                "{value:?} must leave the opt-out flag unset"
            );
        }
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

    /// NET-043: the `dynamic_ingress` setting parses in its three spellings,
    /// is absent when the box declares nothing, and a spelling that names no
    /// decision is refused rather than read as one.
    #[test]
    fn dynamic_ingress_field_parses() {
        for (spelling, expected) in [
            ("allow", DynamicIngress::Allow),
            ("deny", DynamicIngress::Deny),
            ("ask", DynamicIngress::Ask),
        ] {
            let policy: SessionPolicy =
                serde_json_lenient::from_str(&format!(r#"{{"dynamic_ingress":"{spelling}"}}"#))
                    .unwrap_or_else(|e| panic!("dynamic_ingress = {spelling} must parse: {e}"));
            assert_eq!(policy.dynamic_ingress, Some(expected));
            assert_eq!(expected.to_string(), spelling);
            // The wire form round-trips through the same spelling.
            let json = serde_json_lenient::to_string(&policy).unwrap();
            assert!(
                json.contains(&format!(r#""dynamic_ingress":"{spelling}""#)),
                "{json}"
            );
        }

        let absent: SessionPolicy = serde_json_lenient::from_str(r#"{"egress":null}"#).unwrap();
        assert_eq!(absent.dynamic_ingress, None);
        assert_eq!(SessionPolicy::new(None, None).dynamic_ingress, None);

        assert!(
            serde_json_lenient::from_str::<SessionPolicy>(r#"{"dynamic_ingress":"maybe"}"#)
                .is_err(),
            "a spelling that names no decision must not parse"
        );
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

    // =================================================================
    // EgressPolicy property test (proptest)
    // =================================================================
    //
    // Enablement: the workspace's first property test, run under the
    // ordinary `cargo test`/`cargo nextest` recipe rather than a
    // separate lane, ahead of the redemption-decision property tests
    // the box egress proxy spec plans over this policy.

    mod egress_policy_property {
        use super::EgressPolicy;
        use proptest::prelude::*;

        /// Any syntactically well-formed IPv4 CIDR: four dotted octets and a
        /// prefix length in the valid 0..=32 range.
        fn arb_ipv4_cidr() -> impl Strategy<Value = String> {
            (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255, 0u8..=32u8)
                .prop_map(|(a, b, c, d, prefix)| format!("{a}.{b}.{c}.{d}/{prefix}"))
        }

        proptest! {
            #[test]
            fn egress_policy_property_check_runs(subnets in prop::collection::vec(arb_ipv4_cidr(), 0..8)) {
                let policy = EgressPolicy {
                    allow_subnets: Some(subnets),
                    ..EgressPolicy::default()
                };
                prop_assert_eq!(policy.first_invalid_subnet(), None);
            }
        }
    }

    // =================================================================
    // Box spec grants: expansion validation on an un-enrolled host
    // (BEP-003, BEP-008, BEP-009, BEP-010, BEP-056)
    // =================================================================

    mod grants {
        use super::super::*;
        use crate::core::primitives::StrictVarName;
        use proptest::prelude::*;

        fn grant(env: &str, mode: GrantMode) -> Grant {
            Grant {
                module: GrantModule::Github,
                env: StrictVarName::try_new(env).unwrap(),
                source: GrantSource::Broker,
                mode,
                scopes: Vec::new(),
            }
        }

        fn user_grant() -> Grant {
            grant("GITHUB_TOKEN", GrantMode::User)
        }

        /// A user grant declaring `scopes`.
        fn scoped_grant(env: &str, scopes: &[&str]) -> Grant {
            Grant {
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                ..grant(env, GrantMode::User)
            }
        }

        /// A spec every check admits: own-IP, the whole GitHub host set
        /// admitted, `proxy_env` steering.
        fn admitted_network() -> BoxNetwork {
            BoxNetwork {
                mode: Some(NetworkMode::OwnIp),
                egress: Some(EgressPolicy {
                    allow_dns_hosts: Some(
                        GITHUB_HOST_SET.iter().map(|h| (*h).to_owned()).collect(),
                    ),
                    ..EgressPolicy::default()
                }),
                bep: BepPolicy {
                    steering: Some(Steering::ProxyEnv),
                    ..BepPolicy::default()
                },
            }
        }

        /// The host as it is today: no box-zone resolver.
        fn ctx(sign_in_held: bool) -> GrantContext<'static> {
            GrantContext {
                box_name: "web",
                host_set: &GITHUB_HOST_SET,
                sign_in_held,
                resolver_present: false,
                full_breadth_acknowledged: false,
            }
        }

        /// The grammar the reference documents parses to these types:
        /// `[session.network]` with its `egress` and `bep` tables, and a
        /// `[[session.grants]]` entry with `mode` defaulting to `user`.
        #[test]
        fn box_spec_grammar_parses() {
            let network: BoxNetwork = toml::from_str(
                r#"
                mode = "none"
                [egress]
                allow_dns_hosts = ["github.com"]
                [bep]
                steering = "off"
                proxy_env = true
                no_proxy = ["release-assets.githubusercontent.com"]
                "#,
            )
            .unwrap();
            assert_eq!(network.mode, Some(NetworkMode::NoNet));
            assert_eq!(
                network.egress.unwrap().allow_dns_hosts,
                Some(vec!["github.com".to_owned()])
            );
            assert_eq!(network.bep.steering, Some(Steering::Off));
            assert!(network.bep.proxy_env);
            assert_eq!(network.bep.no_proxy.len(), 1);

            let parsed: Grant = toml::from_str(
                r#"
                module = "github"
                env = "GITHUB_TOKEN"
                source = "broker"
                "#,
            )
            .unwrap();
            assert_eq!(parsed, user_grant());
            assert_eq!(parsed.to_string(), "github grant `GITHUB_TOKEN`");
            assert!(parsed.narrower_than_full().is_empty());

            // `scopes` is what the grant asks for; `github:user-token` is the
            // spelling of the `full` member, so it is not narrower.
            let scoped: Grant = toml::from_str(
                r#"
                module = "github"
                env = "GITHUB_TOKEN"
                source = "broker"
                scopes = ["github:user-token", "github:repo:acme/web"]
                "#,
            )
            .unwrap();
            assert_eq!(
                scoped.narrower_than_full(),
                vec!["github:repo:acme/web".to_owned()]
            );

            let secrets: BoxSecrets =
                toml::from_str("acknowledge_full_breadth_unenrolled = true").unwrap();
            assert_eq!(secrets.acknowledge_full_breadth_unenrolled, Some(true));
            assert_eq!(
                BoxSecrets::default().acknowledge_full_breadth_unenrolled,
                None
            );

            // A typo in a security-relevant table is refused, not dropped.
            assert!(toml::from_str::<BepPolicy>("proxyenv = true").is_err());
            assert!(toml::from_str::<BoxSecrets>("acknowledge = true").is_err());
        }

        /// BEP-057: the acknowledgement a project's `[session.secrets]` sets
        /// is ignored — the client configuration's value is the one in force
        /// — and the operator is warned that it was dropped.
        #[test]
        fn project_acknowledgement_is_ignored_with_warning() {
            let asked = BoxSecrets {
                acknowledge_full_breadth_unenrolled: Some(true),
            };
            let (in_force, warning) = acknowledgement_in_force(false, &asked);
            assert!(!in_force, "a project cannot acknowledge the widening");
            let text = warning
                .expect("the dropped value is warned about")
                .to_string();
            assert!(
                text.contains("acknowledge_full_breadth_unenrolled"),
                "{text}"
            );
            assert!(text.contains("ignored"), "{text}");

            // The client's value stands on its own, and a project that says
            // nothing is not warned about.
            assert_eq!(
                acknowledgement_in_force(true, &BoxSecrets::default()),
                (true, None)
            );

            // A narrow grant is refused with the client's `false` however
            // loudly the project asks, and admitted once the client sets it.
            let grants = [scoped_grant("GITHUB_TOKEN", &["github:repo:acme/web"])];
            let context = GrantContext {
                full_breadth_acknowledged: in_force,
                ..ctx(true)
            };
            assert!(validate_grants(&admitted_network(), &grants, &context).is_err());
            let acknowledged = GrantContext {
                full_breadth_acknowledged: acknowledgement_in_force(true, &asked).0,
                ..ctx(true)
            };
            assert!(validate_grants(&admitted_network(), &grants, &acknowledged).is_ok());
        }

        /// BEP-003: with no sign-in held, a box declaring a GitHub grant
        /// fails with the defined error `github_sign_in_required` and
        /// nothing else; the same spec is admitted once a sign-in is held,
        /// and a spec with no grant never asks.
        #[test]
        fn creation_without_sign_in_fails_with_defined_error() {
            let network = admitted_network();
            let grants = [user_grant()];

            let refusal = validate_grants(&network, &grants, &ctx(false)).unwrap_err();
            assert_eq!(
                refusal.causes,
                vec![GrantRefusalCause::SignInRequired {
                    grant: user_grant()
                }]
            );
            assert!(refusal.to_string().contains("github_sign_in_required"));
            assert!(refusal.to_string().contains("github grant `GITHUB_TOKEN`"));
            assert_eq!(GrantRefusal::EXIT_CODE, 3);

            let expansion = validate_grants(&network, &grants, &ctx(true)).unwrap();
            assert!(expansion.inject_ca);
            assert!(expansion.warnings.is_empty());

            assert!(validate_grants(&network, &[], &ctx(false)).is_ok());
        }

        /// BEP-010: `steering = "off"` with a grant is admitted, with a
        /// warning naming the grant, and the box gets no interception CA.
        #[test]
        fn steering_off_with_grant_warns_and_injects_no_ca() {
            let mut network = admitted_network();
            network.bep.steering = Some(Steering::Off);

            let expansion = validate_grants(&network, &[user_grant()], &ctx(true)).unwrap();
            assert!(!expansion.inject_ca);
            assert_eq!(
                expansion.warnings,
                vec![GrantWarning::SteeringOff {
                    grant: user_grant()
                }]
            );
            assert!(
                expansion.warnings[0]
                    .to_string()
                    .contains("github grant `GITHUB_TOKEN`")
            );
        }

        /// BEP-010: `steering = "off"` and `proxy_env = true` is unbuildable
        /// and refused with exit 3 naming both fields.
        #[test]
        fn steering_off_with_proxy_env_is_refused() {
            let mut network = admitted_network();
            network.bep.steering = Some(Steering::Off);
            network.bep.proxy_env = true;

            let refusal = validate_grants(&network, &[user_grant()], &ctx(true)).unwrap_err();
            assert_eq!(
                refusal.causes,
                vec![GrantRefusalCause::SteeringOffWithProxyEnv]
            );
            let text = refusal.to_string();
            assert!(text.contains("steering = \"off\""), "{text}");
            assert!(text.contains("proxy_env = true"), "{text}");
            assert!(text.contains("exit 3"), "{text}");
        }

        /// BEP-016: a spec declaring a grant and no `steering` resolves to
        /// `dns`, and is created with the CA and no proxy environment once
        /// the resolver exists. `[network.bep] proxy_env = true` adds the
        /// proxy environment without changing the resolved steering; a
        /// declared steering is kept as written; and a spec with no grant
        /// has nothing to steer, so nothing is resolved for it.
        #[test]
        fn steering_defaults_to_dns() {
            let with_resolver = GrantContext {
                resolver_present: true,
                ..ctx(true)
            };
            let mut network = admitted_network();
            network.bep.steering = None;
            assert_eq!(network.bep.resolved_steering(), Steering::Dns);

            let expansion = validate_grants(&network, &[user_grant()], &with_resolver).unwrap();
            assert_eq!(expansion.steering, Steering::Dns);
            assert!(expansion.inject_ca);
            assert!(!expansion.proxy_env);
            assert!(expansion.no_proxy.is_empty());
            assert!(expansion.proxy_env_vars().is_empty());

            network.bep.proxy_env = true;
            network.bep.no_proxy = vec![
                "release-assets.githubusercontent.com".to_owned(),
                "LOCALHOST".to_owned(),
            ];
            let expansion = validate_grants(&network, &[user_grant()], &with_resolver).unwrap();
            assert_eq!(expansion.steering, Steering::Dns);
            assert!(expansion.proxy_env);
            // BEP-012: the local zone first, then the spec's entries, each
            // host once.
            assert_eq!(
                expansion.no_proxy,
                vec![
                    ".min.internal",
                    "host.min.internal",
                    "localhost",
                    "127.0.0.1",
                    "release-assets.githubusercontent.com",
                ]
            );
            assert_eq!(
                expansion.proxy_env_vars(),
                vec![
                    ("HTTPS_PROXY".to_owned(), BEP_PROXY_URL.to_owned()),
                    ("HTTP_PROXY".to_owned(), BEP_PROXY_URL.to_owned()),
                    (
                        "NO_PROXY".to_owned(),
                        ".min.internal,host.min.internal,localhost,127.0.0.1,\
                         release-assets.githubusercontent.com"
                            .to_owned()
                    ),
                ]
            );

            for declared in [Steering::ProxyEnv, Steering::Both, Steering::Dns] {
                network.bep.steering = Some(declared);
                network.bep.proxy_env = false;
                let expansion = validate_grants(&network, &[user_grant()], &with_resolver).unwrap();
                assert_eq!(expansion.steering, declared);
                assert_eq!(expansion.proxy_env, declared.steers_proxy_env());
            }

            // No grant: the spec's value is reported, none is resolved.
            network.bep.steering = None;
            let expansion = validate_grants(&network, &[], &ctx(false)).unwrap();
            assert_eq!(expansion.steering, Steering::Off);
            assert!(!expansion.inject_ca);
            assert!(!expansion.proxy_env);
        }

        proptest! {
            /// BEP-017: for every box spec declaring a credentialed upstream,
            /// on a host with no box-zone resolver, expansion refuses iff the
            /// resolved steering is `dns` or `both` — naming the resolver —
            /// and the same spec is admitted once the resolver is present.
            #[test]
            fn prop_dns_steering_without_resolver_is_exit_3(
                steering in prop_oneof![
                    Just(None),
                    Just(Some(Steering::Dns)),
                    Just(Some(Steering::ProxyEnv)),
                    Just(Some(Steering::Both)),
                    Just(Some(Steering::Off)),
                ],
                proxy_env in any::<bool>(),
                grant_count in 1usize..3,
            ) {
                let mut network = admitted_network();
                network.bep.steering = steering;
                // `off` with `proxy_env` is refused on its own (BEP-010) and
                // would muddy the property, so it is kept out of the space.
                network.bep.proxy_env = proxy_env && steering != Some(Steering::Off);
                let grants: Vec<Grant> = (0..grant_count)
                    .map(|i| grant(&format!("TOKEN_{i}"), GrantMode::User))
                    .collect();
                let resolved = steering.unwrap_or(Steering::Dns);

                let result = validate_grants(&network, &grants, &ctx(true));
                prop_assert_eq!(result.is_err(), resolved.steers_dns());
                match result {
                    Err(refusal) => {
                        prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                        let text = refusal.to_string();
                        prop_assert_eq!(
                            refusal.causes,
                            vec![GrantRefusalCause::NoBoxZoneResolver { steering: resolved }]
                        );
                        prop_assert!(text.contains("box-zone resolver"), "{}", text);
                        prop_assert!(text.contains(&format!("steering = \"{resolved}\"")), "{}", text);
                    }
                    Ok(expansion) => {
                        prop_assert_eq!(expansion.steering, resolved);
                    }
                }

                let with_resolver = GrantContext { resolver_present: true, ..ctx(true) };
                let expansion = validate_grants(&network, &grants, &with_resolver).unwrap();
                prop_assert_eq!(expansion.steering, resolved);
                prop_assert_eq!(expansion.inject_ca, resolved != Steering::Off);
                prop_assert_eq!(
                    expansion.proxy_env,
                    resolved.steers_proxy_env() || network.bep.proxy_env
                );
            }
        }

        /// A pool of hostnames a host set and an allow list are drawn from.
        const HOST_POOL: [&str; 6] = [
            "github.com",
            "api.github.com",
            "uploads.github.com",
            "codeload.github.com",
            "example.com",
            "objects.githubusercontent.com",
        ];

        fn arb_hosts(min: usize) -> impl Strategy<Value = Vec<&'static str>> {
            prop::collection::btree_set(0..HOST_POOL.len(), min..=HOST_POOL.len())
                .prop_map(|idx| idx.into_iter().map(|i| HOST_POOL[i]).collect())
        }

        proptest! {
            /// BEP-008: for every host set and every `allow_dns_hosts`,
            /// expansion refuses iff some host of the set is absent from
            /// the allow list, and the refusal names exactly the absent
            /// hosts. An absent `allow_dns_hosts` admits every host.
            #[test]
            fn prop_grant_host_set_outside_egress_is_exit_3(
                host_set in arb_hosts(1),
                allowed in prop::option::of(arb_hosts(0)),
                upper in any::<bool>(),
            ) {
                let mut network = admitted_network();
                network.egress = Some(EgressPolicy {
                    allow_dns_hosts: allowed.as_ref().map(|hosts| {
                        hosts
                            .iter()
                            .map(|h| if upper { h.to_ascii_uppercase() } else { (*h).to_owned() })
                            .collect()
                    }),
                    ..EgressPolicy::default()
                });
                let context = GrantContext { host_set: &host_set, ..ctx(true) };

                let expected_missing: Vec<String> = match &allowed {
                    None => Vec::new(),
                    Some(allowed) => host_set
                        .iter()
                        .filter(|h| !allowed.contains(*h))
                        .map(|h| (*h).to_owned())
                        .collect(),
                };

                let result = validate_grants(&network, &[user_grant()], &context);
                prop_assert_eq!(result.is_err(), !expected_missing.is_empty());
                if let Err(refusal) = result {
                    prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                    let text = refusal.to_string();
                    prop_assert_eq!(
                        refusal.causes,
                        vec![GrantRefusalCause::HostsOutsideEgress {
                            grant: user_grant(),
                            missing: expected_missing.clone(),
                        }]
                    );
                    for host in &expected_missing {
                        prop_assert!(text.contains(host.as_str()), "{}", text);
                    }
                }
            }

            /// BEP-009: for every box spec, expansion refuses iff
            /// `network.mode` is `none` and at least one grant is declared.
            #[test]
            fn prop_none_mode_with_grant_is_exit_3(
                mode in prop_oneof![
                    Just(None),
                    Just(Some(NetworkMode::NoNet)),
                    Just(Some(NetworkMode::HostNet)),
                    Just(Some(NetworkMode::OwnIp)),
                ],
                grant_count in 0usize..3,
            ) {
                let mut network = admitted_network();
                network.mode = mode;
                let grants: Vec<Grant> = (0..grant_count)
                    .map(|i| grant(&format!("TOKEN_{i}"), GrantMode::User))
                    .collect();

                let result = validate_grants(&network, &grants, &ctx(true));
                let none_with_grant = mode == Some(NetworkMode::NoNet) && grant_count > 0;
                prop_assert_eq!(result.is_err(), none_with_grant);
                if let Err(refusal) = result {
                    prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                    prop_assert!(refusal.to_string().contains("mode = \"none\""));
                    prop_assert_eq!(
                        refusal.causes,
                        grants
                            .iter()
                            .map(|g| GrantRefusalCause::NoneModeWithGrant { grant: g.clone() })
                            .collect::<Vec<_>>()
                    );
                }
            }

            /// BEP-056: on an un-enrolled host, expansion refuses iff a
            /// GitHub grant declares `mode = "installation"`, naming each
            /// such grant.
            #[test]
            fn prop_installation_mode_unenrolled_is_exit_3(
                modes in prop::collection::vec(
                    prop_oneof![Just(GrantMode::User), Just(GrantMode::Installation)],
                    1..4,
                ),
            ) {
                let network = admitted_network();
                let grants: Vec<Grant> = modes
                    .iter()
                    .enumerate()
                    .map(|(i, mode)| grant(&format!("TOKEN_{i}"), *mode))
                    .collect();

                let result = validate_grants(&network, &grants, &ctx(true));
                let any_installation = modes.contains(&GrantMode::Installation);
                prop_assert_eq!(result.is_err(), any_installation);
                if let Err(refusal) = result {
                    prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                    let expected: Vec<GrantRefusalCause> = grants
                        .iter()
                        .filter(|g| g.mode == GrantMode::Installation)
                        .map(|g| GrantRefusalCause::InstallationModeUnenrolled { grant: g.clone() })
                        .collect();
                    prop_assert!(refusal.to_string().contains("mode = \"installation\""));
                    prop_assert_eq!(refusal.causes, expected);
                }
            }

            /// BEP-057: on an un-enrolled host, expansion refuses iff some
            /// grant declares scopes narrower than `full` and the
            /// acknowledgement is unset — naming each such grant and the
            /// acknowledgement as the remedy. With it set, the same spec is
            /// admitted and the member minted is the `full` one.
            #[test]
            fn prop_narrow_scopes_unenrolled_need_acknowledgement(
                scope_sets in prop::collection::vec(arb_scopes(), 1..4),
                acknowledged in any::<bool>(),
            ) {
                let network = admitted_network();
                let grants: Vec<Grant> = scope_sets
                    .iter()
                    .enumerate()
                    .map(|(i, scopes)| {
                        let scopes: Vec<&str> = scopes.iter().map(String::as_str).collect();
                        scoped_grant(&format!("TOKEN_{i}"), &scopes)
                    })
                    .collect();
                let context = GrantContext {
                    full_breadth_acknowledged: acknowledged,
                    ..ctx(true)
                };

                let narrow: Vec<&Grant> = grants
                    .iter()
                    .filter(|g| !g.narrower_than_full().is_empty())
                    .collect();
                let result = validate_grants(&network, &grants, &context);
                prop_assert_eq!(result.is_err(), !narrow.is_empty() && !acknowledged);
                match result {
                    Err(refusal) => {
                        prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                        let text = refusal.to_string();
                        prop_assert_eq!(
                            refusal.causes,
                            narrow
                                .iter()
                                .map(|g| GrantRefusalCause::NarrowScopesUnacknowledged {
                                    grant: (*g).clone(),
                                    narrower: g.narrower_than_full(),
                                })
                                .collect::<Vec<_>>()
                        );
                        prop_assert!(
                            text.contains("acknowledge_full_breadth_unenrolled"),
                            "{}",
                            text
                        );
                        for grant in &narrow {
                            prop_assert!(text.contains(&grant.to_string()), "{}", text);
                            for scope in grant.narrower_than_full() {
                                prop_assert!(text.contains(&scope), "{}", text);
                            }
                        }
                    }
                    Ok(expansion) => {
                        prop_assert!(expansion.inject_ca);
                        prop_assert!(expansion.warnings.is_empty());
                    }
                }
            }
        }

        /// The scopes a grant is written with: the `full` spelling, narrower
        /// repository scopes, and a spelling this version does not know —
        /// which is read as narrower, never as `full`.
        const SCOPE_POOL: [&str; 4] = [
            GITHUB_SCOPE_FULL,
            "github:repo:acme/web",
            "github:repo:acme/*",
            "github:issues:read",
        ];

        fn arb_scopes() -> impl Strategy<Value = Vec<String>> {
            prop::collection::vec(0..SCOPE_POOL.len(), 0..3)
                .prop_map(|idx| idx.into_iter().map(|i| SCOPE_POOL[i].to_owned()).collect())
        }
    }

    // =================================================================
    // Box spec store references, validated against the client's
    // `[secret-store-rules]` (BEP-034, BEP-035, BEP-036, BEP-037)
    // =================================================================

    mod references {
        use super::super::*;
        use crate::core::primitives::StrictVarName;
        use proptest::prelude::*;

        /// A box spec's reference to a Keychain identifier.
        fn reference(id: &str) -> StoreReference {
            StoreReference {
                store: SecretStore::Keychain,
                id: id.to_owned(),
                env: StrictVarName::try_new("ANTHROPIC_API_KEY").unwrap(),
                source: ReferenceSource::Store,
            }
        }

        /// A rule registering `id` for `upstream`, injected into `x-api-key`.
        fn rule(id: &str, upstream: &[&str], action: RuleAction) -> StoreRule {
            StoreRule {
                store: SecretStore::Keychain,
                id: id.to_owned(),
                upstream: upstream.iter().map(|a| (*a).to_owned()).collect(),
                inject: Injection::Header {
                    name: "x-api-key".to_owned(),
                    prefix: String::new(),
                },
                action,
            }
        }

        /// A box admitting `hosts` and nothing else.
        fn network(hosts: &[&str]) -> BoxNetwork {
            BoxNetwork {
                mode: Some(NetworkMode::OwnIp),
                egress: Some(EgressPolicy {
                    allow_dns_hosts: Some(hosts.iter().map(|h| (*h).to_owned()).collect()),
                    ..EgressPolicy::default()
                }),
                bep: BepPolicy::default(),
            }
        }

        /// A client with a terminal to ask the operator at.
        fn ctx() -> ReferenceContext<'static> {
            ReferenceContext {
                box_name: "web",
                has_tty: true,
            }
        }

        /// The grammar the reference documents parses to these types: a
        /// `[[session.references]]` entry, and a `[[secret-store-rules]]`
        /// rule whose `inject` table names exactly one form.
        #[test]
        fn store_reference_grammar_parses() {
            let parsed: StoreReference = toml::from_str(
                r#"
                store  = "keychain"
                id     = "anthropic-api-key"
                env    = "ANTHROPIC_API_KEY"
                source = "store"
                "#,
            )
            .unwrap();
            assert_eq!(parsed, reference("anthropic-api-key"));
            assert_eq!(parsed.to_string(), "keychain reference `anthropic-api-key`");

            let parsed_rule: StoreRule = toml::from_str(
                r#"
                store    = "keychain"
                id       = "anthropic-api-key"
                upstream = ["api.anthropic.com:443"]
                inject   = { header = "x-api-key" }
                "#,
            )
            .unwrap();
            assert_eq!(
                parsed_rule,
                rule(
                    "anthropic-api-key",
                    &["api.anthropic.com:443"],
                    RuleAction::Allow
                )
            );
            assert_eq!(parsed_rule.action, RuleAction::Allow);
            assert_eq!(parsed_rule.to_string(), "keychain rule `anthropic-api-key`");
            assert_eq!(parsed_rule.inject.to_string(), "header `x-api-key`");

            // The basic-auth form carries no prefix; the header form's
            // prefix round-trips, and an omitted one stays omitted.
            let basic: Injection = toml::from_str("basic_auth = \"password\"").unwrap();
            assert_eq!(
                basic,
                Injection::BasicAuth {
                    field: BasicAuthField::Password
                }
            );
            assert_eq!(basic.to_string(), "basic_auth `password`");
            let bearer: Injection =
                toml::from_str("header = \"authorization\"\nprefix = \"Bearer \"").unwrap();
            for form in [&bearer, &basic] {
                let written = toml::to_string(form).unwrap();
                assert_eq!(&toml::from_str::<Injection>(&written).unwrap(), form);
            }
            // An undeclared prefix stays undeclared.
            let written = toml::to_string(&Injection::Header {
                name: "x-api-key".to_owned(),
                prefix: String::new(),
            })
            .unwrap();
            assert!(!written.contains("prefix"), "{written}");

            // One value, one place: both forms, neither, or a prefix beside
            // `basic_auth` is refused — and so is a typo, rather than the key
            // being dropped from a security-relevant table.
            for table in [
                "header = \"x-api-key\"\nbasic_auth = \"password\"",
                "",
                "basic_auth = \"password\"\nprefix = \"Bearer \"",
                "heder = \"x-api-key\"",
            ] {
                assert!(
                    toml::from_str::<Injection>(table).is_err(),
                    "`{table}` must be refused"
                );
            }
        }

        /// An authority is compared by its host: `allow_dns_hosts` and a
        /// module's host set both name hosts alone.
        #[test]
        fn authority_host_reads_the_host_alone() {
            assert_eq!(authority_host("api.anthropic.com:443"), "api.anthropic.com");
            assert_eq!(authority_host("api.anthropic.com"), "api.anthropic.com");
            assert_eq!(authority_host("[::1]:443"), "::1");
            // Not a port: the whole string is the host.
            assert_eq!(
                authority_host("api.example.com:http"),
                "api.example.com:http"
            );
            assert_eq!(
                rule(
                    "id",
                    &[
                        "api.example.com:443",
                        "API.EXAMPLE.COM",
                        "other.example.com"
                    ],
                    RuleAction::Allow
                )
                .upstream_hosts(),
                vec!["api.example.com", "other.example.com"]
            );
        }

        /// BEP-034: a rule naming a configured module's host, Minimal's own
        /// infrastructure, or a denied injection header is refused when the
        /// configuration is read, naming the rule and what it named.
        #[test]
        fn store_rule_in_deny_set_is_refused() {
            // A module host, on any port: the module's own sealed member
            // governs those hosts.
            for authority in [
                "api.github.com:443",
                "GITHUB.COM",
                "codeload.github.com:8443",
            ] {
                let refused = rule("anthropic-api-key", &[authority], RuleAction::Allow);
                let err = check_store_rule(&refused, &GITHUB_HOST_SET).unwrap_err();
                assert_eq!(
                    err,
                    StoreRuleError::ModuleHost {
                        rule: Box::new(refused),
                        authority: authority.to_owned(),
                    }
                );
                let text = err.to_string();
                assert!(text.contains("keychain rule `anthropic-api-key`"), "{text}");
                assert!(text.contains(authority), "{text}");
            }

            // Minimal's own infrastructure: peer boxes by name, the host,
            // and loopback.
            for authority in [
                "web.min.internal",
                "min.internal",
                "host.min.internal:7656",
                "localhost:7656",
                "127.0.0.1",
            ] {
                let refused = rule("anthropic-api-key", &[authority], RuleAction::Allow);
                let err = check_store_rule(&refused, &GITHUB_HOST_SET).unwrap_err();
                assert!(
                    matches!(err, StoreRuleError::MinimalInfrastructure { .. }),
                    "`{authority}` must be refused as Minimal's own: {err:?}"
                );
                assert!(err.to_string().contains(authority), "{err}");
            }

            // An injection header that would redirect or reframe the request
            // rather than authenticate it, in any casing, and every
            // `Proxy-*` header.
            for header in [
                "Host",
                ":authority",
                "Cookie",
                "Proxy-Authorization",
                "proxy-connection",
                "Transfer-Encoding",
                "connection",
                "Upgrade",
            ] {
                let refused = StoreRule {
                    inject: Injection::Header {
                        name: header.to_owned(),
                        prefix: String::new(),
                    },
                    ..rule(
                        "anthropic-api-key",
                        &["api.anthropic.com:443"],
                        RuleAction::Allow,
                    )
                };
                let err = check_store_rule(&refused, &GITHUB_HOST_SET).unwrap_err();
                assert_eq!(
                    err,
                    StoreRuleError::DeniedHeader {
                        rule: Box::new(refused),
                        header: header.to_owned(),
                    }
                );
                assert!(err.to_string().contains(header), "{err}");
            }

            // An ordinary rule is accepted, in either injection form.
            let allowed = rule(
                "anthropic-api-key",
                &["api.anthropic.com:443"],
                RuleAction::Allow,
            );
            assert_eq!(check_store_rule(&allowed, &GITHUB_HOST_SET), Ok(()));
            let basic = StoreRule {
                inject: Injection::BasicAuth {
                    field: BasicAuthField::Password,
                },
                ..allowed
            };
            assert_eq!(check_store_rule(&basic, &GITHUB_HOST_SET), Ok(()));
        }

        /// BEP-035: a reference matching an `ask` rule is denied when the
        /// client has no terminal to ask at, and admitted-with-a-prompt when
        /// it has one. A `deny` rule, and a reference no rule registers, are
        /// denied either way.
        #[test]
        fn ask_rule_without_tty_denies() {
            let rules = [rule(
                "anthropic-api-key",
                &["api.anthropic.com:443"],
                RuleAction::Ask,
            )];
            let declared = reference("anthropic-api-key");

            let admitted = decide_reference(&declared, &rules, true).unwrap();
            assert!(admitted.prompt, "a terminal is asked before the injection");
            assert_eq!(admitted.rule, &rules[0]);

            let denial = decide_reference(&declared, &rules, false).unwrap_err();
            assert_eq!(
                denial,
                ReferenceDenial::AskWithoutTty {
                    reference: declared.clone()
                }
            );
            let text = denial.to_string();
            assert!(
                text.contains("keychain reference `anthropic-api-key`"),
                "{text}"
            );
            assert!(text.contains("action = \"ask\""), "{text}");

            // The expansion carries the same denial, refused with exit 3.
            let refusal = validate_references(
                &network(&["api.anthropic.com"]),
                std::slice::from_ref(&declared),
                &rules,
                &ReferenceContext {
                    box_name: "web",
                    has_tty: false,
                },
            )
            .unwrap_err();
            assert_eq!(
                refusal.causes,
                vec![GrantRefusalCause::ReferenceDenied { denial }]
            );
            assert!(refusal.to_string().contains("exit 3"), "{refusal}");
            assert_eq!(GrantRefusal::EXIT_CODE, 3);

            // `deny`, and no rule at all, deny with a terminal too.
            let denying = [rule(
                "anthropic-api-key",
                &["api.anthropic.com"],
                RuleAction::Deny,
            )];
            assert_eq!(
                decide_reference(&declared, &denying, true).unwrap_err(),
                ReferenceDenial::RuleDenies {
                    reference: declared.clone()
                }
            );
            assert_eq!(
                decide_reference(&declared, &[], true).unwrap_err(),
                ReferenceDenial::NoRule {
                    reference: declared.clone()
                }
            );

            // `allow` needs no terminal and asks nothing.
            let allowing = [rule(
                "anthropic-api-key",
                &["api.anthropic.com"],
                RuleAction::Allow,
            )];
            assert!(
                !decide_reference(&declared, &allowing, false)
                    .unwrap()
                    .prompt
            );

            // A spec with no reference is admitted as it stands.
            assert_eq!(
                validate_references(&network(&[]), &[], &rules, &ctx()),
                Ok(Vec::new())
            );
        }

        /// BEP-037: the `[secret-store-rules]` a project's `minimal.toml`
        /// supplies are ignored — the client configuration's rules are the
        /// ones in force — and the operator is warned that they were
        /// dropped.
        #[test]
        fn project_store_rules_are_ignored_with_warning() {
            let client = [rule(
                "anthropic-api-key",
                &["api.anthropic.com:443"],
                RuleAction::Allow,
            )];
            // A project widening the same identifier to another upstream, in
            // another injection form.
            let project: toml::Value = toml::from_str(indoc::indoc! {r#"
                [[secret-store-rules]]
                store    = "keychain"
                id       = "anthropic-api-key"
                upstream = ["exfil.example.com"]
                inject   = { header = "authorization", prefix = "Bearer " }

                [[secret-store-rules]]
                store    = "keychain"
                id       = "registry-password"
                upstream = ["registry.example.com"]
                inject   = { basic_auth = "password" }
            "#})
            .unwrap();

            let (in_force, warning) =
                store_rules_in_force(&client, project.get("secret-store-rules"));
            assert_eq!(in_force, &client[..], "a project cannot register a rule");
            let text = warning
                .expect("the dropped section is warned about")
                .to_string();
            assert!(text.contains("[secret-store-rules]"), "{text}");
            assert!(text.contains("2 rule(s)"), "{text}");
            assert!(text.contains("ignored"), "{text}");

            // A project that says nothing is not warned about, and the
            // reference stays bounded by the operator's rule alone.
            assert_eq!(store_rules_in_force(&client, None), (&client[..], None));
            let admitted =
                decide_reference(&reference("anthropic-api-key"), in_force, true).unwrap();
            assert_eq!(admitted.rule.upstream_hosts(), vec!["api.anthropic.com"]);
            assert_eq!(
                admitted.rule.inject,
                Injection::Header {
                    name: "x-api-key".to_owned(),
                    prefix: String::new(),
                }
            );
            // The identifier the project alone registers is registered
            // nowhere.
            assert_eq!(
                decide_reference(&reference("registry-password"), in_force, true).unwrap_err(),
                ReferenceDenial::NoRule {
                    reference: reference("registry-password")
                }
            );
        }

        /// The upstreams a rule registers, drawn from hosts that are neither
        /// a module's nor Minimal's own — those are refused when the
        /// configuration is read (BEP-034), never here.
        const UPSTREAM_POOL: [&str; 5] = [
            "api.anthropic.com",
            "registry.example.com",
            "api.openai.example",
            "files.example.net",
            "mcp.example.org",
        ];

        fn arb_upstreams(min: usize) -> impl Strategy<Value = Vec<&'static str>> {
            prop::collection::btree_set(0..UPSTREAM_POOL.len(), min..=UPSTREAM_POOL.len())
                .prop_map(|idx| idx.into_iter().map(|i| UPSTREAM_POOL[i]).collect())
        }

        proptest! {
            /// BEP-036: for every registered upstream set and every
            /// `allow_dns_hosts`, expansion refuses with exit 3 iff some
            /// registered upstream is absent from the egress declaration,
            /// naming exactly the absent hosts. An absent `allow_dns_hosts`
            /// admits every host.
            #[test]
            fn prop_store_upstream_outside_egress_is_exit_3(
                upstream in arb_upstreams(1),
                allowed in prop::option::of(arb_upstreams(0)),
                port in prop::option::of(1u16..=65535),
                upper in any::<bool>(),
            ) {
                let rules = [StoreRule {
                    upstream: upstream
                        .iter()
                        .map(|host| port.map_or_else(
                            || (*host).to_owned(),
                            |port| format!("{host}:{port}"),
                        ))
                        .collect(),
                    ..rule("anthropic-api-key", &[], RuleAction::Allow)
                }];
                let declaring_box = BoxNetwork {
                    egress: Some(EgressPolicy {
                        allow_dns_hosts: allowed.as_ref().map(|hosts| hosts
                            .iter()
                            .map(|h| if upper { h.to_ascii_uppercase() } else { (*h).to_owned() })
                            .collect()),
                        ..EgressPolicy::default()
                    }),
                    ..network(&[])
                };
                let references = [reference("anthropic-api-key")];

                let expected_missing: Vec<String> = match &allowed {
                    None => Vec::new(),
                    Some(allowed) => upstream
                        .iter()
                        .filter(|host| !allowed.contains(*host))
                        .map(|host| (*host).to_owned())
                        .collect(),
                };

                let result = validate_references(&declaring_box, &references, &rules, &ctx());
                prop_assert_eq!(result.is_err(), !expected_missing.is_empty());
                match result {
                    Err(refusal) => {
                        prop_assert_eq!(GrantRefusal::EXIT_CODE, 3);
                        let text = refusal.to_string();
                        prop_assert_eq!(
                            refusal.causes,
                            vec![GrantRefusalCause::ReferenceUpstreamOutsideEgress {
                                reference: reference("anthropic-api-key"),
                                missing: expected_missing.clone(),
                            }]
                        );
                        prop_assert!(text.contains("exit 3"), "{}", text);
                        prop_assert!(
                            text.contains("keychain reference `anthropic-api-key`"),
                            "{}",
                            text
                        );
                        for host in &expected_missing {
                            prop_assert!(text.contains(host.as_str()), "{}", text);
                        }
                    }
                    Ok(admitted) => {
                        prop_assert_eq!(admitted.len(), 1);
                        prop_assert_eq!(admitted[0].rule, &rules[0]);
                        prop_assert!(!admitted[0].prompt);
                    }
                }
            }
        }

        /// BEP-011, BEP-012, BEP-017: a box whose only credential is a store
        /// reference is steered like a box declaring a grant — the proxy
        /// environment and the interception root, refused when the steering
        /// needs a resolver this host does not run — because the value it
        /// refers to is injected by the proxy its requests have to reach.
        #[test]
        fn a_reference_only_box_is_steered_like_a_credentialed_box() {
            let steered = |steering| BoxNetwork {
                bep: BepPolicy {
                    steering: Some(steering),
                    ..BepPolicy::default()
                },
                ..network(&["api.anthropic.com"])
            };

            let expansion = expand_for_references(&steered(Steering::ProxyEnv), "web", false)
                .expect("a proxy_env box needs no resolver");
            assert_eq!(expansion.steering, Steering::ProxyEnv);
            assert!(expansion.inject_ca, "{expansion:?}");
            assert!(expansion.proxy_env, "{expansion:?}");
            assert!(
                expansion
                    .proxy_env_vars()
                    .iter()
                    .any(|(name, value)| name == "HTTPS_PROXY" && value == BEP_PROXY_URL),
                "{expansion:?}"
            );

            // The same box with no grant declared delivers nothing, which is
            // why a reference-declaring spec is expanded through
            // `expand_for_references` rather than `validate_grants`.
            let nothing = validate_grants(
                &steered(Steering::ProxyEnv),
                &[],
                &GrantContext {
                    box_name: "web",
                    host_set: &GITHUB_HOST_SET,
                    sign_in_held: true,
                    resolver_present: false,
                    full_breadth_acknowledged: false,
                },
            )
            .expect("a spec with no grant is admitted as it stands");
            assert!(!nothing.proxy_env, "{nothing:?}");
            assert!(!nothing.inject_ca, "{nothing:?}");

            // The default steering is `dns`, which this host cannot serve.
            let refusal = expand_for_references(&network(&["api.anthropic.com"]), "web", false)
                .expect_err("dns steering with no resolver is refused");
            assert_eq!(
                refusal.causes,
                vec![GrantRefusalCause::NoBoxZoneResolver {
                    steering: Steering::DEFAULT
                }]
            );
            assert!(refusal.to_string().contains("exit 3"), "{refusal}");
        }
    }
}
