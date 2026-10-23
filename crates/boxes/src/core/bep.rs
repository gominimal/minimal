//! The Box Egress Proxy's box spec settings and the checks a box spec must
//! pass before a box with a credential grant is created.
//!
//! The settings are the `[network.bep]` table (`steering`, `proxy_env`,
//! `no_proxy`) and the `[secrets]` grants. The UDP 443 stance, [`Quic443`],
//! is a `[network]` setting, not a `[network.bep]` one. A project declares
//! them under its `[session]` table as `[session.network.bep]` and
//! `[session.secrets.<VAR>]`. They ride the box's policy inside
//! [`crate::CredentialedUpstream`].
//!
//! [`check_activation`] is pure apart from one debug log line per refusal.
//! It takes the module host set as an argument, so this crate does not
//! depend on the `bep` crate that owns the set.
//!
//! A grant is a GitHub grant when its `source` is `broker` and one of its
//! scopes starts with `github:` (for example `github:user-token`), as
//! [`SecretGrant::is_github`] decides. The grant's key is the environment
//! variable the sealed value lands in, and it is the name a message uses for
//! the grant.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{EgressPolicy, NetworkMode};

/// The exit code of a box spec that the activation refuses.
pub const REFUSAL_EXIT_CODE: u8 = 3;

/// The defined error of a box with a GitHub grant that is created while no
/// GitHub sign-in is held (BEP-003).
pub const GITHUB_SIGN_IN_REQUIRED: &str = "github_sign_in_required";

/// The defined error of a box with a GitHub grant that is created where no
/// node-local Box Egress Proxy serves boxes (Gatehouse §6.2).
pub const GATEHOUSE_UNENROLLED_NODE: &str = "gatehouse_unenrolled_node";

/// The exit code of a creation refused with [`GATEHOUSE_UNENROLLED_NODE`]
/// (spec 29 BOX-081).
pub const UNENROLLED_NODE_EXIT_CODE: u8 = 5;

/// How a box's credentialed traffic reaches the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Steering {
    /// The box-zone resolver answers a credentialed name with the proxy's
    /// address. The default (BEP-016).
    #[default]
    Dns,
    /// The box's `HTTPS_PROXY` and `HTTP_PROXY` point at the proxy.
    ProxyEnv,
    /// Both of the above.
    Both,
    /// Nothing is steered, and the box gets no interception CA.
    Off,
}

impl Steering {
    /// The word the box spec spells this mode with.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Steering::Dns => "dns",
            Steering::ProxyEnv => "proxy_env",
            Steering::Both => "both",
            Steering::Off => "off",
        }
    }

    /// Whether this mode needs the box-zone resolver.
    #[must_use]
    pub fn needs_resolver(self) -> bool {
        matches!(self, Steering::Dns | Steering::Both)
    }
}

/// The box's stance on UDP to port 443.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quic443 {
    /// Blocked when the box has a credentialed upstream under `dns` or
    /// `both` steering, and allowed otherwise.
    #[default]
    Auto,
    /// Always blocked.
    Block,
    /// Always allowed.
    Allow,
}

impl Quic443 {
    /// Whether the stance in effect blocks UDP to port 443. `block` always
    /// blocks and `allow` never does. `auto` blocks exactly when the box
    /// has a credentialed upstream and `steering` is `dns` or `both`
    /// (BEP-018).
    #[must_use]
    pub fn blocks(self, credentialed_upstream: bool, steering: Steering) -> bool {
        match self {
            Quic443::Block => true,
            Quic443::Allow => false,
            Quic443::Auto => credentialed_upstream && steering.needs_resolver(),
        }
    }
}

/// The `[network.bep]` table. Every field is optional, so an absent table
/// and an empty one read the same.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BepSettings {
    /// The declared steering mode. `None` resolves to [`Steering::Dns`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steering: Option<Steering>,
    /// Point the box's proxy environment at the proxy, whatever the
    /// steering mode.
    #[serde(default, skip_serializing_if = "is_false")]
    pub proxy_env: bool,
    /// Extra `NO_PROXY` entries.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub no_proxy: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's skip_serializing_if passes a reference
fn is_false(value: &bool) -> bool {
    !*value
}

impl BepSettings {
    /// The steering mode in effect: the declared one, or `dns` (BEP-016).
    #[must_use]
    pub fn resolved_steering(&self) -> Steering {
        self.steering.unwrap_or_default()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// Who a GitHub member acts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantMode {
    /// The signed-in GitHub account.
    #[default]
    User,
    /// A GitHub App installation. It needs the App's private key, which an
    /// un-enrolled host does not have.
    Installation,
}

/// Where a grant's value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    /// The credential broker. Only a broker grant makes a credentialed
    /// upstream.
    Broker,
    /// A copy of a variable from the client's environment. It makes no
    /// credentialed upstream.
    ClientEnv,
}

/// One `[secrets.<VAR>]` grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretGrant {
    /// Where the value comes from. Required: a grant with no source, or an
    /// unknown one, does not parse.
    pub source: GrantSource,
    /// The scopes the grant asks for, for example `github:user-token`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    /// The member's mode. `None` reads as [`GrantMode::User`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<GrantMode>,
}

impl SecretGrant {
    /// Whether this grant makes a credentialed upstream: its source is the
    /// broker.
    #[must_use]
    pub fn is_credentialed(&self) -> bool {
        self.source == GrantSource::Broker
    }

    /// Whether this grant is a GitHub grant: a broker grant with a
    /// `github:` scope.
    #[must_use]
    pub fn is_github(&self) -> bool {
        self.is_credentialed() && self.scopes.iter().any(|scope| scope.starts_with("github:"))
    }

    /// The `github:repo:*` scopes narrower than `full`: every one but
    /// `github:repo:full`. An un-enrolled host cannot narrow a member, so
    /// it mints such a grant `full` (BEP-057).
    #[must_use]
    pub fn narrow_scopes(&self) -> Vec<&str> {
        self.scopes
            .iter()
            .map(String::as_str)
            .filter(|scope| {
                scope
                    .strip_prefix("github:repo:")
                    .is_some_and(|rest| rest != "full")
            })
            .collect()
    }

    /// Whether this is a GitHub grant that declares a scope narrower than
    /// `full`.
    #[must_use]
    pub fn is_narrower_than_full(&self) -> bool {
        self.is_github() && !self.narrow_scopes().is_empty()
    }
}

/// The client configuration key that accepts a `full` member for a grant
/// that declares narrower scopes on an un-enrolled host (BEP-057). It is
/// read from the user and organization `config.toml` `[secrets]` table,
/// never from a project.
pub const FULL_BREADTH_ACKNOWLEDGEMENT: &str = "acknowledge_full_breadth_unenrolled";

/// A project's `[session.secrets]` table as a project file declares it.
/// A project cannot set [`FULL_BREADTH_ACKNOWLEDGEMENT`]: the reader drops
/// that key and records that it did, so the caller can warn.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectSecrets {
    /// The grants, by the environment variable each one lands in.
    pub grants: SecretGrants,
    /// Whether the table set the acknowledgement, which was ignored.
    pub acknowledgement_ignored: bool,
}

/// The warning for a project that sets the acknowledgement.
pub const PROJECT_ACKNOWLEDGEMENT_IGNORED: &str = "minimal.toml sets \
     acknowledge_full_breadth_unenrolled in [session.secrets]. A project cannot set it, \
     so it is ignored. Set it in [secrets] in your own config.toml instead. \
     Run `min dirs` to find that file.";

impl<'de> Deserialize<'de> for ProjectSecrets {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ProjectSecrets;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a table of secret grants")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = ProjectSecrets::default();
                while let Some(key) = map.next_key::<String>()? {
                    if key == FULL_BREADTH_ACKNOWLEDGEMENT {
                        map.next_value::<serde::de::IgnoredAny>()?;
                        out.acknowledgement_ignored = true;
                    } else {
                        let grant = map.next_value::<SecretGrant>()?;
                        out.grants.insert(key, grant);
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

/// Reads a project's `[session.secrets]` table for `serde(deserialize_with)`.
/// It ignores the full-breadth acknowledgement with a warning, because only
/// the client configuration can set it (BEP-057).
///
/// # Errors
///
/// The deserializer's error when a grant does not parse.
pub fn deserialize_project_secrets<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SecretGrants, D::Error> {
    let secrets = ProjectSecrets::deserialize(deserializer)?;
    if secrets.acknowledgement_ignored {
        tracing::warn!("{PROJECT_ACKNOWLEDGEMENT_IGNORED}");
    }
    Ok(secrets.grants)
}

/// The `[secrets]` table: grants by the environment variable that carries
/// each one in the box.
pub type SecretGrants = BTreeMap<String, SecretGrant>;

/// What the activation knows about this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFacts {
    /// Whether the host is enrolled with a Gatehouse.
    pub enrolled: bool,
    /// Whether the host runs a box-zone resolver.
    pub box_zone_resolver: bool,
    /// Whether the client configuration sets
    /// [`FULL_BREADTH_ACKNOWLEDGEMENT`]. It matters only un-enrolled.
    pub full_breadth_acknowledged: bool,
}

impl HostFacts {
    /// An un-enrolled host with no box-zone resolver and no acknowledgement.
    pub const LOCAL: Self = Self {
        enrolled: false,
        box_zone_resolver: false,
        full_breadth_acknowledged: false,
    };
}

/// The parts of a box spec the checks read.
#[derive(Debug, Clone, Copy)]
pub struct ActivationSpec<'a> {
    /// The box's network mode.
    pub network: NetworkMode,
    /// The box's declared egress, if any. `None` admits no name.
    pub egress: Option<&'a EgressPolicy>,
    /// The proxy settings.
    pub bep: &'a BepSettings,
    /// The grants.
    pub secrets: &'a SecretGrants,
}

impl ActivationSpec<'_> {
    /// Whether the spec declares a credentialed upstream: at least one
    /// broker grant. A `client_env` grant makes none.
    #[must_use]
    pub fn has_credentialed_upstream(&self) -> bool {
        self.secrets.values().any(SecretGrant::is_credentialed)
    }

    fn github_grants(&self) -> impl Iterator<Item = &str> {
        self.secrets
            .iter()
            .filter(|(_, grant)| grant.is_github())
            .map(|(name, _)| name.as_str())
    }
}

/// One reason the activation refuses a box spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BepRefusal {
    /// BEP-008: the egress does not admit these hosts of the GitHub set.
    HostsOutsideEgress {
        /// The absent hosts, in the module's order.
        missing: Vec<String>,
    },
    /// BEP-009: network mode `none` with a grant.
    NoNetworkWithGrant {
        /// The grants, in name order.
        grants: Vec<String>,
    },
    /// BEP-010: `steering = "off"` with `proxy_env = true`.
    SteeringOffWithProxyEnv,
    /// BEP-017: `dns` or `both` steering with no box-zone resolver.
    NoResolver {
        /// The resolved steering mode.
        steering: Steering,
    },
    /// BEP-056: an `installation` grant on an un-enrolled host.
    InstallationUnenrolled {
        /// The grant's name.
        grant: String,
    },
    /// BEP-057: a grant narrower than `full` on an un-enrolled host with no
    /// acknowledgement.
    NarrowScopesUnenrolled {
        /// The grant's name.
        grant: String,
        /// The narrower scopes it declares.
        scopes: Vec<String>,
    },
    /// BEP-003: a GitHub grant while no GitHub sign-in is held. Its defined
    /// error is [`GITHUB_SIGN_IN_REQUIRED`].
    SignInRequired {
        /// The GitHub grants, in name order.
        grants: Vec<String>,
    },
    /// Gatehouse §6.2: a GitHub grant where no node-local proxy serves
    /// boxes. Its defined error is [`GATEHOUSE_UNENROLLED_NODE`].
    UnenrolledNode {
        /// The GitHub grants, in name order.
        grants: Vec<String>,
    },
}

impl BepRefusal {
    /// The requirement the refusal enforces, for the log line only.
    #[must_use]
    pub fn rule(&self) -> &'static str {
        match self {
            Self::HostsOutsideEgress { .. } => "BEP-008",
            Self::NoNetworkWithGrant { .. } => "BEP-009",
            Self::SteeringOffWithProxyEnv => "BEP-010",
            Self::NoResolver { .. } => "BEP-017",
            Self::InstallationUnenrolled { .. } => "BEP-056",
            Self::NarrowScopesUnenrolled { .. } => "BEP-057",
            Self::SignInRequired { .. } | Self::UnenrolledNode { .. } => "BEP-003",
        }
    }

    /// The refusal's defined error, for a refusal that has one.
    #[must_use]
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::SignInRequired { .. } => Some(GITHUB_SIGN_IN_REQUIRED),
            Self::UnenrolledNode { .. } => Some(GATEHOUSE_UNENROLLED_NODE),
            _ => None,
        }
    }

    /// The spec fields the refusal is about, for the log line only.
    #[must_use]
    pub fn fields(&self) -> &'static str {
        match self {
            Self::HostsOutsideEgress { .. } => "secrets, egress.allow_dns_hosts",
            Self::NoNetworkWithGrant { .. } => "secrets, network.mode",
            Self::SteeringOffWithProxyEnv => "network.bep.steering, network.bep.proxy_env",
            Self::NoResolver { .. } => "secrets, network.bep.steering",
            Self::InstallationUnenrolled { .. } => "secrets.mode",
            Self::NarrowScopesUnenrolled { .. } => {
                "secrets.scopes, config [secrets] acknowledge_full_breadth_unenrolled"
            }
            Self::SignInRequired { .. } | Self::UnenrolledNode { .. } => "secrets",
        }
    }
}

impl fmt::Display for BepRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The task fixes this wording.
            Self::HostsOutsideEgress { missing } => write!(
                f,
                "This box declares a GitHub grant, but its egress does not allow: {}. \
                 Add them to egress.allow_dns_hosts.",
                missing.join(", ")
            ),
            Self::NoNetworkWithGrant { grants } => write!(
                f,
                "This box declares the secret {} but has no network, so the secret \
                 cannot reach anything. Use --network own_ip, or remove the secret.",
                grants.join(", ")
            ),
            Self::SteeringOffWithProxyEnv => write!(
                f,
                "This box sets steering = \"off\" and proxy_env = true in [network.bep]. \
                 With steering off the box does not trust the proxy, so every HTTPS \
                 request through the proxy fails. Remove proxy_env, or set \
                 steering = \"proxy_env\"."
            ),
            Self::NoResolver { steering } => write!(
                f,
                "This box declares a secret with steering = \"{}\", but this host has no \
                 box DNS resolver. Set steering = \"proxy_env\" in [network.bep].",
                steering.word()
            ),
            Self::InstallationUnenrolled { grant } => write!(
                f,
                "The GitHub secret {grant} sets mode = \"installation\", but this host is \
                 not enrolled, so it cannot act as a GitHub App installation. \
                 Set mode = \"user\"."
            ),
            Self::NarrowScopesUnenrolled { grant, scopes } => write!(
                f,
                "The GitHub secret {grant} asks for {}, but this host is not enrolled, \
                 so it cannot limit the secret to those scopes. The secret will reach every \
                 repository your GitHub sign-in reaches. To accept this, set \
                 acknowledge_full_breadth_unenrolled = true in [secrets] in your \
                 config.toml. Run `min dirs` to find that file.",
                scopes.join(", ")
            ),
            // The task fixes this wording.
            Self::SignInRequired { .. } => write!(
                f,
                "This box declares a GitHub grant, and no GitHub sign-in is held on this \
                 machine. Run `min auth login`, then create the box again."
            ),
            Self::UnenrolledNode { grants } => write!(
                f,
                "Cannot create the box: it declares the GitHub grant {}, and no Box Egress \
                 Proxy serves boxes on this machine. Remove the grant from the [secrets] table \
                 in minimal.toml, then create the box again.",
                grants.join(", ")
            ),
        }
    }
}

/// The activation refused the box spec. It carries every reason, so one
/// run names everything to fix. It exits [`REFUSAL_EXIT_CODE`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationRefused {
    /// The reasons, in a fixed order. Never empty.
    pub refusals: Vec<BepRefusal>,
}

impl ActivationRefused {
    /// The exit code the run ends with.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self
            .refusals
            .iter()
            .any(|refusal| matches!(refusal, BepRefusal::UnenrolledNode { .. }))
        {
            UNENROLLED_NODE_EXIT_CODE
        } else {
            REFUSAL_EXIT_CODE
        }
    }
}

impl fmt::Display for ActivationRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, refusal) in self.refusals.iter().enumerate() {
            if i > 0 {
                f.write_str("\n")?;
            }
            write!(f, "{refusal}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ActivationRefused {}

/// A box spec the activation accepts but warns about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BepWarning {
    /// BEP-010: `steering = "off"` with a GitHub grant.
    SteeringOffWithGrant {
        /// The GitHub grants, in name order.
        grants: Vec<String>,
    },
    /// BEP-011: the box spec's environment sets a trust variable that the
    /// box would get from its trust store, so the spec's value stays.
    TrustEnvSetBySpec {
        /// The variable the spec sets.
        variable: String,
    },
}

/// The trust variables a box with the proxy's root gets (BEP-011): the
/// first two at the box's CA bundle, the last at the root alone.
pub const TRUST_ENV_VARIABLES: [&str; 3] =
    ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"];

impl fmt::Display for BepWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SteeringOffWithGrant { grants } => write!(
                f,
                "steering is \"off\", so this box does not trust the proxy. \
                 The GitHub secret {} will not work in it.",
                grants.join(", ")
            ),
            Self::TrustEnvSetBySpec { variable } => write!(
                f,
                "This box sets {variable} itself, so tools that read it will not \
                 trust the proxy's certificate."
            ),
        }
    }
}

/// What the activation does for an accepted box spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationPlan {
    /// The steering mode in effect.
    pub steering: Steering,
    /// Whether the box gets the interception CA in its trust store.
    pub inject_ca: bool,
    /// The warnings to print.
    pub warnings: Vec<BepWarning>,
}

/// Every reason to refuse `spec` on a host with `host` facts, in a fixed
/// order. `module_hosts` is the GitHub module's host set. Empty when the
/// spec passes.
#[must_use]
pub fn refusals(
    spec: &ActivationSpec<'_>,
    host: HostFacts,
    module_hosts: &[&str],
) -> Vec<BepRefusal> {
    let mut out = Vec::new();
    let steering = spec.bep.resolved_steering();
    let github: Vec<&str> = spec.github_grants().collect();

    // BEP-009: a grant in a box with no network reaches nothing.
    if spec.network == NetworkMode::NoNet && spec.has_credentialed_upstream() {
        out.push(BepRefusal::NoNetworkWithGrant {
            grants: spec
                .secrets
                .iter()
                .filter(|(_, grant)| grant.is_credentialed())
                .map(|(name, _)| name.clone())
                .collect(),
        });
    }

    // BEP-008: every host of the GitHub set must be an egress name.
    if !github.is_empty() {
        let allowed: Vec<String> = spec
            .egress
            .and_then(|egress| egress.allow_dns_hosts.as_ref())
            .map(|hosts| hosts.iter().map(|h| normalize_host(h)).collect())
            .unwrap_or_default();
        let missing: Vec<String> = module_hosts
            .iter()
            .filter(|host| !allowed.contains(&normalize_host(host)))
            .map(|host| (*host).to_string())
            .collect();
        if !missing.is_empty() {
            out.push(BepRefusal::HostsOutsideEgress { missing });
        }
    }

    // BEP-010: `off` injects no CA, so a proxy environment cannot work.
    if steering == Steering::Off && spec.bep.proxy_env {
        out.push(BepRefusal::SteeringOffWithProxyEnv);
    }

    // BEP-017: `dns` and `both` need the box-zone resolver.
    if !host.box_zone_resolver && steering.needs_resolver() && spec.has_credentialed_upstream() {
        out.push(BepRefusal::NoResolver { steering });
    }

    // BEP-056: an un-enrolled host has no GitHub App key.
    if !host.enrolled {
        for (name, grant) in spec.secrets {
            if grant.is_github() && grant.mode == Some(GrantMode::Installation) {
                out.push(BepRefusal::InstallationUnenrolled {
                    grant: name.clone(),
                });
            }
        }
    }

    // BEP-057: un-enrolled, a narrower grant is minted `full`, which the
    // client configuration must accept.
    if !host.enrolled && !host.full_breadth_acknowledged {
        for (name, grant) in spec.secrets {
            if grant.is_narrower_than_full() {
                out.push(BepRefusal::NarrowScopesUnenrolled {
                    grant: name.clone(),
                    scopes: grant
                        .narrow_scopes()
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                });
            }
        }
    }
    out
}

/// Checks `spec` before the box is created. Returns the plan for an
/// accepted spec, or every reason to refuse it. Logs one debug line per
/// refusal, naming the rule and the fields.
///
/// # Errors
///
/// [`ActivationRefused`] when any check refuses the spec.
pub fn check_activation(
    spec: &ActivationSpec<'_>,
    host: HostFacts,
    module_hosts: &[&str],
) -> Result<ActivationPlan, ActivationRefused> {
    let refusals = refusals(spec, host, module_hosts);
    if !refusals.is_empty() {
        for refusal in &refusals {
            tracing::debug!(
                rule = refusal.rule(),
                fields = refusal.fields(),
                reason = %refusal,
                "box spec refused at activation"
            );
        }
        return Err(ActivationRefused { refusals });
    }
    let steering = spec.bep.resolved_steering();
    let github: Vec<String> = spec.github_grants().map(str::to_string).collect();
    let mut warnings = Vec::new();
    if steering == Steering::Off && !github.is_empty() {
        warnings.push(BepWarning::SteeringOffWithGrant { grants: github });
    }
    Ok(ActivationPlan {
        steering,
        inject_ca: spec.has_credentialed_upstream() && steering != Steering::Off,
        warnings,
    })
}

impl ActivationPlan {
    /// Adds a warning for each trust variable (BEP-011) that the box spec's
    /// environment sets, in [`TRUST_ENV_VARIABLES`] order, when the box gets
    /// the proxy's root. The spec's value stays, so a tool that reads that
    /// variable does not trust the proxy. `spec_env` is the names of the
    /// variables the spec sets. A box without the root gets no warning.
    pub fn warn_spec_trust_env<'a>(&mut self, spec_env: impl IntoIterator<Item = &'a str>) {
        if !self.inject_ca {
            return;
        }
        let set: std::collections::BTreeSet<&str> = spec_env.into_iter().collect();
        for variable in TRUST_ENV_VARIABLES {
            if set.contains(variable) {
                tracing::debug!(
                    rule = "BEP-011",
                    variable,
                    "box spec sets a trust variable, so its value stays"
                );
                self.warnings.push(BepWarning::TrustEnvSetBySpec {
                    variable: variable.to_string(),
                });
            }
        }
    }
}

/// Refuses a box spec with a GitHub grant when no GitHub sign-in is held
/// (BEP-003). `signed_in` says whether the host holds a sign-in. The caller
/// reads it from the sign-in item's metadata, and nothing here asks for a
/// sign-in. Logs one debug line when it refuses.
///
/// # Errors
///
/// [`ActivationRefused`] with one [`BepRefusal::SignInRequired`] when
/// `secrets` holds a GitHub grant and `signed_in` is false.
pub fn require_sign_in(secrets: &SecretGrants, signed_in: bool) -> Result<(), ActivationRefused> {
    let grants: Vec<String> = secrets
        .iter()
        .filter(|(_, grant)| grant.is_github())
        .map(|(name, _)| name.clone())
        .collect();
    if signed_in || grants.is_empty() {
        return Ok(());
    }
    let refusal = BepRefusal::SignInRequired { grants };
    tracing::debug!(
        rule = refusal.rule(),
        fields = refusal.fields(),
        code = GITHUB_SIGN_IN_REQUIRED,
        "box spec refused at creation: no GitHub sign-in is held"
    );
    Err(ActivationRefused {
        refusals: vec![refusal],
    })
}

/// Refuses a box spec with a GitHub grant where no node-local proxy serves
/// boxes (Gatehouse §6.2). `proxy_present` says whether one does. Logs one
/// debug line when it refuses.
///
/// # Errors
///
/// [`ActivationRefused`] with one [`BepRefusal::UnenrolledNode`] when
/// `secrets` holds a GitHub grant and `proxy_present` is false.
pub fn require_proxy(secrets: &SecretGrants, proxy_present: bool) -> Result<(), ActivationRefused> {
    let grants: Vec<String> = secrets
        .iter()
        .filter(|(_, grant)| grant.is_github())
        .map(|(name, _)| name.clone())
        .collect();
    if proxy_present || grants.is_empty() {
        return Ok(());
    }
    Err(unenrolled_node(grants))
}

/// The [`GATEHOUSE_UNENROLLED_NODE`] refusal of the GitHub grants `grants`.
/// Logs one debug line.
#[must_use]
pub fn unenrolled_node(grants: Vec<String>) -> ActivationRefused {
    let refusal = BepRefusal::UnenrolledNode { grants };
    tracing::debug!(
        rule = refusal.rule(),
        fields = refusal.fields(),
        code = GATEHOUSE_UNENROLLED_NODE,
        "box spec refused at creation: no node-local proxy serves boxes"
    );
    ActivationRefused {
        refusals: vec![refusal],
    }
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const GITHUB_HOSTS: &[&str] = &[
        "github.com",
        "api.github.com",
        "uploads.github.com",
        "codeload.github.com",
    ];

    const RESOLVER_HOST: HostFacts = HostFacts {
        enrolled: false,
        box_zone_resolver: true,
        full_breadth_acknowledged: false,
    };

    fn github_grant(mode: Option<GrantMode>) -> SecretGrant {
        SecretGrant {
            source: GrantSource::Broker,
            scopes: vec!["github:user-token".into()],
            mode,
        }
    }

    fn grants(grant: SecretGrant) -> SecretGrants {
        BTreeMap::from([("GH_TOKEN".to_string(), grant)])
    }

    // BEP-003: a GitHub grant with no sign-in held fails with the defined
    // error and the fixed text, and exits as a refused box spec.
    #[test]
    fn creation_without_sign_in_fails_with_defined_error() {
        let secrets = grants(github_grant(None));
        let refused = require_sign_in(&secrets, false).unwrap_err();
        assert_eq!(
            refused.refusals,
            [BepRefusal::SignInRequired {
                grants: vec!["GH_TOKEN".into()]
            }]
        );
        assert_eq!(refused.refusals[0].code(), Some(GITHUB_SIGN_IN_REQUIRED));
        assert_eq!(GITHUB_SIGN_IN_REQUIRED, "github_sign_in_required");
        assert_eq!(refused.exit_code(), REFUSAL_EXIT_CODE);
        assert_eq!(
            refused.to_string(),
            "This box declares a GitHub grant, and no GitHub sign-in is held on this machine. \
             Run `min auth login`, then create the box again."
        );

        // A held sign-in, or a box with no GitHub grant, is not refused.
        assert!(require_sign_in(&secrets, true).is_ok());
        let client_env = grants(SecretGrant {
            source: GrantSource::ClientEnv,
            scopes: vec!["github:user-token".into()],
            mode: None,
        });
        assert!(require_sign_in(&client_env, false).is_ok());
        assert!(require_sign_in(&SecretGrants::new(), false).is_ok());
        // Another refusal has no defined error.
        assert_eq!(BepRefusal::SteeringOffWithProxyEnv.code(), None);
    }

    fn egress_with(hosts: &[&str]) -> EgressPolicy {
        EgressPolicy {
            allow_dns_hosts: Some(hosts.iter().map(|h| (*h).to_string()).collect()),
            ..EgressPolicy::default()
        }
    }

    fn proxy_env() -> BepSettings {
        BepSettings {
            steering: Some(Steering::ProxyEnv),
            ..BepSettings::default()
        }
    }

    fn any_network() -> impl Strategy<Value = NetworkMode> {
        prop_oneof![
            Just(NetworkMode::NoNet),
            Just(NetworkMode::HostNet),
            Just(NetworkMode::OwnIp),
        ]
    }

    fn any_steering() -> impl Strategy<Value = Option<Steering>> {
        prop_oneof![
            Just(None),
            Just(Some(Steering::Dns)),
            Just(Some(Steering::ProxyEnv)),
            Just(Some(Steering::Both)),
            Just(Some(Steering::Off)),
        ]
    }

    fn any_mode() -> impl Strategy<Value = Option<GrantMode>> {
        prop_oneof![
            Just(None),
            Just(Some(GrantMode::User)),
            Just(Some(GrantMode::Installation)),
        ]
    }

    fn any_source() -> impl Strategy<Value = GrantSource> {
        prop_oneof![Just(GrantSource::Broker), Just(GrantSource::ClientEnv)]
    }

    /// Grants that all copy a client variable: no credentialed upstream.
    fn client_env_grants() -> impl Strategy<Value = SecretGrants> {
        prop::collection::btree_map(
            "[A-Z]{1,6}",
            any_grant().prop_map(|grant| SecretGrant {
                source: GrantSource::ClientEnv,
                ..grant
            }),
            1..3,
        )
    }

    fn any_grant() -> impl Strategy<Value = SecretGrant> {
        (
            prop::collection::vec(
                prop_oneof![
                    Just("github:user-token".to_string()),
                    Just("github:repo:read".to_string()),
                    Just("keychain:npm".to_string()),
                ],
                0..3,
            ),
            any_mode(),
            any_source(),
        )
            .prop_map(|(scopes, mode, source)| SecretGrant {
                source,
                scopes,
                mode,
            })
    }

    fn any_grants() -> impl Strategy<Value = SecretGrants> {
        prop::collection::btree_map("[A-Z]{1,6}", any_grant(), 0..3)
    }

    fn any_bep() -> impl Strategy<Value = BepSettings> {
        (any_steering(), any::<bool>()).prop_map(|(steering, proxy_env)| BepSettings {
            steering,
            proxy_env,
            ..BepSettings::default()
        })
    }

    /// A host list drawn from the GitHub set plus a stranger, with case and
    /// trailing-dot variants.
    fn any_egress() -> impl Strategy<Value = Option<EgressPolicy>> {
        let host = prop_oneof![
            Just("github.com".to_string()),
            Just("api.github.com".to_string()),
            Just("uploads.github.com".to_string()),
            Just("codeload.github.com".to_string()),
            Just("API.GitHub.com.".to_string()),
            Just("example.com".to_string()),
        ];
        prop_oneof![
            Just(None),
            Just(Some(EgressPolicy::default())),
            prop::collection::vec(host, 0..7).prop_map(|hosts| Some(EgressPolicy {
                allow_dns_hosts: Some(hosts),
                ..EgressPolicy::default()
            })),
        ]
    }

    fn any_module_hosts() -> impl Strategy<Value = Vec<&'static str>> {
        prop::sample::subsequence(GITHUB_HOSTS.to_vec(), 0..=GITHUB_HOSTS.len())
    }

    fn any_host() -> impl Strategy<Value = HostFacts> {
        (any::<bool>(), any::<bool>()).prop_map(|(enrolled, box_zone_resolver)| HostFacts {
            enrolled,
            box_zone_resolver,
            full_breadth_acknowledged: false,
        })
    }

    proptest! {
        /// BEP-008: the refusal fires iff a GitHub grant is declared and a
        /// host of the set is absent from the egress names, it names
        /// exactly the absent hosts, and it ends the run with exit 3.
        #[test]
        fn prop_grant_host_set_outside_egress_is_exit_3(
            network in any_network(),
            egress in any_egress(),
            bep in any_bep(),
            secrets in any_grants(),
            host in any_host(),
            module in any_module_hosts(),
        ) {
            let spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &secrets };
            let allowed: Vec<String> = egress
                .as_ref()
                .and_then(|e| e.allow_dns_hosts.clone())
                .unwrap_or_default()
                .iter()
                .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
                .collect();
            let absent: Vec<String> = module
                .iter()
                .filter(|h| !allowed.contains(&(**h).to_string()))
                .map(|h| (*h).to_string())
                .collect();
            let expected = secrets.values().any(SecretGrant::is_github) && !absent.is_empty();
            let named = refusals(&spec, host, &module).into_iter().find_map(|r| match r {
                BepRefusal::HostsOutsideEgress { missing } => Some(missing),
                _ => None,
            });
            prop_assert_eq!(named.is_some(), expected);
            if let Some(missing) = named {
                prop_assert_eq!(missing, absent);
            }
            if expected {
                let refused = check_activation(&spec, host, &module).expect_err("refused");
                prop_assert_eq!(refused.exit_code(), 3);
            }
        }

        /// BEP-009: the refusal fires iff the network mode is `none` and at
        /// least one broker grant is declared. It names the broker grants
        /// only.
        #[test]
        fn prop_none_mode_with_grant_is_exit_3(
            network in any_network(),
            egress in any_egress(),
            bep in any_bep(),
            secrets in any_grants(),
            client in client_env_grants(),
            host in any_host(),
        ) {
            // A `client_env` grant in a `none` box is legal.
            let client_spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &client };
            let client_fired = refusals(&client_spec, host, GITHUB_HOSTS)
                .iter()
                .any(|r| matches!(r, BepRefusal::NoNetworkWithGrant { .. }));
            prop_assert!(!client_fired);

            let spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &secrets };
            let broker: Vec<String> = secrets
                .iter()
                .filter(|(_, g)| g.source == GrantSource::Broker)
                .map(|(name, _)| name.clone())
                .collect();
            let expected = network == NetworkMode::NoNet && !broker.is_empty();
            let named = refusals(&spec, host, GITHUB_HOSTS).into_iter().find_map(|r| match r {
                BepRefusal::NoNetworkWithGrant { grants } => Some(grants),
                _ => None,
            });
            prop_assert_eq!(named.is_some(), expected);
            if let Some(grants) = named {
                prop_assert_eq!(grants, broker);
            }
            if expected {
                let refused = check_activation(&spec, host, GITHUB_HOSTS).expect_err("refused");
                prop_assert_eq!(refused.exit_code(), 3);
            }
        }

        /// BEP-017: with no box-zone resolver, the refusal fires iff a
        /// broker grant is declared and the resolved steering is `dns` or
        /// `both`. Grants that are all `client_env` never fire it.
        #[test]
        fn prop_dns_steering_without_resolver_is_exit_3(
            network in any_network(),
            egress in any_egress(),
            bep in any_bep(),
            secrets in any_grants(),
            client in client_env_grants(),
            enrolled in any::<bool>(),
        ) {
            let host = HostFacts { enrolled, box_zone_resolver: false, full_breadth_acknowledged: false };

            let client_spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &client };
            let client_fired = refusals(&client_spec, host, GITHUB_HOSTS)
                .iter()
                .any(|r| matches!(r, BepRefusal::NoResolver { .. }));
            prop_assert!(!client_fired);
            if !(bep.steering == Some(Steering::Off) && bep.proxy_env) {
                let plan = check_activation(&client_spec, host, GITHUB_HOSTS);
                prop_assert!(plan.is_ok_and(|plan| !plan.inject_ca));
            }

            let spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &secrets };
            let resolved = bep.steering.unwrap_or(Steering::Dns);
            let expected = secrets.values().any(|g| g.source == GrantSource::Broker)
                && matches!(resolved, Steering::Dns | Steering::Both);
            let fired = refusals(&spec, host, GITHUB_HOSTS)
                .iter()
                .any(|r| matches!(r, BepRefusal::NoResolver { .. }));
            prop_assert_eq!(fired, expected);
            if expected {
                let refused = check_activation(&spec, host, GITHUB_HOSTS).expect_err("refused");
                prop_assert_eq!(refused.exit_code(), 3);
                prop_assert!(refused.to_string().contains("no box DNS resolver"));
            }
        }

        /// BEP-056: on an un-enrolled host the refusal fires iff a GitHub
        /// grant sets `mode = "installation"`, once per such grant, naming
        /// it.
        #[test]
        fn prop_installation_mode_unenrolled_is_exit_3(
            network in any_network(),
            egress in any_egress(),
            bep in any_bep(),
            secrets in any_grants(),
            box_zone_resolver in any::<bool>(),
        ) {
            let host = HostFacts { enrolled: false, box_zone_resolver, full_breadth_acknowledged: false };
            let spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &secrets };
            let expected: Vec<String> = secrets
                .iter()
                .filter(|(_, g)| g.is_github() && g.mode == Some(GrantMode::Installation))
                .map(|(name, _)| name.clone())
                .collect();
            let named: Vec<String> = refusals(&spec, host, GITHUB_HOSTS)
                .into_iter()
                .filter_map(|r| match r {
                    BepRefusal::InstallationUnenrolled { grant } => Some(grant),
                    _ => None,
                })
                .collect();
            prop_assert_eq!(&named, &expected);
            if let Some(first) = expected.first() {
                let refused = check_activation(&spec, host, GITHUB_HOSTS).expect_err("refused");
                prop_assert_eq!(refused.exit_code(), 3);
                prop_assert!(refused.to_string().contains(first.as_str()));
            }
        }
    }

    proptest! {
        /// BEP-057: on an un-enrolled host the refusal fires iff a GitHub
        /// grant declares a `github:repo:*` scope narrower than `full` and
        /// the client configuration does not acknowledge full breadth. It
        /// names the grant and the acknowledgement.
        #[test]
        fn prop_narrow_scopes_unenrolled_need_acknowledgement(
            network in any_network(),
            egress in any_egress(),
            bep in any_bep(),
            secrets in any_grants(),
            box_zone_resolver in any::<bool>(),
            enrolled in any::<bool>(),
            acknowledged in any::<bool>(),
        ) {
            let host = HostFacts { enrolled, box_zone_resolver, full_breadth_acknowledged: acknowledged };
            let spec = ActivationSpec { network, egress: egress.as_ref(), bep: &bep, secrets: &secrets };
            let expected: Vec<String> = if enrolled || acknowledged {
                Vec::new()
            } else {
                secrets
                    .iter()
                    .filter(|(_, g)| {
                        g.is_github()
                            && g.scopes.iter().any(|s| s.starts_with("github:repo:") && s != "github:repo:full")
                    })
                    .map(|(name, _)| name.clone())
                    .collect()
            };
            let named: Vec<String> = refusals(&spec, host, GITHUB_HOSTS)
                .into_iter()
                .filter_map(|r| match r {
                    BepRefusal::NarrowScopesUnenrolled { grant, .. } => Some(grant),
                    _ => None,
                })
                .collect();
            prop_assert_eq!(&named, &expected);
            if let Some(first) = expected.first() {
                let refused = check_activation(&spec, host, GITHUB_HOSTS).expect_err("refused");
                prop_assert_eq!(refused.exit_code(), 3);
                let text = refused.to_string();
                prop_assert!(text.contains(first.as_str()), "{}", text);
                prop_assert!(text.contains(FULL_BREADTH_ACKNOWLEDGEMENT), "{}", text);
            }
        }
    }

    /// `github:repo:full` is not narrower, and `github:user-token` is the
    /// `full` member's own spelling.
    #[test]
    fn full_scopes_are_not_narrow() {
        let mut grant = github_grant(None);
        assert!(!grant.is_narrower_than_full());
        grant.scopes = vec!["github:repo:full".into()];
        assert!(!grant.is_narrower_than_full());
        grant.scopes = vec!["github:repo:contents:read".into()];
        assert!(grant.is_narrower_than_full());
    }

    /// BEP-057: a project's `[session.secrets]` acknowledgement is dropped
    /// with a warning, and the grants beside it still load.
    #[test]
    fn project_acknowledgement_is_ignored_with_warning() {
        let table = "acknowledge_full_breadth_unenrolled = true\n\
                     [GH_TOKEN]\nsource = \"broker\"\nscopes = [\"github:repo:read\"]\n";
        let secrets: ProjectSecrets = toml::from_str(table).expect("parses");
        assert!(secrets.acknowledgement_ignored);
        assert_eq!(secrets.grants.len(), 1);
        assert!(secrets.grants["GH_TOKEN"].is_narrower_than_full());
        assert!(PROJECT_ACKNOWLEDGEMENT_IGNORED.contains(FULL_BREADTH_ACKNOWLEDGEMENT));
        assert!(PROJECT_ACKNOWLEDGEMENT_IGNORED.contains("ignored"));

        // The ignored acknowledgement does not reach the activation: the
        // narrower grant is still refused on this host.
        let bep = proxy_env();
        let egress = egress_with(GITHUB_HOSTS);
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: Some(&egress),
            bep: &bep,
            secrets: &secrets.grants,
        };
        let refused = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect_err("refused");
        assert_eq!(refused.exit_code(), 3);

        // A table without the key records nothing to warn about, and a
        // grant that does not parse is still an error.
        let quiet: ProjectSecrets =
            toml::from_str("[GH_TOKEN]\nsource = \"broker\"\n").expect("parses");
        assert!(!quiet.acknowledgement_ignored);
        assert!(toml::from_str::<ProjectSecrets>("[GH_TOKEN]\nsource = \"vault\"\n").is_err());
    }

    /// The resolved `quic443` stance (BEP-018).
    #[test]
    fn quic443_auto_blocks_only_on_credentialed_resolver_steering() {
        assert!(Quic443::Block.blocks(false, Steering::Off));
        assert!(!Quic443::Allow.blocks(true, Steering::Dns));
        assert!(Quic443::Auto.blocks(true, Steering::Dns));
        assert!(Quic443::Auto.blocks(true, Steering::Both));
        assert!(!Quic443::Auto.blocks(true, Steering::ProxyEnv));
        assert!(!Quic443::Auto.blocks(false, Steering::Dns));
    }

    /// The diagnostic text the task fixes for BEP-008.
    #[test]
    fn missing_hosts_message_names_each_host() {
        let secrets = grants(github_grant(None));
        let egress = egress_with(&["github.com", "api.github.com"]);
        let bep = proxy_env();
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: Some(&egress),
            bep: &bep,
            secrets: &secrets,
        };
        let refused = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect_err("refused");
        assert_eq!(
            refused.to_string(),
            "This box declares a GitHub grant, but its egress does not allow: \
             uploads.github.com, codeload.github.com. Add them to egress.allow_dns_hosts."
        );
    }

    /// BEP-010: `off` with a GitHub grant is accepted, injects no CA, and
    /// warns naming the grant.
    #[test]
    fn steering_off_with_grant_warns_and_injects_no_ca() {
        let secrets = grants(github_grant(None));
        let egress = egress_with(GITHUB_HOSTS);
        let bep = BepSettings {
            steering: Some(Steering::Off),
            ..BepSettings::default()
        };
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: Some(&egress),
            bep: &bep,
            secrets: &secrets,
        };
        let plan = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect("accepted");
        assert_eq!(plan.steering, Steering::Off);
        assert!(!plan.inject_ca, "steering off injects no interception CA");
        assert_eq!(
            plan.warnings,
            vec![BepWarning::SteeringOffWithGrant {
                grants: vec!["GH_TOKEN".into()]
            }]
        );
        assert!(plan.warnings[0].to_string().contains("GH_TOKEN"));

        // The same box under `proxy_env` gets the CA and no warning.
        let bep = proxy_env();
        let spec = ActivationSpec { bep: &bep, ..spec };
        let plan = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect("accepted");
        assert!(plan.inject_ca);
        assert!(plan.warnings.is_empty());
    }

    /// BEP-011: a box spec that sets a trust variable keeps its value, and
    /// the activation warns naming the variable. A box without the root
    /// gets no warning.
    #[test]
    fn spec_trust_env_shadows_platform_with_warning() {
        let secrets = grants(github_grant(None));
        let egress = egress_with(GITHUB_HOSTS);
        let bep = proxy_env();
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: Some(&egress),
            bep: &bep,
            secrets: &secrets,
        };
        let mut plan = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect("accepted");
        assert!(plan.inject_ca);
        plan.warn_spec_trust_env(["PATH", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"]);
        assert_eq!(
            plan.warnings,
            vec![
                BepWarning::TrustEnvSetBySpec {
                    variable: "SSL_CERT_FILE".into()
                },
                BepWarning::TrustEnvSetBySpec {
                    variable: "NODE_EXTRA_CA_CERTS".into()
                },
            ]
        );
        assert_eq!(
            plan.warnings[0].to_string(),
            "This box sets SSL_CERT_FILE itself, so tools that read it will not \
             trust the proxy's certificate."
        );

        // Steering `off` injects no root, so the spec's value shadows nothing.
        let bep = BepSettings {
            steering: Some(Steering::Off),
            ..BepSettings::default()
        };
        let spec = ActivationSpec { bep: &bep, ..spec };
        let mut plan = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect("accepted");
        let before = plan.warnings.clone();
        plan.warn_spec_trust_env(["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"]);
        assert_eq!(plan.warnings, before);
    }

    /// BEP-010: `off` with `proxy_env = true` is refused with exit 3,
    /// naming both fields.
    #[test]
    fn steering_off_with_proxy_env_is_refused() {
        let secrets = SecretGrants::new();
        let bep = BepSettings {
            steering: Some(Steering::Off),
            proxy_env: true,
            ..BepSettings::default()
        };
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: None,
            bep: &bep,
            secrets: &secrets,
        };
        let refused = check_activation(&spec, HostFacts::LOCAL, GITHUB_HOSTS).expect_err("refused");
        assert_eq!(refused.refusals, vec![BepRefusal::SteeringOffWithProxyEnv]);
        assert_eq!(refused.exit_code(), 3);
        let text = refused.to_string();
        assert!(text.contains("steering = \"off\""), "{text}");
        assert!(text.contains("proxy_env = true"), "{text}");
    }

    /// BEP-016: a spec with a grant and no `steering` resolves to `dns`,
    /// from TOML and from the default alike, and an empty table reads as
    /// empty.
    #[test]
    fn steering_defaults_to_dns() {
        assert_eq!(BepSettings::default().resolved_steering(), Steering::Dns);
        let parsed: BepSettings = toml::from_str("proxy_env = false").expect("parses");
        assert_eq!(parsed.steering, None);
        assert_eq!(parsed.resolved_steering(), Steering::Dns);
        assert!(parsed.is_empty());

        let secrets = grants(github_grant(None));
        let egress = egress_with(GITHUB_HOSTS);
        let bep = BepSettings::default();
        let spec = ActivationSpec {
            network: NetworkMode::OwnIp,
            egress: Some(&egress),
            bep: &bep,
            secrets: &secrets,
        };
        let plan = check_activation(&spec, RESOLVER_HOST, GITHUB_HOSTS).expect("accepted");
        assert_eq!(plan.steering, Steering::Dns);
        assert!(plan.inject_ca);
    }

    /// A misspelt field is refused, never ignored: an ignored `mode` would
    /// skip BEP-056.
    #[test]
    fn unknown_grant_field_is_refused() {
        let err = toml::from_str::<SecretGrant>(
            "source = \"broker\"\nscopes = [\"github:user-token\"]\nmdoe = \"installation\"",
        );
        assert!(err.is_err());
    }

    /// The source is required and closed: a grant with no source, or an
    /// unknown one, does not parse.
    #[test]
    fn grant_source_is_required_and_known() {
        assert!(toml::from_str::<SecretGrant>("scopes = [\"github:user-token\"]").is_err());
        assert!(toml::from_str::<SecretGrant>("source = \"vault\"").is_err());
        let grant: SecretGrant = toml::from_str("source = \"client_env\"").expect("parses");
        assert_eq!(grant.source, GrantSource::ClientEnv);
        let grant: SecretGrant =
            toml::from_str("source = \"broker\"\nscopes = [\"github:user-token\"]")
                .expect("parses");
        assert!(grant.is_credentialed() && grant.is_github());
    }
}
