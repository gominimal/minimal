//! The node-plane baseline set: the helper's built-in enumeration of the
//! categories the node plane's own traffic may reach, for the host that is
//! un-enrolled (NET-130).
//!
//! A box's egress is decided by the rules its own declaration compiled into
//! its row. The in-VM daemon's own traffic — its registry and cache fetches
//! (NET-080) — is not a box's: it wears the daemon's own address on the
//! fabric, the address the plan reserves for it, and the row the run path
//! registers for it is an allow-all interim. On a host un-enrolled, the node
//! plane's allowance is this enumeration instead: the design's categories,
//! built in from the switch fabric's own address plan, each carrying the
//! subnets its traffic reaches — the registry and the cache configurable as
//! to which, never absent — and the in-VM daemon's own address, the one
//! source identity the set's verdict accepts.
//!
//! The host-side egress gate decides a frame from the daemon's address by
//! this set beside the boxes' rows: a deny-all box cannot clip the daemon's
//! own fetches, because the set is decided before the box's row is
//! consulted, and a frame wearing the daemon's address to reach somewhere
//! else is bounded by the enumeration, not by the interim row (NET-085).
//! The gate decides by the set from VM start ([`NODE_BASELINE_PHASE`] is
//! [`NodeBaselinePhase::InForce`]).
//!
//! The registry and cache entries are named endpoints: the hosts the
//! daemon's own fetches go to ([`DAEMON_REGISTRY_ENDPOINT`],
//! [`DAEMON_CACHE_ENDPOINT`]). A name is not an address, so the set admits a
//! name's addresses only as the node plane's own lookups resolve them: the
//! host-side DNS admission table pins each answer against the entry that
//! named it ([`crate::net::dns_pins`]), under the same window and per-name
//! cap a box's pins hold. An endpoint spelled as a subnet (`a.b.c.d/n`) is
//! admitted as it stands. Which registry and which cache the node plane
//! uses is the deployment's to say (`MINVMD_BASELINE_REGISTRY`,
//! `MINVMD_BASELINE_CACHE`), every change is logged, and neither category is
//! ever dropped from the enumeration by saying it.
//!
//! A frame from the node address that wears the box mark is not the node
//! plane's: the gate decides it by the union of the resident `host_ip`
//! boxes' rules, and drops it when no `host_ip` box is resident
//! ([`crate::net::egress_gate`]). The set never decides a marked frame, and
//! the node row never does either.

use boxes::core::egress::{EgressRules, Ipv4Cidr};
use std::io;
use switch::SwitchSubnet;

/// A category of the node-plane baseline enumeration: one of the design's
/// named service planes the node plane's own traffic may reach. The set is
/// bounded to these categories and never a general-purpose allowance for
/// the switch fabric itself — a frame the node plane sends to a box is the
/// target box's ingress rules to decide, not this set's, so the categories
/// name nothing of the boxes' leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCategory {
    /// The package registry the node plane resolves and fetches from.
    Registry,
    /// The content cache the node plane fetches package content from.
    Cache,
}

impl BaselineCategory {
    /// The category's name as the policy display and the daemon log spell
    /// it: the display lists the set one term per category under the
    /// category's own name, and the start-up line logs the same terms.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Cache => "cache",
        }
    }
}

/// One category's entry in the enumeration: the category and the endpoints
/// it admits. An endpoint is a host name (`cache.minimal.dev`), whose
/// addresses the node plane's own lookups pin, or a subnet spelled the way an
/// egress policy declares one (`a.b.c.d/n`), admitted as it stands. The set
/// a host sees in its log and its policy display is the set the gate decides
/// by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    category: BaselineCategory,
    endpoints: Vec<String>,
}

impl BaselineEntry {
    /// The entry's category.
    #[must_use]
    pub fn category(&self) -> BaselineCategory {
        self.category
    }

    /// The entry's endpoints, as the host names and the subnet spellings
    /// the entry was configured with.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// The entry's subnet endpoints in the matchable form the compiled rules
    /// hold. An endpoint that does not parse as a subnet is a host name, and
    /// [`Self::names`] carries it instead.
    fn cidrs(&self) -> Vec<Ipv4Cidr> {
        self.endpoints
            .iter()
            .filter_map(|cidr| Ipv4Cidr::parse(cidr))
            .collect()
    }

    /// The entry's host-name endpoints, normalized to the form DNS names are
    /// matched in (ASCII-lowercased, the root dot stripped): the names whose
    /// answers the node plane's own lookups pin against this entry.
    pub(crate) fn names(&self) -> impl Iterator<Item = String> + '_ {
        self.endpoints
            .iter()
            .filter(|endpoint| Ipv4Cidr::parse(endpoint).is_none())
            .map(|name| {
                let lowered = name.trim().to_ascii_lowercase();
                lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
            })
            .filter(|name| !name.is_empty())
    }
}

/// The posture the node plane's own traffic is decided under: whether the
/// host-side gate decides a frame from the in-VM daemon's address by this
/// enumeration, or leaves the node plane to the run path's interim node row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeBaselinePhase {
    /// The enumeration is carried, logged at VM start, and shown beside the
    /// box's rules; the node plane's frames are decided by the interim node
    /// row.
    ///
    /// Constructed today only by the tests that pin the phase's other arm
    /// ([`NodePlaneBaseline::announced`]). The gate's decision reads the arm
    /// by path, so the variant is carried live even unconstructed.
    Announced,
    /// The gate decides node-plane frames by the enumeration: the addresses
    /// the node plane's own lookups pinned for an entry, the entries' subnet
    /// endpoints, the host alias at the configured host exposures, and the
    /// resolver carve-out.
    InForce,
}

impl NodeBaselinePhase {
    /// The phase as the value the gate's start-up line logs and the policy
    /// display spells beside the set: one spelling for the posture, so a
    /// host reading its policy output reads the same terms its daemon log
    /// wrote at VM start.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced (node row's allow-all interim)",
            Self::InForce => "in force",
        }
    }
}

/// The phase this build ships: in force. The registry and cache entries name
/// the hosts the daemon's own fetches go to, and the node plane's own lookups
/// pin their addresses, so the gate deciding by the set keeps those fetches
/// passing (NET-080) and bounds everything else the node's address sends
/// (NET-085). The gate's decision reads the phase off the baseline it was
/// built with ([`NodePlaneBaseline::phase`]), and the start-up line logs it.
pub(crate) const NODE_BASELINE_PHASE: NodeBaselinePhase = NodeBaselinePhase::InForce;

/// The registry the daemon's own fetches resolve packages against: the host
/// of the package source repository a project's `[upstream]` names (`op`'s
/// default, `https://github.com/gominimal/pkgs`). Before a box launches, the
/// in-VM daemon git-fetches that repository at its locked commit to build
/// the package graph, so the fetch is node-plane traffic and the host must
/// be a member. The package index and the package content the daemon reads
/// next are objects in the cache ([`DAEMON_CACHE_ENDPOINT`]). Nothing on a
/// VM host configures another location for the guest daemon, so the
/// daemon's configured registry is this default. A deployment re-points the
/// category with [`BASELINE_REGISTRY_ENV`].
pub const DAEMON_REGISTRY_ENDPOINT: &str = "github.com";

/// The cache the daemon's own fetches read package content from: the host of
/// its default remote cache read location (`mctx`'s
/// `DEFAULT_REMOTE_CACHE_READ_URL`, `https://cache.minimal.dev/`). A
/// deployment re-points the category with [`BASELINE_CACHE_ENV`].
pub const DAEMON_CACHE_ENDPOINT: &str = "cache.minimal.dev";

/// The environment variable that re-points the registry category: a
/// comma-separated list of host names (`pkgs.example.com`) and subnets
/// (`a.b.c.d/n`). Absent, the category keeps [`DAEMON_REGISTRY_ENDPOINT`].
/// Set and empty, the category stays carried and admits nothing. Read from
/// the reading process's own environment each time the set is built.
pub(crate) const BASELINE_REGISTRY_ENV: &str = "MINVMD_BASELINE_REGISTRY";

/// The environment variable that re-points the cache category, spelled the
/// way [`BASELINE_REGISTRY_ENV`] is. Absent, the category keeps
/// [`DAEMON_CACHE_ENDPOINT`].
pub(crate) const BASELINE_CACHE_ENV: &str = "MINVMD_BASELINE_CACHE";

/// One category's endpoints as the deployment spelled them in `var`, or
/// `None` when the variable is absent. A value that is not Unicode keeps the
/// built-in endpoints and logs a warning that names the variable.
fn baseline_endpoints_from_env(var: &str) -> Option<Vec<String>> {
    match std::env::var(var) {
        Ok(raw) => Some(baseline_endpoints_from_raw(var, &raw)),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            tracing::warn!(
                variable = var,
                "the node-plane baseline entry's variable is not valid Unicode; the built-in \
                 endpoints stay in force",
            );
            None
        }
    }
}

/// Parses one category's endpoint list: comma-separated terms, whitespace
/// trimmed, empty terms skipped. A term with a `/` must be an IPv4 subnet,
/// and any other term must be a host name of letters, digits, `-` and `.`.
/// A term that is neither is skipped with a warning that names it, so a typo
/// narrows the set and never widens it. A bare IPv4 address is not a host
/// name: it is skipped with a warning that names its `/32` subnet form.
fn baseline_endpoints_from_raw(var: &str, raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|term| !term.is_empty())
        .filter(|term| {
            if term.parse::<std::net::Ipv4Addr>().is_ok() {
                tracing::warn!(
                    variable = var,
                    term = %term,
                    "skipped a node-plane baseline endpoint that is a bare IPv4 address; \
                     write it as the subnet {term}/32",
                );
                return false;
            }
            let valid = if term.contains('/') {
                Ipv4Cidr::parse(term).is_some()
            } else {
                term.trim_end_matches('.').split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            };
            if !valid {
                tracing::warn!(
                    variable = var,
                    term = %term,
                    "skipped a node-plane baseline endpoint that is neither a host name nor an \
                     IPv4 subnet",
                );
            }
            valid
        })
        .map(str::to_string)
        .collect()
}

/// The environment variable the daemon's host-exposure port list is read
/// from, each time the daemon starts the VM's network — from the daemon's
/// own environment, so a change takes a daemon restart, the same shape the
/// hostname proxy port and the egress-default opt-out carry.
pub(crate) const HOST_EXPOSURE_PORTS_ENV: &str = "MINVMD_HOST_EXPOSURE_PORTS";

/// The host-exposure port list the daemon starts with, as the deployment
/// spelled it. The design holds the alias default-deny except explicitly
/// configured host exposures (design §7.1), so absent or empty, the list is
/// empty and the alias is refused at every port for every row. The list is
/// comma-separated, each term a port (`4200`) or an inclusive range
/// (`3000-3999`), port 0 excluded; a term that is neither, a reversed range,
/// or a value that is not Unicode fails the start, the error naming the term
/// and the fix.
pub(crate) fn host_exposure_ports_from_env() -> io::Result<Vec<(u16, u16)>> {
    match std::env::var(HOST_EXPOSURE_PORTS_ENV) {
        Ok(raw) => host_exposure_ports_from_raw(Some(&raw)),
        Err(std::env::VarError::NotPresent) => host_exposure_ports_from_raw(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::other(format!(
            "{HOST_EXPOSURE_PORTS_ENV} is not valid Unicode. {HOST_EXPOSURE_FIX}"
        ))),
    }
}

/// The correction every parse error ends with.
const HOST_EXPOSURE_FIX: &str = "Set it to ports and ranges such as 8080,3000-3999, \
     or set it empty to close host.min.internal.";

/// Parses one deployment's spelling of the host-exposure port list: every
/// term a port or an inclusive range from 1 to 65535, whitespace trimmed;
/// absent or empty, no exposure at all.
fn host_exposure_ports_from_raw(raw: Option<&str>) -> io::Result<Vec<(u16, u16)>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let port = |text: &str, term: &str| match text.trim().parse::<u16>() {
        Ok(0) | Err(_) => Err(bad_host_exposure_term(term)),
        Ok(port) => Ok(port),
    };
    raw.split(',')
        .filter(|term| !term.trim().is_empty())
        .map(|term| {
            let term = term.trim();
            match term.split_once('-') {
                Some((lo, hi)) => {
                    let (lo, hi) = (port(lo, term)?, port(hi, term)?);
                    if lo <= hi {
                        Ok((lo, hi))
                    } else {
                        Err(io::Error::other(format!(
                            "{HOST_EXPOSURE_PORTS_ENV}: `{term}` is a reversed range; write it \
                             low-high, as `{hi}-{lo}`. {HOST_EXPOSURE_FIX}"
                        )))
                    }
                }
                None => port(term, term).map(|port| (port, port)),
            }
        })
        .collect()
}

/// The start-failing error for one unparseable term: the variable, the term
/// as it was read, and the correction.
fn bad_host_exposure_term(term: &str) -> io::Error {
    io::Error::other(format!(
        "{HOST_EXPOSURE_PORTS_ENV}: `{term}` is not a port from 1 to 65535 or a low-high port \
         range. {HOST_EXPOSURE_FIX}"
    ))
}

/// The node-plane baseline set: the categories in force, each with the
/// endpoints it admits, and the compiled rules the host-side gate decides
/// node-plane frames by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePlaneBaseline {
    /// The in-VM daemon's own address on the fabric — the one source
    /// identity the set's verdict accepts, carried as the compiled rules'
    /// lease.
    node_addr: [u8; 4],
    /// The switch's resolver, carried into every recompilation so the
    /// resolver carve-out survives a re-pointed category.
    resolver: [u8; 4],
    /// The categories in force, in the order the display spells them.
    entries: Vec<BaselineEntry>,
    /// The compiled allow list the gate decides node-plane frames by: every
    /// category's subnet endpoints, every IP protocol within them, keyed to
    /// the daemon's own address as its lease. A named endpoint is not in it:
    /// its addresses are the node plane's own pins.
    rules: EgressRules,
    /// The posture the gate decides the set under: the shipped constant.
    phase: NodeBaselinePhase,
    /// The configured host exposures over the alias, as inclusive port
    /// ranges: the ports the node plane reaches the host alias at, every
    /// other port refused through the alias. Empty unless the deployment
    /// names ports. The host-side gate alone reads it: the guest-side
    /// verdict's own alias list starts empty and nothing in the run path
    /// fills it, so own-address boxes stay refused at every port.
    host_exposure: Vec<(u16, u16)>,
}

impl NodePlaneBaseline {
    /// The built-in enumeration for one switch fabric. The categories are
    /// the design's, in the order the display spells them, and each names
    /// the host the daemon's own fetches go to:
    ///
    /// - `registry`: [`DAEMON_REGISTRY_ENDPOINT`], where the daemon fetches
    ///   the package source repository its package graph is built from.
    /// - `cache`: [`DAEMON_CACHE_ENDPOINT`], where the daemon reads the
    ///   package index and package content.
    ///
    /// Which registry and which cache the node plane uses is the
    /// deployment's to say: [`BASELINE_REGISTRY_ENV`] and
    /// [`BASELINE_CACHE_ENV`], when set, replace these endpoints within their
    /// category through [`with_registry`](Self::with_registry) and
    /// [`with_cache`](Self::with_cache), and each change is logged. A category
    /// is replaced, never absent. The VM host daemon reads them at VM start,
    /// and the policy display reads them from its own environment, so the two
    /// show one set when both run with the same environment.
    ///
    /// The set carries no row for the switch fabric itself: the categories
    /// are the design's named service planes, and the plane the node lives
    /// on is no allowance of its own. A node-plane frame aimed at a box's
    /// lease is the target box's ingress to decide, and the gate's in-force
    /// arm passes it on to the switch for that decision.
    ///
    /// The compiled set allows every IP protocol within the admitted
    /// subnets, and is keyed to the in-VM daemon's own address as its lease:
    /// the verdict rejects any frame wearing another source, so the set
    /// decides node-plane frames and only those. The resolver's carve-out
    /// keeps the node resolving, which is how its named endpoints get pinned.
    #[must_use]
    pub fn built_in(subnet: SwitchSubnet) -> Self {
        let mut baseline = Self::from_entries(
            subnet.daemon_ip().octets(),
            subnet.dns_server().octets(),
            vec![
                BaselineEntry {
                    category: BaselineCategory::Registry,
                    endpoints: vec![DAEMON_REGISTRY_ENDPOINT.to_string()],
                },
                BaselineEntry {
                    category: BaselineCategory::Cache,
                    endpoints: vec![DAEMON_CACHE_ENDPOINT.to_string()],
                },
            ],
        );
        if let Some(endpoints) = baseline_endpoints_from_env(BASELINE_REGISTRY_ENV) {
            baseline = baseline.with_registry(endpoints);
        }
        if let Some(endpoints) = baseline_endpoints_from_env(BASELINE_CACHE_ENV) {
            baseline = baseline.with_cache(endpoints);
        }
        baseline
    }

    /// The in-VM daemon's own address on the fabric: the one source identity
    /// the compiled set's verdict accepts, and the address the gate
    /// attributes node-plane frames by.
    #[must_use]
    pub(crate) fn node_addr(&self) -> [u8; 4] {
        self.node_addr
    }

    /// The categories in force, in the order they were carried.
    #[must_use]
    pub fn entries(&self) -> &[BaselineEntry] {
        &self.entries
    }

    /// The compiled rules the host-side gate decides node-plane frames by.
    #[must_use]
    pub(crate) fn rules(&self) -> &EgressRules {
        &self.rules
    }

    /// The posture the gate decides the set under. In force, the shipped
    /// posture: the set decides the node plane's frames. Announced: the run
    /// path's allow-all interim node row does.
    #[must_use]
    pub fn phase(&self) -> NodeBaselinePhase {
        self.phase
    }

    /// The host-name endpoints of every entry, each with the categories that
    /// name it, in the order the entries carry them: the names whose answers
    /// the node plane's own lookups pin ([`crate::net::dns_pins`]). One name
    /// can serve two categories, the built-in registry and cache among them.
    #[must_use]
    pub(crate) fn named_endpoints(&self) -> Vec<(String, Vec<BaselineCategory>)> {
        let mut named: Vec<(String, Vec<BaselineCategory>)> = Vec::new();
        for entry in &self.entries {
            for name in entry.names() {
                match named.iter_mut().find(|(known, _)| *known == name) {
                    Some((_, categories)) if !categories.contains(&entry.category) => {
                        categories.push(entry.category);
                    }
                    Some(_) => {}
                    None => named.push((name, vec![entry.category])),
                }
            }
        }
        named
    }

    /// The host exposures over the alias this gate carries: the inclusive
    /// port ranges the node plane reaches the host alias at, empty unless
    /// the deployment configured ports.
    #[must_use]
    pub(crate) fn host_exposure_ports(&self) -> &[(u16, u16)] {
        &self.host_exposure
    }

    /// Points the host exposures at `ports`, replacing the current list: a
    /// host names or clears its own exposure surface, and a cleared list is an
    /// alias with no opening — refused at every port for every row — not
    /// an absent arm. The compiled set is untouched: the list scopes the
    /// alias alone.
    #[must_use]
    pub fn with_host_exposure(mut self, ports: Vec<(u16, u16)>) -> Self {
        self.host_exposure = ports;
        self
    }

    /// The host-exposure list as the daemon's start-up line spells it: one
    /// `lo-hi` term per range, a bare port for a single-port term, and
    /// `(none)` when the deployment cleared the list.
    #[must_use]
    pub(crate) fn render_host_exposure(&self) -> String {
        if self.host_exposure.is_empty() {
            return "(none)".to_string();
        }
        self.host_exposure
            .iter()
            .map(|&(lo, hi)| {
                if lo == hi {
                    lo.to_string()
                } else {
                    format!("{lo}-{hi}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// One entry's endpoints as the policy display spells them (NET-061):
    /// each host name and each subnet as the entry holds it.
    #[must_use]
    pub fn display_endpoints(&self, entry: &BaselineEntry) -> Vec<String> {
        entry.endpoints.clone()
    }

    /// The set as the daemon's start-up line spells it: one
    /// `category=endpoints` term per category, in the order the categories
    /// are carried, so the line names the set in force with each entry's
    /// category. An entry with no endpoint is spelled `(none)`.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        self.entries
            .iter()
            .map(|entry| {
                let endpoints = if entry.endpoints.is_empty() {
                    "(none)".to_string()
                } else {
                    entry.endpoints.join(",")
                };
                format!("{}={endpoints}", entry.category.as_str())
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Points the registry category at `endpoints`, replacing the built-in:
    /// which registry the node plane uses is the host's to configure, within
    /// the category. The category stays carried — an empty list is a
    /// registry that admits nothing, not an absent one (NET-130) — the
    /// compiled set is rebuilt from every category's endpoints, and the
    /// change is logged.
    #[must_use]
    pub fn with_registry(mut self, endpoints: Vec<String>) -> Self {
        self.replace(BaselineCategory::Registry, endpoints);
        self
    }

    /// Points the cache category at `endpoints`, the way
    /// [`with_registry`](Self::with_registry) points the registry: replaced
    /// within its category, never absent, the compiled set rebuilt, the
    /// change logged.
    #[must_use]
    pub fn with_cache(mut self, endpoints: Vec<String>) -> Self {
        self.replace(BaselineCategory::Cache, endpoints);
        self
    }

    /// Pins the phase's other arm ([`NodeBaselinePhase::Announced`]): the
    /// run path's interim node row decides node-plane frames. Kept so the
    /// tests can pin both arms of the phase.
    #[cfg(test)]
    pub(crate) fn announced(mut self) -> Self {
        self.phase = NodeBaselinePhase::Announced;
        self
    }

    /// Re-points one category's endpoints, rebuilds the compiled set, and
    /// logs the change with the endpoints before and after it. A category
    /// the enumeration does not carry is added rather than skipped, so
    /// configuring a category can never make it absent.
    fn replace(&mut self, category: BaselineCategory, endpoints: Vec<String>) {
        let previous = match self
            .entries
            .iter_mut()
            .find(|entry| entry.category == category)
        {
            Some(entry) => std::mem::replace(&mut entry.endpoints, endpoints.clone()),
            None => {
                self.entries.push(BaselineEntry {
                    category,
                    endpoints: endpoints.clone(),
                });
                Vec::new()
            }
        };
        tracing::info!(
            entry = category.as_str(),
            previous = %previous.join(","),
            endpoints = %endpoints.join(","),
            "re-pointed a node-plane baseline entry",
        );
        self.rules = Self::compile_rules(&self.entries, self.resolver, self.node_addr);
    }

    /// Assembles the set from its parts: the categories carried, and the
    /// addresses the compiled rules are keyed to. The host exposures start
    /// empty, the alias closed; the deployment's spelling replaces them in
    /// the run path's builder.
    fn from_entries(node_addr: [u8; 4], resolver: [u8; 4], entries: Vec<BaselineEntry>) -> Self {
        Self {
            node_addr,
            resolver,
            rules: Self::compile_rules(&entries, resolver, node_addr),
            entries,
            phase: NODE_BASELINE_PHASE,
            host_exposure: Vec::new(),
        }
    }

    /// Compiles the categories' subnet endpoints into the allow list the
    /// gate decides node-plane frames by: every category's subnets, every IP
    /// protocol within them, the daemon's own address as the lease the
    /// verdict checks the frame's source against.
    fn compile_rules(
        entries: &[BaselineEntry],
        resolver: [u8; 4],
        node_addr: [u8; 4],
    ) -> EgressRules {
        let admitted = entries
            .iter()
            .flat_map(BaselineEntry::cidrs)
            .collect::<Vec<_>>();
        EgressRules::new(None, Some(admitted), None, resolver, node_addr)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BASELINE_CACHE_ENV, BASELINE_REGISTRY_ENV, BaselineCategory, BaselineEntry,
        DAEMON_CACHE_ENDPOINT, DAEMON_REGISTRY_ENDPOINT, HOST_EXPOSURE_PORTS_ENV,
        NodeBaselinePhase, NodePlaneBaseline, baseline_endpoints_from_env,
        baseline_endpoints_from_raw, host_exposure_ports_from_raw,
    };
    use boxes::core::egress::{FrameVerdict, summarize, verdict};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use switch::SwitchSubnet;

    /// The switch fabric these tests build the enumeration against: the
    /// default subnet the run path serves box addresses on.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// An Ethernet II frame carrying an IPv4 TCP payload — the shape the
    /// host-side gate reads a node-plane frame out of.
    fn tcp_frame(src: [u8; 4], dst: [u8; 4], port: u16) -> Vec<u8> {
        let mut frame = Vec::with_capacity(14 + 24);
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x01]); // dst MAC
        frame.extend_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x00, 0x02]); // src MAC
        frame.extend_from_slice(&0x0800u16.to_be_bytes()); // EtherType: IPv4
        frame.extend_from_slice(&[0x45, 0, 0, 0]); // version 4, IHL 5, TOS, length
        frame.extend_from_slice(&[0; 4]); // id, flags+offset: 0
        frame.push(64); // TTL
        frame.push(6); // protocol: TCP
        frame.extend_from_slice(&[0; 2]); // checksum (unchecked)
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);
        frame.extend_from_slice(&40000u16.to_be_bytes()); // source port
        frame.extend_from_slice(&port.to_be_bytes()); // destination port
        frame
    }

    /// The built-in entry for one category.
    fn entry(baseline: &NodePlaneBaseline, category: BaselineCategory) -> &BaselineEntry {
        baseline
            .entries()
            .iter()
            .find(|entry| entry.category() == category)
            .expect("the enumeration carries every category")
    }

    /// The first endpoint of one category's entry, parsed back to the
    /// address the compiled set admits.
    fn first_endpoint(baseline: &NodePlaneBaseline, category: BaselineCategory) -> [u8; 4] {
        let cidr = entry(baseline, category)
            .endpoints()
            .first()
            .expect("the category carries an endpoint");
        let addr = cidr
            .split_once('/')
            .expect("an endpoint is spelled `a.b.c.d/n`")
            .0;
        Ipv4Addr::from_str(addr)
            .expect("an endpoint's address parses")
            .octets()
    }

    /// NET-130: on a host un-enrolled, the node-plane baseline set comes
    /// from the helper's built-in enumeration — and the enumeration keeps
    /// the registry and the cache categories, each named by the host the
    /// daemon's own fetches go to, configurable as to which registry and
    /// which cache, never absent: re-pointing one leaves the other carried
    /// with its built-in endpoints, every re-pointing is logged, and the
    /// compiled set carries the replacement beside the survivors.
    #[test]
    fn baseline_enumeration_always_carries_registry_and_cache() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let baseline = NodePlaneBaseline::built_in(SUBNET);

        // The built-in enumeration carries every category — the registry and
        // the cache, the two the design names — each a named endpoint: the
        // host the daemon's own fetches go to, never an address the fabric
        // plan made up.
        assert_eq!(baseline.entries().len(), 2);
        assert_eq!(
            entry(&baseline, BaselineCategory::Registry).endpoints(),
            &[DAEMON_REGISTRY_ENDPOINT.to_string()]
        );
        assert_eq!(
            entry(&baseline, BaselineCategory::Cache).endpoints(),
            &[DAEMON_CACHE_ENDPOINT.to_string()]
        );
        // Both names are the ones the node plane's own lookups pin against,
        // each against its own category: the package source repository's
        // host for the registry, the cache's host for the cache.
        assert_eq!(
            baseline.named_endpoints(),
            vec![
                ("github.com".to_string(), vec![BaselineCategory::Registry]),
                (
                    "cache.minimal.dev".to_string(),
                    vec![BaselineCategory::Cache]
                ),
            ]
        );
        // And it carries the in-VM daemon's own address, the one source
        // identity the set's verdict accepts.
        assert_eq!(baseline.node_addr(), SUBNET.daemon_ip().octets());
        // The shipped posture is in force: the set decides the node plane's
        // own frames, and a marked frame is the resident `host_ip` boxes'
        // to decide, never the node row's. The posture carries no caveat.
        assert_eq!(baseline.phase(), NodeBaselinePhase::InForce);
        assert_eq!(baseline.phase().as_str(), "in force");

        // The deployment's spelling of an entry: host names and subnets,
        // whitespace trimmed, and a term that is neither skipped, so a typo
        // narrows the set and never widens it. A bare address is skipped
        // too: its subnet form is `/32`. Set and empty, the category
        // is carried with no endpoint.
        assert_eq!(
            baseline_endpoints_from_raw(
                BASELINE_REGISTRY_ENV,
                " pkgs.example.com , 203.0.113.0/24,,bad name,10.0.0.0/99,a..b,203.0.113.9 "
            ),
            vec!["pkgs.example.com".to_string(), "203.0.113.0/24".to_string()]
        );
        assert!(baseline_endpoints_from_raw(BASELINE_CACHE_ENV, "").is_empty());
        let emptied = baseline
            .clone()
            .with_cache(baseline_endpoints_from_raw(BASELINE_CACHE_ENV, " "));
        assert!(
            entry(&emptied, BaselineCategory::Cache)
                .endpoints()
                .is_empty(),
            "an emptied cache is carried and admits nothing, never absent"
        );
        // Absent, the built-in endpoints stand: this run sets neither
        // variable, which is how the built-in assertions above hold.
        assert_eq!(baseline_endpoints_from_env(BASELINE_REGISTRY_ENV), None);
        assert_eq!(baseline_endpoints_from_env(BASELINE_CACHE_ENV), None);

        // Which registry the node plane uses is the host's to say. The
        // registry category is replaced within itself, and the cache is
        // carried still, with its built-in endpoints.
        let cache_endpoints = entry(&baseline, BaselineCategory::Cache)
            .endpoints()
            .to_vec();
        let re_registered = baseline.with_registry(vec!["10.9.0.0/16".to_string()]);
        assert_eq!(
            entry(&re_registered, BaselineCategory::Registry).endpoints(),
            &["10.9.0.0/16".to_string()]
        );
        assert_eq!(
            entry(&re_registered, BaselineCategory::Cache).endpoints(),
            cache_endpoints,
        );

        // The same for the cache: replaced, with the registry carried still —
        // the re-pointed registry, exactly as the previous configuration left
        // it.
        let registry_endpoints = entry(&re_registered, BaselineCategory::Registry)
            .endpoints()
            .to_vec();
        let re_cached = re_registered.with_cache(vec!["10.8.0.0/16".to_string()]);
        assert_eq!(
            entry(&re_cached, BaselineCategory::Cache).endpoints(),
            &["10.8.0.0/16".to_string()]
        );
        assert_eq!(
            entry(&re_cached, BaselineCategory::Registry).endpoints(),
            registry_endpoints,
        );

        // Every change is logged, naming the entry and its endpoints before
        // and after.
        let logged = log.contents();
        for line in [
            "entry=\"registry\" previous=github.com endpoints=10.9.0.0/16",
            "entry=\"cache\" previous=cache.minimal.dev endpoints=10.8.0.0/16",
        ] {
            assert!(
                logged.contains(line) && logged.contains("re-pointed a node-plane baseline entry"),
                "each re-pointing is logged ({line}), got: {logged}"
            );
        }

        // An empty list keeps the category, admitting nothing: never absent.
        let emptied = re_cached.clone().with_registry(Vec::new());
        assert_eq!(emptied.entries().len(), 2);
        assert!(
            entry(&emptied, BaselineCategory::Registry)
                .endpoints()
                .is_empty()
        );
        assert_eq!(emptied.render(), "registry=(none), cache=10.8.0.0/16");

        // The compiled set decides by what the categories carry: the
        // replaced registry's subnets are admitted beside the surviving
        // cache's, and a destination no category names is not.
        let node_addr = re_cached.node_addr();
        for admitted in [
            first_endpoint(&re_cached, BaselineCategory::Registry),
            first_endpoint(&re_cached, BaselineCategory::Cache),
        ] {
            let summary = summarize(&tcp_frame(node_addr, admitted, 443));
            assert!(
                matches!(verdict(&summary, re_cached.rules()), FrameVerdict::Admit),
                "the re-pointed registry's and the surviving cache's endpoints are admitted"
            );
        }
        let summary = summarize(&tcp_frame(node_addr, [8, 8, 8, 8], 443));
        assert!(
            matches!(verdict(&summary, re_cached.rules()), FrameVerdict::Drop(_)),
            "a destination no category names is not admitted"
        );
    }

    /// The built-in set's compiled rules carry no address of their own: the
    /// named endpoints are admitted by the node plane's pins, not by a
    /// subnet, so a frame from the daemon's own address to any destination
    /// is the undeclared drop here and the pins decide it at the gate. A
    /// frame wearing another source is rejected by the lease the set is
    /// keyed to.
    #[test]
    fn baseline_rules_admit_no_address_but_the_resolver() {
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let node_addr = baseline.node_addr();

        let summary = summarize(&tcp_frame(node_addr, [8, 8, 8, 8], 443));
        match verdict(&summary, baseline.rules()) {
            FrameVerdict::Drop(reason) => {
                assert_eq!(reason.rule(), "egress-undeclared-subnet")
            }
            FrameVerdict::Admit => panic!("the compiled set admits no address of its own"),
        }

        // A frame wearing another source is rejected by the lease the set
        // is keyed to: the set decides node-plane frames, and only those.
        let summary = summarize(&tcp_frame([100, 64, 0, 9], [8, 8, 8, 8], 443));
        match verdict(&summary, baseline.rules()) {
            FrameVerdict::Drop(reason) => assert_eq!(reason.rule(), "egress-foreign-source"),
            FrameVerdict::Admit => panic!("a foreign source is not admitted by the set"),
        }
    }

    /// The deployment's spelling of the host-exposure list: absent or
    /// empty, no exposure — the alias closed; every term a port or an
    /// inclusive range from 1 to 65535; an undecodable term, port 0, or a
    /// reversed range a surfaced error naming the variable, the term and
    /// the fix.
    #[test]
    fn host_exposure_ports_read_from_the_environment() {
        assert!(
            host_exposure_ports_from_raw(None).unwrap().is_empty(),
            "an unset variable is no exposure: the alias stays closed"
        );
        assert_eq!(
            host_exposure_ports_from_raw(Some("8080")).unwrap(),
            vec![(8080, 8080)],
            "a bare port is a single-port range"
        );
        assert_eq!(
            host_exposure_ports_from_raw(Some(" 3000-3999, 4200 ")).unwrap(),
            vec![(3000, 3999), (4200, 4200)],
            "terms are inclusive ranges and ports, whitespace trimmed"
        );
        assert!(
            host_exposure_ports_from_raw(Some("")).unwrap().is_empty(),
            "a set-but-empty list is no exposure"
        );
        let garbage = host_exposure_ports_from_raw(Some("8080:nope"))
            .expect_err("an undecodable term is a surfaced error")
            .to_string();
        assert!(
            garbage.contains(HOST_EXPOSURE_PORTS_ENV)
                && garbage.contains("`8080:nope` is not a port")
                && garbage.contains("set it empty to close host.min.internal"),
            "an undecodable term names the variable, the term and the fix, got: {garbage}"
        );
        for zero in ["0", "0-65535"] {
            let error = host_exposure_ports_from_raw(Some(zero))
                .expect_err("port 0 is refused")
                .to_string();
            assert!(
                error.contains(&format!("`{zero}` is not a port")),
                "port 0 names the term, got: {error}"
            );
        }
        let reversed = host_exposure_ports_from_raw(Some("4000-3000"))
            .expect_err("a reversed range is not an inclusive one")
            .to_string();
        assert!(
            reversed.contains("`4000-3000` is a reversed range")
                && reversed.contains("`3000-4000`")
                && !reversed.contains("is not a port"),
            "a reversed range gets its own message, got: {reversed}"
        );
    }

    /// The baseline carries no exposure until the deployment's spelling
    /// replaces the list: the builder replaces rather than merges, and a
    /// cleared list reaches the accessor empty.
    #[test]
    fn baseline_carries_the_configured_host_exposures() {
        let built_in = NodePlaneBaseline::built_in(SUBNET);
        assert!(
            built_in.host_exposure_ports().is_empty(),
            "the built-in enumeration carries no host exposure"
        );
        let re_exposed = built_in.with_host_exposure(vec![(8080, 8080)]);
        assert_eq!(
            re_exposed.host_exposure_ports(),
            &[(8080, 8080)],
            "the builder sets the list"
        );
        let cleared = re_exposed.with_host_exposure(vec![]);
        assert!(
            cleared.host_exposure_ports().is_empty(),
            "a cleared list is carried empty"
        );
    }

    /// NET-061: the policy display spells each endpoint as the set holds
    /// it, a host name as a name and a subnet as a subnet.
    #[test]
    fn display_endpoints_spell_the_entries() {
        let baseline =
            NodePlaneBaseline::built_in(SUBNET).with_cache(vec!["198.51.100.0/24".to_owned()]);
        assert_eq!(
            baseline.display_endpoints(entry(&baseline, BaselineCategory::Registry)),
            vec!["github.com".to_owned()]
        );
        assert_eq!(
            baseline.display_endpoints(entry(&baseline, BaselineCategory::Cache)),
            vec!["198.51.100.0/24".to_owned()]
        );
    }
}
