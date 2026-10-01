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
//! the compiled set ([`NodePlaneBaseline::rules`]) beside the boxes' rows: a
//! deny-all box cannot clip the daemon's own fetches, because the set is
//! decided before the table is consulted, and a frame wearing the daemon's
//! address to reach somewhere else is bounded by the enumeration, not by the
//! interim row (NET-085). Whether the gate decides by the set yet is the
//! baseline's phase ([`NodeBaselinePhase`], [`NODE_BASELINE_PHASE`]) —
//! announced until the node plane's store surfaces are configured, the same
//! cutover shape the unregistered-source phase carries
//! ([`crate::net::egress_gate::UNREGISTERED_SOURCE_PHASE`]).
//!
//! The built-in registry and cache endpoints name the helper's answer
//! address on the fabric — the switch's host alias, the one address in this
//! tree's address plan where a store surface the helper itself carries
//! answers — because an un-enrolled host's own supply is the helper's to
//! carry. Which registry and which cache the node plane uses is the
//! deployment's to say, and neither category is ever dropped from the
//! enumeration by saying it.

use sessions::core::egress::{EgressRules, Ipv4Cidr};
use switch::SwitchSubnet;

/// A category of the node-plane baseline enumeration: one of the design's
/// named planes the node plane's own traffic may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineCategory {
    /// The package registry the node plane resolves and fetches from.
    Registry,
    /// The content cache the node plane fetches package content from.
    Cache,
    /// The switch fabric itself — the node's own plane: its own address, the
    /// resolver, the host alias, the box leases.
    Fabric,
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
            Self::Fabric => "fabric",
        }
    }
}

/// One category's entry in the enumeration: the category and the subnets it
/// admits, spelled the way an egress policy declares subnets (`a.b.c.d/n`) —
/// the same spelling the compiled rules parse from, so the set a host sees
/// in its log and its policy display is the set the gate decides by.
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

    /// The entry's endpoints, as the CIDR spellings the compiled set parses
    /// from.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// The entry's endpoints in the matchable form the compiled rules hold.
    /// The spellings are the constructors' own, so each parses; one that
    /// does not is skipped the way an egress policy's subnet declarations
    /// are compiled ([`EgressRules::from_policy`]).
    fn cidrs(&self) -> Vec<Ipv4Cidr> {
        self.endpoints
            .iter()
            .filter_map(|cidr| Ipv4Cidr::parse(cidr))
            .collect()
    }
}

/// The posture the node plane's own traffic is decided under: whether the
/// host-side gate decides a frame from the in-VM daemon's address by this
/// enumeration's compiled set, or leaves the node plane to the run path's
/// interim node row while the set is announced.
///
/// Shipped announced, for the one thing the enumeration cannot fix alone:
/// the built-in registry and cache endpoints name the helper's answer
/// address on the fabric, and the guest daemon's shipped cache endpoint is
/// a public service whose serving addresses no subnet list this tree can
/// name. A gate deciding by the built-in set before the node plane's store
/// surfaces are configured would sever the daemon's own fetches — the
/// traffic the enumeration exists to keep passing (NET-080). The flip is
/// [`NODE_BASELINE_PHASE`], one constant, the same shape the
/// unregistered-source cutover carries
/// ([`crate::net::egress_gate::UNREGISTERED_SOURCE_PHASE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeBaselinePhase {
    /// The enumeration is carried, logged at VM start, and shown beside the
    /// box's rules; the node plane's frames are still decided by the interim
    /// node row.
    Announced,
    /// The gate decides node-plane frames by the enumeration's compiled set.
    ///
    /// Constructed today only by the tests that pin the phase's other arm
    /// ([`NodePlaneBaseline::in_force`]) — the arm the store-surface
    /// configuration change flips [`NODE_BASELINE_PHASE`] onto. The gate's
    /// decision reads the arm by path, so the variant is carried live even
    /// unconstructed; no dead-code expectation sits on it.
    InForce,
}

impl NodeBaselinePhase {
    /// The phase as the value the gate's start-up line logs: a host reads
    /// its own posture off the one line every boot writes, so a host running
    /// the announced interim can tell it is.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Announced => "announced (node row's allow-all interim)",
            Self::InForce => "in force (decided by the baseline set)",
        }
    }
}

/// The phase this build ships: announced, because the node plane's store
/// surfaces are not yet configured to the endpoints the built-in enumeration
/// names. The endpoint-configuration change — the deployment's registry and
/// cache, answering where `with_registry` and `with_cache` point them — is
/// the change that flips this constant, and the constant is the whole
/// cutover: the gate's decision reads it off the baseline it was built with
/// ([`NodePlaneBaseline::phase`]), the start-up line logs it, and the tests
/// pin both of its arms, so the flip is one line and nothing else.
pub(crate) const NODE_BASELINE_PHASE: NodeBaselinePhase = NodeBaselinePhase::Announced;

/// The node-plane baseline set: the categories in force, each with the
/// subnets it admits, and the compiled rules the host-side gate decides
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
    /// category's endpoints, every IP protocol within them, keyed to the
    /// daemon's own address as its lease.
    rules: EgressRules,
    /// The posture the gate decides the set under: the shipped constant,
    /// until the store-surface configuration flips it.
    phase: NodeBaselinePhase,
}

impl NodePlaneBaseline {
    /// The built-in enumeration for one switch fabric. The categories are
    /// the design's, in the order the display spells them; the built-in
    /// endpoints come from the fabric's own address plan:
    ///
    /// - `registry` and `cache`: the helper's answer address on the fabric
    ///   (the switch's host alias) — the one address the plan holds for a
    ///   store surface the helper itself carries. Which registry and which
    ///   cache the node plane uses is the deployment's to say:
    ///   [`with_registry`](Self::with_registry) and
    ///   [`with_cache`](Self::with_cache) replace these endpoints within
    ///   their category, and a category is replaced, never absent.
    /// - `fabric`: the whole switch subnet — the node's own plane, its
    ///   resolver and the box leases included, reachable because it is the
    ///   plane the node plane lives on.
    ///
    /// The compiled set allows every IP protocol within the admitted
    /// subnets — the categories bound destinations, not protocols — and is
    /// keyed to the in-VM daemon's own address as its lease: the verdict
    /// rejects any frame wearing another source, so the set decides
    /// node-plane frames and only those. The resolver's carve-out keeps the
    /// node resolving under the declaration, the same carve-out a box's
    /// rules carry.
    #[must_use]
    pub fn built_in(subnet: SwitchSubnet) -> Self {
        let host_alias = subnet.host_alias();
        Self::from_entries(
            subnet.daemon_ip().octets(),
            subnet.dns_server().octets(),
            vec![
                BaselineEntry {
                    category: BaselineCategory::Registry,
                    endpoints: vec![format!("{host_alias}/32")],
                },
                BaselineEntry {
                    category: BaselineCategory::Cache,
                    endpoints: vec![format!("{host_alias}/32")],
                },
                BaselineEntry {
                    category: BaselineCategory::Fabric,
                    endpoints: vec![format!("{}/{}", subnet.network(), subnet.prefix())],
                },
            ],
        )
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

    /// The posture the gate decides the set under.
    #[must_use]
    pub(crate) fn phase(&self) -> NodeBaselinePhase {
        self.phase
    }

    /// The set as the daemon's start-up line spells it: one
    /// `category=endpoints` term per category, in the order the categories
    /// are carried, so the line names the set in force with each entry's
    /// category.
    #[must_use]
    pub(crate) fn render(&self) -> String {
        self.entries
            .iter()
            .map(|entry| format!("{}={}", entry.category.as_str(), entry.endpoints.join(",")))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Points the registry category at `endpoints`, replacing the built-in:
    /// which registry the node plane uses is the host's to configure, within
    /// the category. The category stays carried — an empty list is a
    /// registry that admits nothing, not an absent one (NET-130) — and the
    /// compiled set is rebuilt from every category's endpoints.
    #[must_use]
    pub fn with_registry(mut self, endpoints: Vec<String>) -> Self {
        self.replace(BaselineCategory::Registry, endpoints);
        self
    }

    /// Points the cache category at `endpoints`, the way
    /// [`with_registry`](Self::with_registry) points the registry: replaced
    /// within its category, never absent, the compiled set rebuilt.
    #[must_use]
    pub fn with_cache(mut self, endpoints: Vec<String>) -> Self {
        self.replace(BaselineCategory::Cache, endpoints);
        self
    }

    /// Pins the phase's other arm ([`NodeBaselinePhase::InForce`]): the gate
    /// decides node-plane frames by the compiled set. The arm the
    /// store-surface configuration change flips the shipped constant onto —
    /// built here so the in-force behavior has its proof before the flip
    /// lands, rather than tests to rewrite after it.
    #[cfg(test)]
    pub(crate) fn in_force(mut self) -> Self {
        self.phase = NodeBaselinePhase::InForce;
        self
    }

    /// Re-points one category's endpoints and rebuilds the compiled set.
    /// A category the enumeration does not carry is added rather than
    /// skipped, so configuring a category can never make it absent.
    fn replace(&mut self, category: BaselineCategory, endpoints: Vec<String>) {
        match self
            .entries
            .iter_mut()
            .find(|entry| entry.category == category)
        {
            Some(entry) => entry.endpoints = endpoints,
            None => self.entries.push(BaselineEntry {
                category,
                endpoints,
            }),
        }
        self.rules = Self::compile_rules(&self.entries, self.resolver, self.node_addr);
    }

    /// Assembles the set from its parts: the categories carried, and the
    /// addresses the compiled rules are keyed to.
    fn from_entries(node_addr: [u8; 4], resolver: [u8; 4], entries: Vec<BaselineEntry>) -> Self {
        Self {
            node_addr,
            resolver,
            rules: Self::compile_rules(&entries, resolver, node_addr),
            entries,
            phase: NODE_BASELINE_PHASE,
        }
    }

    /// Compiles the categories' endpoints into the allow list the gate
    /// decides node-plane frames by: every category's subnets, every IP
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
    use super::{BaselineCategory, BaselineEntry, NodePlaneBaseline};
    use sessions::core::egress::{FrameVerdict, summarize, verdict};
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
    /// the registry and the cache categories, configurable as to which
    /// registry and which cache, never absent: re-pointing one leaves the
    /// other carried with its built-in endpoints, and the compiled set
    /// carries the replacement beside the survivors.
    #[test]
    fn baseline_enumeration_always_carries_registry_and_cache() {
        let baseline = NodePlaneBaseline::built_in(SUBNET);

        // The built-in enumeration carries every category, the registry and
        // the cache among them, each with an endpoint to admit.
        assert_eq!(baseline.entries().len(), 3);
        assert!(
            !entry(&baseline, BaselineCategory::Registry)
                .endpoints()
                .is_empty()
        );
        assert!(
            !entry(&baseline, BaselineCategory::Cache)
                .endpoints()
                .is_empty()
        );
        assert!(
            !entry(&baseline, BaselineCategory::Fabric)
                .endpoints()
                .is_empty()
        );
        // And it carries the in-VM daemon's own address, the one source
        // identity the set's verdict accepts.
        assert_eq!(baseline.node_addr(), SUBNET.daemon_ip().octets());

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

    /// The built-in set's compiled rules decide node-plane frames by the
    /// enumeration alone: the daemon's own address may reach the categories'
    /// endpoints and nothing else, and a frame wearing another source is
    /// rejected by the lease the set is keyed to.
    #[test]
    fn baseline_rules_admit_the_enumerated_categories_alone() {
        let baseline = NodePlaneBaseline::built_in(SUBNET);
        let node_addr = baseline.node_addr();

        // The registry and cache endpoints — the helper's answer address on
        // the fabric — are admitted from the daemon's own address.
        let summary = summarize(&tcp_frame(
            node_addr,
            first_endpoint(&baseline, BaselineCategory::Registry),
            443,
        ));
        assert!(matches!(
            verdict(&summary, baseline.rules()),
            FrameVerdict::Admit
        ));

        // A destination no category names is dropped as undeclared — the
        // gap the announced phase covers until the store surfaces are
        // configured (see `NodeBaselinePhase`).
        let summary = summarize(&tcp_frame(node_addr, [8, 8, 8, 8], 443));
        match verdict(&summary, baseline.rules()) {
            FrameVerdict::Drop(reason) => {
                assert_eq!(reason.rule(), "egress-undeclared-subnet")
            }
            FrameVerdict::Admit => panic!("an out-of-set destination is not admitted"),
        }

        // A frame wearing another source is rejected by the lease the set
        // is keyed to: the set decides node-plane frames, and only those.
        let summary = summarize(&tcp_frame(
            [100, 64, 0, 9],
            first_endpoint(&baseline, BaselineCategory::Registry),
            443,
        ));
        match verdict(&summary, baseline.rules()) {
            FrameVerdict::Drop(reason) => assert_eq!(reason.rule(), "egress-foreign-source"),
            FrameVerdict::Admit => panic!("a foreign source is not admitted by the set"),
        }
    }
}
