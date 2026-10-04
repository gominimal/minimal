//! The host-side table of every published namespace (NET-138) — the rows the
//! VM host daemon's egress gate decides by (NET-081).
//!
//! On a VM-backed host the guest cannot be trusted to say what its boxes may
//! reach: the in-VM daemon is *inside* the escape boundary, and a process
//! that breaks out of a box into the VM controls it. The per-box,
//! source-addressed egress rules NET-081 asks for therefore live **outside**
//! the VM, in `minvmd`, applied by [`crate::net::egress_gate`] between the
//! guest's shuttle and the switch socket. This module is the table that gate
//! reads: one row per published namespace, holding its name, its addresses on
//! the switch and on the loopback, the ports it admitted, the names it
//! declared, and its compiled [`EgressRules`] — the rules the gate decides
//! every frame by, the same set the in-guest relay applies, now held where
//! nothing inside the VM can change it. The publish half of the gate
//! (NET-081's control verbs) reads the row's ports and names as the records
//! it will admit a switch publish for; the frame half reads the rules alone.
//!
//! The trust boundary is the type boundary. Rows are filled **in this
//! process**, from the host side — the host's own derivation of the guest
//! node's namespace ([`BoxRegistry::register_node_namespace`]), and the
//! client's box declarations carried over the host's control path — and never
//! from anything the guest says. The gate is handed a [`BoxTable`], the
//! read-only view whose only row operations are lookups, so the one component
//! that reads guest frames cannot add, replace, or withdraw a row. The
//! registration path that carries a client's box declarations into this
//! registry is [`crate::control`] — the host daemon's control socket, over
//! which the activating client registers a box and reads the addresses the
//! allocation hands back.
//!
//! This registry is also the proxy's attachment source (NET-133): when the
//! host hands it the attachment table
//! ([`BoxRegistry::feeding_proxy_attachments`]), every box row it publishes
//! is an attachment issued ahead of the row and every retirement takes the
//! attachment with it — the same host-side facts, the same trust boundary,
//! the one writer.
//!
//! One dimension of a row is filled from the in-VM daemon's own reports —
//! the **runtime-admitted ports** (NET-138's sanctioned exception, NET-045's
//! decisions), reported over the daemon's control channel and recorded only
//! inside the grant the row's host-side registration holds: the box's
//! dynamic-ingress stance, its allowed range, the per-row cap, and the
//! per-row admit rate ([`BoxRegistry::admit_runtime_port`]). Everything the
//! guest says still passes that check; a row's other facts stay host-sourced
//! alone.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use sessions::core::egress::EgressRules;
use sessions::core::zone_answer;
use sessions::{DynamicIngress, EgressPolicy, IpProto};
use switch::SwitchSubnet;

use crate::bep_attach::BoxId;

/// The per-row cap on runtime-admitted ports (NET-138): the row's
/// runtime-published set answers to this bound, so a report storm cannot
/// grow a row without limit — the cap is the row-state half of the grant,
/// beside the stance and range the declaration carries. An admit report a
/// row at its cap receives is refused, whatever it names — even a port the
/// row already holds: a full row admits nothing, and a client that retries
/// a lost reply gets the refusal its report could not have changed.
pub(crate) const RUNTIME_PORT_CAP: usize = 256;

/// The per-row admit rate (NET-138): at most this many admit reports are
/// recorded per trailing second. The rate bounds the *reports*, not the
/// ports (the cap bounds the ports): a box that churns its mappings faster
/// than this is a loop, and a loop must not hold the serving thread. Only
/// reports that pass every grant check count toward it — a refusal records
/// nothing and paces nothing — and a withdrawal never counts.
pub(crate) const ROW_ADMIT_RATE_PER_SECOND: usize = 10;

/// The window the admit rate is measured over, matching
/// [`ROW_ADMIT_RATE_PER_SECOND`] one trailing second.
const ADMIT_RATE_WINDOW: std::time::Duration = std::time::Duration::from_secs(1);

/// The allow-list spelling of the absent egress dimension: every address,
/// the compiled rules' `None` meaning as the row's derived allow-list
/// answers it.
const ALLOW_ALL_SUBNET: &str = "0.0.0.0/0";

/// The addresses of one relay's end, as the host reports them: the switch
/// addresses whose relayed traffic that connection carried, for the
/// registry to withdraw by. Reported, not held — the gate has no say over
/// whether a row goes with its report.
type WithdrawalReport = Vec<[u8; 4]>;

/// The guest node namespace's name in the table: the in-VM daemon, whose own
/// root-netns tap [`BoxRegistry::register_node_namespace`] publishes.
const NODE_NAMESPACE: &str = "minimald";

/// The node namespace's row's name under the zone, as
/// [`BoxRegistry::zone_view`] holds it: `minimald.min.internal`, the same
/// name every VM host daemon's table holds its own node's row under. The
/// row never travels the answerer channel (`net::answerer::zone_rows`
/// excludes it): one name for every VM means a second VM's registration of
/// it is refused by the holder's first-writer rule by construction — a
/// standing clash-warn for the normal multi-VM case — so the holder's own
/// node row is the one the zone answers host-side, and inside the guest
/// the node's DNS layer keeps answering the name for its own VM.
#[must_use]
pub fn node_zone_name() -> String {
    zone_name(NODE_NAMESPACE)
}

/// The published rows, keyed by switch address in wire octets — the key the
/// gate's per-frame lookup uses, straight off the frame summary. A `BTreeMap`
/// because the row set's order escapes to diagnostics and to
/// [`BoxTable::rows`], and the same declarations must produce the same order
/// every time (a hash map's would vary run to run).
type Rows = BTreeMap<[u8; 4], Arc<BoxRecord>>;

/// One published namespace's row in the host-side table. Of what it holds,
/// two dimensions decide a frame from this namespace's address: its switch
/// address, the lease the shared verdict checks every frame's source against
/// (NET-084), and its compiled egress rules — beside which the dimensions
/// the frame rules cannot carry travel in the row too: the DNS hosts its
/// declaration named ([`Self::allow_dns_hosts`]), for the gate's DNS
/// admission table to pin the row's destinations from, and whether its box
/// declared a credentialed upstream
/// ([`Self::declares_credentialed_upstream`], NET-134), for the gate to
/// admit the proxy's address by. The rest — its name
/// (diagnostics), its loopback address, the ports it admitted, the names it
/// declared — is the declaration itself, carried for the host-side paths that
/// attach and name the namespace, and for the publish half of the gate, which
/// reads the ports and names as the records a switch publish may carry. Owned
/// outright, so no borrow of a client's declaration survives the registration
/// that built it. Not [`PartialEq`]: the row's runtime half is interior and
/// mutable ([`RowRuntime`]), so no two records the same registration built
/// stay comparable for the record's life.
#[derive(Debug)]
pub struct BoxRecord {
    name: String,
    box_id: BoxId,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: EgressRules,
    resolves_names: bool,
    dns_hosts: Vec<String>,
    credentialed_upstream: bool,
    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant a runtime port report is checked against. Carried from the
    /// host-side registration — the same create inputs the session record
    /// holds — never from the guest: the guest reports, the host decides.
    /// The default an absent declaration carries is [`DynamicIngress::Deny`],
    /// which admits nothing.
    dynamic_ingress: DynamicIngress,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance, the same meaning the session policy's absent range
    /// carries.
    dynamic_range: Option<(u16, u16)>,
    /// The row's runtime-admitted ports and the admit timestamps its rate
    /// is measured by (NET-138): the one row dimension the in-VM daemon's
    /// reports fill, guarded by the grant the two fields above hold.
    /// Interior to the row because reports arrive while the row is
    /// published and shared — the gate reads the ports as the row's
    /// runtime-published set, the read-only row verb answers with them,
    /// and the row's withdrawal takes the whole set with it structurally.
    runtime_ports: Mutex<RowRuntime>,
    /// The row's egress allow-list as derived at registration: the
    /// declaration's `allow_subnets` dimension in its own spelling, or the
    /// allow-all one when the dimension is absent. Carried for the
    /// read-only row verb — a person's surface, where the strings are the
    /// policy as it was declared, not the compiled form only the gate
    /// reads.
    egress_allow_list: Vec<String>,
}

/// Manual because the row's runtime half is interior ([`RowRuntime`]): the
/// derive cannot compare through a mutex, and equality that ignored the
/// half would call two rows with different runtime admissions equal. Two
/// records are equal when every dimension matches, the runtime set under
/// its own lock included — an instantaneous comparison, never a stable
/// ordering across concurrent reports.
impl PartialEq for BoxRecord {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.box_id == other.box_id
            && self.switch_addr == other.switch_addr
            && self.loopback_addr == other.loopback_addr
            && self.admitted_ports == other.admitted_ports
            && self.declared_names == other.declared_names
            && self.egress == other.egress
            && self.resolves_names == other.resolves_names
            && self.dns_hosts == other.dns_hosts
            && self.credentialed_upstream == other.credentialed_upstream
            && self.dynamic_ingress == other.dynamic_ingress
            && self.dynamic_range == other.dynamic_range
            && *self
                .runtime_ports
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                == *other
                    .runtime_ports
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            && self.egress_allow_list == other.egress_allow_list
    }
}

impl Eq for BoxRecord {}

/// A row's mutable runtime half: the ports the in-VM daemon's admit reports
/// recorded — each the port and protocol pair the report named, so one port
/// number published under two protocols is two admissions, not one — and
/// the timestamps of the admits the trailing-second rate is measured by.
/// Guarded by its own mutex, never the row lock: the ports change with the
/// box's runtime publications, while every other row dimension is
/// registration-frozen.
#[derive(Debug, Default, PartialEq, Eq)]
struct RowRuntime {
    ports: Vec<RuntimePort>,
    admits: VecDeque<Instant>,
}

/// One runtime-admitted port: the port number and the protocol it was
/// published under — the pair a report names and a withdrawal removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimePort {
    port: u16,
    proto: IpProto,
}

impl BoxRecord {
    /// The namespace's name — what a diagnostic names a row by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The box's own id (BEP-070): minted once for this creation — by
    /// the registration that published the row, or taken from the id a
    /// re-registration presented — with its random bytes from the host's
    /// OS CSPRNG. Unique per creation, so a box recreated with the same
    /// name and addresses carries a different id, and the id never
    /// returns to use: a revocation scoped to it stays scoped forever.
    /// This is what the proxy's attachment names the box by and a
    /// delivered connection's header carries (NET-133).
    #[must_use]
    pub fn box_id(&self) -> BoxId {
        self.box_id
    }

    /// The namespace's address on the switch: the lease its frames must carry
    /// (NET-084) and the key the gate resolves a frame's source through.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The namespace's address on the guest's loopback.
    #[must_use]
    pub fn loopback_addr(&self) -> Ipv4Addr {
        self.loopback_addr
    }

    /// The ports this namespace admitted, in the order the declaration
    /// carried them.
    ///
    /// Two readings, both of them the declaration's own and neither one the
    /// frame verdict's:
    ///
    /// * An **ingress** dimension — what may be sent *to* this namespace,
    ///   which the host attaches it by on the registration path (T66's
    ///   client-driven one, the same path that fills this table). The frame
    ///   verdict reads [`Self::egress`] alone and never this.
    /// * The **publish** dimension — the ports a switch publish at this
    ///   namespace's address may name: the host-side listener a forwarder
    ///   binds, the end the registration wire carries. A mapping's inside
    ///   end is not a record of the publish — it is the port the forwarder
    ///   dials on the target, governed by the target's own ingress
    ///   declaration inside the VM, which no row here is compiled from. The
    ///   gate's publish decision (NET-081's control verbs) reads this and
    ///   [`Self::declared_names`] as the records it admits a publish by;
    ///   nothing outside the declaration is publishable, so a row that names
    ///   no ports publishes none.
    ///
    /// It is carried in the row because NET-138's row holds a namespace's
    /// whole declaration, where both the attaching side and the publish
    /// decision reach it without a second table.
    #[must_use]
    pub fn admitted_ports(&self) -> &[u16] {
        &self.admitted_ports
    }

    /// The zone names this namespace declared, in the order the declaration
    /// carried them — the publish dimension's name half: the records a
    /// `dns/add` at this namespace's address may carry. A row that names none
    /// publishes none.
    #[must_use]
    pub fn declared_names(&self) -> &[String] {
        &self.declared_names
    }

    /// The namespace's compiled egress rules — the decision the gate applies
    /// to every frame leaving the VM from its address.
    #[must_use]
    pub fn egress(&self) -> &EgressRules {
        &self.egress
    }

    /// Whether the namespace's own declaration named DNS hosts: `true` when
    /// [`Self::allow_dns_hosts`] is non-empty. Such a row has destinations
    /// its compiled frame rules cannot carry — the addresses its declared
    /// names resolve to — so its undeclared-destination drops are decided
    /// by the host-side DNS admission table
    /// ([`crate::net::dns_pins`], NET-081 deciding NET-066's admission
    /// outside the VM) against the answers its own lookups received. `false`
    /// — no names declared — means the frame rules are the whole decision,
    /// and the table is never consulted for the row.
    #[must_use]
    pub fn resolves_names(&self) -> bool {
        self.resolves_names
    }

    /// The DNS hostnames the namespace's declaration named in
    /// `egress.allow_dns_hosts`, as the client spelled them — the one egress
    /// dimension that compiles to nothing in the frame rules, because a
    /// name is not an address: NET-066 enforces it as the addresses the
    /// box's own lookups resolved to, admitted for the shared admission
    /// window. The host-side admission table reads this — it pins only
    /// answers to a name the row declared here, so every pin it holds is an
    /// answer the box's own query received. Empty for a row that declared
    /// none: a name grant is earned by an entry, never by an absent field
    /// (the dns-gate module doc records why `None` is not allow-all names).
    #[must_use]
    pub fn allow_dns_hosts(&self) -> &[String] {
        &self.dns_hosts
    }

    /// Whether this box's declaration named a credentialed upstream
    /// (NET-134): `true` marks the Box Egress Proxy's listener as this
    /// box's infrastructure — the one destination its compiled frame rules
    /// never decide, because the credentials the proxy redeems are the
    /// lane's own and no egress rule of the box's says anything about them.
    /// `false`, the absent declaration, is no lane: the proxy's address
    /// stays under the box-to-host default-deny like any other host-side
    /// destination, whatever the box's rules would allow.
    ///
    /// The gate reads this beside the row's rules ([`crate::net::egress_gate`]),
    /// never through them: the declaration is a fact about the box, reduced
    /// from the session policy's own field at registration — nothing the
    /// guest says can add a lane to a row behind the gate's back.
    #[must_use]
    pub fn declares_credentialed_upstream(&self) -> bool {
        self.credentialed_upstream
    }

    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant a runtime port report is checked against ([`Self::admit` is
    /// not this — that is the registry's]). `allow` and `ask` are the two
    /// stances that can record a report in range; `deny`, the default,
    /// admits none.
    #[must_use]
    pub fn dynamic_ingress(&self) -> DynamicIngress {
        self.dynamic_ingress
    }

    /// The range the stance admits runtime ports in, inclusive at both
    /// ends — the grant's range half. `None` permits nothing even under an
    /// `allow` stance.
    #[must_use]
    pub fn dynamic_range(&self) -> Option<(u16, u16)> {
        self.dynamic_range
    }

    /// The row's runtime-admitted ports, distinct port numbers in report
    /// order: the runtime half of the set the gate admits the box's
    /// publications by — the declared half is [`Self::admitted_ports`] —
    /// and the read-only row verb's answer's runtime dimension. Reported
    /// by the in-VM daemon within the grant the registration holds
    /// ([`BoxRegistry::admit_runtime_port`]), removed by its withdrawal
    /// reports, and gone with the row itself when the row is withdrawn.
    #[must_use]
    pub fn runtime_port_numbers(&self) -> Vec<u16> {
        let runtime = self
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut seen = Vec::new();
        for port in runtime.ports.iter().map(|reported| reported.port) {
            if !seen.contains(&port) {
                seen.push(port);
            }
        }
        seen
    }

    /// The row's egress allow-list, derived at registration from the same
    /// declaration the frame rules compiled from: the `allow_subnets`
    /// dimension's own spelling when the declaration named one, and the
    /// allow-all one when it did not. The read-only row verb's answer — a
    /// person's surface, so the list is the policy as it was declared, not
    /// the compiled form the gate decides by (the deny dimension stays the
    /// gate's to apply; this names what the allow dimension admits).
    #[must_use]
    pub fn egress_allow_list(&self) -> &[String] {
        &self.egress_allow_list
    }
}

/// A namespace's declaration as it arrives on the host, before any frame
/// exists: the facts a row is compiled from. Builder-shaped (the crate's
/// `VmEgressPolicy` style) because the addresses alone make a namespace and
/// everything else is optional.
#[derive(Debug, Clone)]
pub struct BoxRegistration {
    name: String,
    box_id: Option<BoxId>,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: Option<EgressPolicy>,
    credentialed_upstream: Option<sessions::CredentialedUpstream>,
    dynamic_ingress: Option<DynamicIngress>,
    dynamic_allowed_range: Option<(u16, u16)>,
}

impl BoxRegistration {
    /// A declaration for the namespace `name`, addressed at `switch_addr` on
    /// the switch and `loopback_addr` on the guest's loopback. The egress
    /// policy is absent (allow-all, the shipped default) until
    /// [`with_egress_policy`](Self::with_egress_policy) declares one, and
    /// the box's id is minted at registration
    /// ([`crate::bep_attach::mint_box_id`]).
    #[must_use]
    pub fn new(name: impl Into<String>, switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Self {
        Self {
            name: name.into(),
            box_id: None,
            switch_addr,
            loopback_addr,
            admitted_ports: Vec::new(),
            declared_names: Vec::new(),
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        }
    }

    /// The ports this namespace admitted — the ingress **and** publish
    /// dimensions [`BoxRecord::admitted_ports`] documents, not a dimension
    /// the gate's frame verdict reads.
    #[must_use]
    pub fn with_admitted_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.admitted_ports = ports.into_iter().collect();
        self
    }

    /// The zone names this namespace declared — the name half of the publish
    /// dimension [`BoxRecord::declared_names`] documents. Names are matched
    /// exactly, as the client's own client spells them.
    #[must_use]
    pub fn with_declared_names(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.declared_names = names.into_iter().map(Into::into).collect();
        self
    }

    /// The namespace's egress policy, as the client declared it at launch.
    /// Compiled at registration; the declaration itself is not retained.
    #[must_use]
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress = Some(policy);
        self
    }

    /// The namespace's declaration of a credentialed upstream (NET-134):
    /// `Some` marks the Box Egress Proxy's listener as this box's
    /// infrastructure, so the gate admits its address beside — never
    /// through — whatever egress rules the declaration also carries. The
    /// declaration is reduced to a lane in the row; its own content is the
    /// proxy document's to extend, so nothing of it is retained here.
    #[must_use]
    pub fn with_credentialed_upstream(
        mut self,
        declaration: sessions::CredentialedUpstream,
    ) -> Self {
        self.credentialed_upstream = Some(declaration);
        self
    }

    /// The box's dynamic-ingress grant (NET-045, NET-138): the stance and
    /// the range a runtime port report is checked against — the row's own
    /// copy of the same create inputs the session record holds, carried at
    /// registration so the host decides every report against a fact the
    /// guest cannot change. `None` for the stance is the declaration's
    /// `deny` default; `None` for the range permits nothing under any
    /// stance.
    #[must_use]
    pub fn with_dynamic_ingress(
        mut self,
        stance: DynamicIngress,
        range: Option<(u16, u16)>,
    ) -> Self {
        self.dynamic_ingress = Some(stance);
        self.dynamic_allowed_range = range;
        self
    }
}

/// A box declaration as the activating client carries it over the host's
/// control socket: the facts a row is compiled from, without the addresses —
/// a client-driven registration allocates those on the host, from the
/// address plan this registry's switch serves, and hands them back with the
/// row ([`BoxRegistry::register_client_box`]).
#[derive(Debug, Clone)]
pub struct ClientBoxSpec {
    /// The box's name: what the row is named by, and the name the create
    /// request will carry — a box's id on the host is its name.
    pub name: String,
    /// The external ports the box's ingress rules admit, as the client
    /// expanded them.
    pub ingress_ports: Vec<u16>,
    /// The box's egress policy, as the client declared it. Absent compiles
    /// the allow-all default, the same meaning the create request's absent
    /// policy carries.
    pub egress: Option<EgressPolicy>,
    /// The box's declaration of a credentialed upstream (NET-134), carried
    /// from the session's policy: `Some` makes the Box Egress Proxy's
    /// listener this box's infrastructure — reachable whatever the egress
    /// rules say — while `None` is no lane, and the proxy's address stays
    /// refused under the box-to-host default-deny. The one field a client
    /// that predates NET-134 sends absent, every time.
    pub credentialed_upstream: Option<sessions::CredentialedUpstream>,
    /// The box's dynamic-ingress stance (NET-045): the stance half of the
    /// grant the row holds a runtime port report against. `None` is the
    /// declaration's `deny` default — a client that predates the grant
    /// fields registers a row that admits no runtime port, exactly as one
    /// whose declaration said `deny` does.
    pub dynamic_ingress: Option<DynamicIngress>,
    /// The range the stance admits runtime ports in, inclusive at both
    /// ends. `None` permits nothing even under an `allow` stance.
    pub dynamic_allowed_range: Option<(u16, u16)>,
}

/// The run of `subnet`'s address plan the host hands registered boxes from:
/// the PTask run's upper half, `[midpoint + 1, last_ptask]`, as an inclusive
/// `(first, last)` pair — one address more than the daemon's reserve below
/// it, a PTask run holding an odd number of addresses.
///
/// The plan's PTask run is split into two disjoint sub-runs so the two
/// allocators that draw on it cannot meet: this host hands a registered box
/// only from the upper half, and the in-VM daemon self-allocates task
/// sandboxes and unregistered boxes from the lower half — the run below this
/// hand-out run. The daemon's half is the same midpoint rule mirrored in
/// `minimald::net::self_allocation_run`; one rule, two statements, so change
/// both together — each side's tests pin the default plan's split literally.
///
/// This is the interim allocation shape (NET-138): the daemon keeps
/// self-allocating from the reserve until the task registering every live
/// box host-side retires daemon-side allocation, after which a daemon with a
/// control socket draws nothing — every own-address box arrives handed.
#[must_use]
fn hand_out_run(subnet: SwitchSubnet) -> (u32, u32) {
    let first = subnet.first_ptask();
    let last = subnet.last_ptask();
    let reserve_len = (last - first).div_ceil(2);
    (first + reserve_len, last)
}

/// Why a client-driven registration could not be allocated. Both runs a
/// box address comes from — the plan's switch lease run and the published
/// loopback slice — are finite; exhausting one is an answer to hand back
/// over the control socket, not a panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AllocationError {
    /// Every switch address in the plan's lease run is published.
    #[error("the switch's address plan is exhausted; no box address remains")]
    SwitchExhausted,
    /// Every address in the loopback slice this subnet's switch publishes
    /// at is handed out.
    #[error("the host's loopback slice is exhausted; no published address remains")]
    LoopbackExhausted,
    /// The address plan does not serve this registry's subnet, so no box
    /// address can be allocated against it. An explicit registration
    /// ([`BoxRegistry::register`]) still works: it brings its own
    /// addresses.
    #[error("the address plan does not serve subnet {0}; no box address can be allocated")]
    UnplannedSubnet(SwitchSubnet),
    /// The id minted for the registration is already held by a live row or
    /// attachment: one id names one box (BEP-070), so the registration is
    /// refused — never re-minted — before any address is spent, so the
    /// refusal leaves no new fact on the host.
    #[error(
        "box id {} is already held by a live row or attachment",
        crate::bep_attach::BoxIdText(id)
    )]
    CollidingBoxId {
        /// The id a live row or attachment already holds.
        id: BoxId,
    },
}

/// Why a client-driven withdrawal was refused. The pair a withdrawal
/// presents is the proof that its client is the row's creator (T66), so a
/// refusal is the daemon saying the proof does not match the row the
/// switch address publishes — never a failure of the goal state, which
/// [`BoxRegistry::withdraw_client_box`] reports as `Ok(None)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WithdrawError {
    /// A row is published at the switch address under another box's name:
    /// the requesting client is not its creator.
    #[error(
        "the row at switch address {switch_addr} is held by box {held_name:?}, \
         not by the withdrawing {asked_name:?}"
    )]
    NotTheCreatorsRow {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The name the published row carries.
        held_name: String,
        /// The name the withdrawal presented.
        asked_name: String,
    },
    /// The row at the switch address carries the requested name but another
    /// loopback address than the pair presented: not the pair the
    /// registration handed back.
    #[error(
        "the row at switch address {switch_addr} carries loopback address \
         {held_loopback}, not the {asked_loopback} the withdrawal presented"
    )]
    NotTheHandedPair {
        /// The switch address the withdrawal named.
        switch_addr: Ipv4Addr,
        /// The loopback address the published row carries.
        held_loopback: Ipv4Addr,
        /// The loopback address the withdrawal presented.
        asked_loopback: Ipv4Addr,
    },
}

/// Why an admit report was refused against the host-held grant (NET-138):
/// the one refusal the in-VM daemon's publish unwinds by. Every variant
/// names the box whose row was asked about — except the first, which names
/// the address no row answered at, because the box is exactly what the
/// report could not prove — and the port and protocol the report carried,
/// so the refusal the guest unwinds its publish on says what was refused
/// and which check refused it, in one sentence the wire carries verbatim.
///
/// Refused reports record nothing: not the port, not a rate timestamp, not
/// a fact the host did not already hold. Not `Copy`: every variant that
/// names a box carries its [`String`] name, and the refusal is built once,
/// answered with, and dropped.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PortReportRefusal {
    /// No row is held at the switch address the report named — the box was
    /// never registered, its row was withdrawn, or the daemon restarted
    /// since: the guest cannot invent a row by reporting at an address.
    #[error(
        "no box row is held at switch address {switch_addr}; the reported port {port} \
         records nowhere"
    )]
    NoRow {
        /// The switch address the report named.
        switch_addr: Ipv4Addr,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's dynamic-ingress stance is `deny` — or the declaration
    /// carried no stance, its default — which admits no runtime port.
    #[error("box {name} declared dynamic ingress deny; its runtime port reports record nothing")]
    DenyStance {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The row's stance is `allow` or `ask` but its declaration named no
    /// allowed range, and an absent range permits nothing.
    #[error("box {name} declared no dynamic allowed range; no runtime port is permitted")]
    NoAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
    },
    /// The reported port is outside the row's allowed range, inclusive at
    /// both ends.
    #[error(
        "runtime port {port} is outside box {name}'s allowed range \
         {}-{}",
        range.0,
        range.1
    )]
    OutsideAllowedRange {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The row's allowed range, inclusive at both ends.
        range: (u16, u16),
    },
    /// The row already holds the per-row cap of runtime-admitted ports
    /// ([`RUNTIME_PORT_CAP`]).
    #[error(
        "box {name} already holds {cap} runtime-admitted ports, its per-row cap; \
         the reported port {port} records nothing"
    )]
    RowCapReached {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The cap the row reached.
        cap: usize,
    },
    /// The row is over its per-row admit rate
    /// ([`ROW_ADMIT_RATE_PER_SECOND`] per trailing second).
    #[error(
        "box {name} is over its per-row admit rate ({rate} per second); the reported \
         port {port} records nothing"
    )]
    RateExceeded {
        /// The name the row was registered under.
        name: String,
        /// The port the report carried.
        port: u16,
        /// The protocol the report carried.
        proto: IpProto,
        /// The rate the row is over.
        rate: usize,
    },
}

/// The writable half of the host-side table, held by the host process: the
/// registration surface — the host's own node-namespace row, and T66's
/// client-driven path — and the source of the read-only [`BoxTable`] the
/// gate reads.
///
/// Cheap to clone, and every clone shares the rows, the allocation cursors,
/// and the withdrawal channel: the table the gate holds is the same one every
/// later registration lands in, which is how a box published after the gate
/// started is decided by its rules from that moment on, an address a
/// registration takes on one clone is never handed twice, and a report any
/// handle files reaches the one drainer. The subnet a registry is built with
/// fixes the address plan its rows compile against — the resolver the
/// carve-out is keyed to, the node address, and the runs the client-driven
/// allocation draws from — so it must be the same subnet the gate's switch
/// serves.
#[derive(Debug)]
pub struct BoxRegistry {
    subnet: SwitchSubnet,
    rows: Arc<RwLock<Rows>>,
    /// The switch addresses whose rows this daemon has marked stopped —
    /// namespaces whose declarations stay published while they are not
    /// running, keyed by the row's own key and shared by every clone.
    stopped: Arc<RwLock<BTreeSet<[u8; 4]>>>,
    /// The table's change pings: one `()` to every live subscriber whenever
    /// a row lands, goes, or is marked stopped. The host answerer
    /// ([`crate::net::answerer`]) subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and the zone-table dump does
    /// ([`crate::diag`]). Senders whose subscriber is gone are pruned on
    /// the next ping, so a dead subscriber is never held past one change.
    table_pings: Arc<Mutex<Vec<std::sync::mpsc::Sender<()>>>>,
    /// The sending end of the withdrawal reports, cloned into every
    /// [`BoxTable`] this registry hands out — one channel for the whole
    /// registry, whatever handle files a report into it.
    withdrawal_reports: std::sync::mpsc::Sender<WithdrawalReport>,
    /// The receiving end, taken once — by [`Self::spawn_withdrawal_drainer`]
    /// or, in tests, by whatever wants to read the reports directly.
    withdrawal_reports_rx: Mutex<Option<std::sync::mpsc::Receiver<WithdrawalReport>>>,
    /// The next switch address the client-driven allocation hands out,
    /// shared by every clone of this registry. Draws from the hand-out run
    /// — the plan run's upper half, above the daemon's self-allocation
    /// reserve (`hand_out_run`) — never from the reserve itself.
    next_switch_addr: Arc<AtomicU32>,
    /// The next published loopback address the client-driven allocation
    /// hands out, shared the same way.
    next_loopback_addr: Arc<AtomicU32>,
    /// The loopback slice this subnet's switch publishes at, when the
    /// address plan serves it: the run [`Self::register_client_box`]
    /// allocates published addresses from. `None` for a subnet the plan
    /// does not serve — such a registry still holds explicit registrations
    /// (the node's own row among them), it just cannot allocate for a
    /// client box.
    loopback_slice: Option<switch::LoopbackSlice>,
    /// The proxy's attachment table this registry feeds (NET-133), when the
    /// host handed one over: every box row published here is an attachment
    /// first and every row retired here retires its attachment with it.
    /// `None` for a registry that feeds no proxy — a table-less registry
    /// still publishes rows, it just gives no attachments.
    attachments: Option<crate::bep_attach::Attachments>,
}

/// A clone shares the live rows, the allocation cursors, and the withdrawal
/// channel but not the receiver: only the registry that created the channel —
/// the one [`Self::spawn_withdrawal_drainer`] (or a test) drains — holds the
/// receiving end, so a clone can register, allocate, and file reports like
/// the original but has nothing to take.
impl Clone for BoxRegistry {
    fn clone(&self) -> Self {
        BoxRegistry {
            subnet: self.subnet,
            rows: self.rows.clone(),
            stopped: Arc::clone(&self.stopped),
            table_pings: Arc::clone(&self.table_pings),
            withdrawal_reports: self.withdrawal_reports.clone(),
            withdrawal_reports_rx: Mutex::new(None),
            next_switch_addr: Arc::clone(&self.next_switch_addr),
            next_loopback_addr: Arc::clone(&self.next_loopback_addr),
            loopback_slice: self.loopback_slice,
            attachments: self.attachments.clone(),
        }
    }
}

impl BoxRegistry {
    /// An empty registry for a switch serving `subnet`. Every row registered
    /// here compiles its lease from its own switch address and the resolver
    /// carve-out from this subnet, so `subnet` must be the one the switch was
    /// configured with.
    #[must_use]
    pub fn new(subnet: SwitchSubnet) -> Self {
        let (reports, reports_rx) = std::sync::mpsc::channel();
        let loopback_slice = switch::AddressPlan::default().loopback_slice_for_switch(subnet);
        Self {
            subnet,
            rows: Arc::new(RwLock::new(BTreeMap::new())),
            stopped: Arc::new(RwLock::new(BTreeSet::new())),
            table_pings: Arc::new(Mutex::new(Vec::new())),
            withdrawal_reports: reports,
            withdrawal_reports_rx: Mutex::new(Some(reports_rx)),
            next_switch_addr: Arc::new(AtomicU32::new(hand_out_run(subnet).0)),
            next_loopback_addr: Arc::new(AtomicU32::new(
                loopback_slice.map_or(0, |slice| u32::from(slice.first())),
            )),
            loopback_slice,
            attachments: None,
        }
    }

    /// Hands this registry the proxy's attachment table to feed
    /// (NET-133): from here on every box row it publishes is an attachment
    /// issued ahead of the row — the proxy holds the box before its first
    /// connection could arrive — and every row it retires takes the
    /// attachment with it, ahead of the row's own removal. Returns `self`,
    /// for the supervisor's call chain.
    ///
    /// The table is the host's own; feeding it is the registry's one write
    /// path, so the attachments stay sourced from the host-side creator
    /// alone: nothing the guest says reaches either table (NET-138's
    /// boundary, which NET-133 borrows for the proxy).
    #[must_use]
    pub fn feeding_proxy_attachments(
        mut self,
        attachments: crate::bep_attach::Attachments,
    ) -> Self {
        self.attachments = Some(attachments);
        self
    }

    /// The subnet this registry's rows are addressed on.
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Publishes one namespace: compiles the declaration into a row keyed by
    /// its switch address — the lease the shared verdict checks every
    /// frame's source against (NET-084) — and returns it. Registering an
    /// address that is already published replaces that row with the newest
    /// declaration, whatever it holds: the table compares no policy against
    /// the row it holds — a rule set's absent dimensions are allow-all, so
    /// there is not even a widest one to rank against — and a re-registration
    /// can widen a namespace's reach as readily as narrow it. Whether a
    /// re-declaration may widen is the registering side's contract to enforce
    /// (T66's client-driven path, which decides whether re-declaring a live
    /// namespace is even possible); what this table enforces is NET-138's
    /// boundary — only the host process holding this registry can publish at
    /// all, so nothing inside the VM can change a row behind the gate's back.
    ///
    /// A row that declared DNS hosts carries those names in the row itself
    /// ([`BoxRecord::allow_dns_hosts`]), beside the rules: the name-based
    /// admission is decided against them, on the host, by the gate's DNS
    /// admission table ([`crate::net::dns_pins`]).
    ///
    /// # Panics
    ///
    /// Never: the row lock is only ever held across this map update, never
    /// across a panic.
    pub fn register(&self, registration: BoxRegistration) -> Arc<BoxRecord> {
        // The name-based admission lives beside the frame rules, not in
        // them: whether a row's undeclared destinations are the DNS
        // admission table's to decide is the declaration's own fact, read
        // off the policy here and carried in the row for the gate's table
        // to pin from.
        let dns_hosts = registration
            .egress
            .as_ref()
            .and_then(|policy| policy.allow_dns_hosts.as_ref())
            .cloned()
            .unwrap_or_default();
        let resolves_names = !dns_hosts.is_empty();
        // The box's own id (BEP-070): the one a client-driven registration
        // minted and checked ([`Self::register_client_box`]), or a fresh
        // UUIDv7 minted here for this creation — never a counter, never a
        // digest of the declaration below, never one a client presented.
        // Minted once, before anything else, so the row and the attachment
        // it issues hold the one identity this registration created the
        // box with.
        let box_id = registration
            .box_id
            .unwrap_or_else(crate::bep_attach::mint_box_id);
        // The row's derived allow-list: the declaration's `allow_subnets`
        // dimension in its own spelling — `None`, the absent dimension, is
        // allow-all, the same meaning the compiled rules carry.
        let egress_allow_list = registration
            .egress
            .as_ref()
            .and_then(|policy| policy.allow_subnets.clone())
            .unwrap_or_else(|| vec![ALLOW_ALL_SUBNET.to_string()]);
        // The dynamic-ingress grant (NET-045, NET-138): the stance and range
        // the host holds every runtime port report against, from the same
        // create inputs the session record holds. Absent is deny with no
        // range — the row a pre-grant client registers admits no runtime
        // port.
        let dynamic_ingress = registration.dynamic_ingress.unwrap_or(DynamicIngress::Deny);
        let dynamic_range = registration.dynamic_allowed_range;
        let record = Arc::new(BoxRecord {
            name: registration.name,
            box_id,
            // The lease the compiled rules check is the row's own switch
            // address: the one source its frames may carry. The resolver the
            // carve-out is keyed to is the switch this registry was built for
            // — the resolver Minimal owns for every box on it.
            egress: EgressRules::from_policy(
                registration.egress.as_ref(),
                self.subnet.dns_server().octets(),
                registration.switch_addr.octets(),
            ),
            resolves_names,
            dns_hosts,
            // NET-134: the lane is the one egress dimension that compiles
            // to nothing in the frame rules — a declaration, not a rule —
            // so it travels in the row itself, reduced to the fact the
            // gate reads beside those rules.
            credentialed_upstream: registration.credentialed_upstream.is_some(),
            dynamic_ingress,
            dynamic_range,
            // A row starts with no runtime-admitted ports: the box's
            // runtime publications are reported one by one, inside the
            // grant, and a re-registration at the same address starts the
            // set empty again — the newest declaration never inherits the
            // box it replaced's runtime facts.
            runtime_ports: Mutex::new(RowRuntime::default()),
            egress_allow_list,
            switch_addr: registration.switch_addr,
            loopback_addr: registration.loopback_addr,
            admitted_ports: registration.admitted_ports,
            declared_names: registration.declared_names,
        });
        // NET-133: the box's proxy attachment is issued from the row's own
        // host facts — the name, both addresses, and the box's own id
        // minted above — and issued **before** the row is visible, so the
        // proxy holds the box ahead of its first connection: the box-egress
        // pool's listeners are partitioned by rows, a delivered connection
        // can only exist once the row made the box a share, and the share
        // comes a pool turn after the row. The guest node's own namespace
        // is not a box: its row buys no share in the pool (the same one
        // address `RegisteredBoxes` excludes) and no attachment either —
        // the plan keeps that address outside the run every client box is
        // handed from, so excluding it names exactly the node row.
        if let Some(attachments) = &self.attachments
            && record.switch_addr != self.subnet.daemon_ip()
        {
            attachments.issue(
                record.name(),
                record.box_id(),
                record.switch_addr,
                record.loopback_addr,
                record.declares_credentialed_upstream(),
            );
        }
        self.rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .insert(record.switch_addr.octets(), Arc::clone(&record));
        // The newest declaration is a namespace that is running: whatever
        // stopped mark the address carried is stale now, and the change is
        // a ping every subscriber re-derives from.
        self.stopped
            .write()
            .expect("the stopped set's lock is never held across a panic, so it cannot be poisoned")
            .remove(&record.switch_addr.octets());
        self.ping();
        record
    }

    /// Withdraws the row published for `switch_addr`, returning it when one
    /// was held. From here on the gate holds no namespace at that address, and
    /// no rules are decided by it: withdrawing is how the host retires a
    /// namespace's declaration, never a way to leave its address attributed.
    ///
    /// What the address's frames do next is unconditional
    /// ([`crate::net::egress_gate`]): an address inside the plan's lease block
    /// is an unregistered source the gate drops (NET-085), so a withdrawal
    /// inside that block ends the address's reach at once, and outside it the
    /// frames were already an unknown source's refusal (NET-081's failure
    /// case). The row is gone either way, and a re-registration starts from
    /// the newest declaration.
    pub fn withdraw(&self, switch_addr: Ipv4Addr) -> Option<Arc<BoxRecord>> {
        // The box's end is observed here — the drainer's arrival of the
        // relay's report — so the withdrawal's own line measures itself
        // against this instant (NET-133's bound).
        self.retire_proxy_attachment(switch_addr, Instant::now());
        let removed = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .remove(&switch_addr.octets());
        self.retired(&removed);
        removed
    }

    /// Retires the proxy attachment issued for `switch_addr`, when this
    /// registry feeds a table and one is held: the host-side half of the
    /// requirement's "the attachment is the box's row, withdrawn with it"
    /// (NET-133). Retired **before** the row it goes with, so a delivery
    /// racing the box's end finds no attachment and is refused rather than
    /// attributed to a namespace the table no longer holds.
    ///
    /// `box_ended` is the instant this process observed the box's end —
    /// the drainer's arrival of the relay's report, or the creator's
    /// withdrawal request reaching the control socket — and the one line
    /// the withdrawal logs measures itself against, so a tail can see a
    /// withdrawal that did not keep the requirement's bound.
    fn retire_proxy_attachment(&self, switch_addr: Ipv4Addr, box_ended: Instant) {
        if let Some(attachments) = &self.attachments {
            attachments.withdraw(switch_addr, box_ended);
        }
    }

    /// Registers a client box: allocates its switch address from the plan's
    /// lease run and its published loopback address from the slice this
    /// subnet's switch serves at, then fills the row from `spec` — the same
    /// compile [`Self::register`] does, addressed at the allocation — and
    /// returns the row, whose addresses are the ones to hand back over the
    /// control socket.
    ///
    /// Addresses are handed out in plan order from shared cursors: each
    /// registration takes the next address the plan has not spent, and no
    /// address is ever handed to two rows (clones of this registry share the
    /// cursors, so that holds across every clone). The switch cursor draws
    /// only from the hand-out run — the plan run's upper half, above the
    /// daemon's self-allocation reserve (`hand_out_run`) — so the two
    /// allocators cannot meet. The runs are finite — the hand-out run ends
    /// at the plan's last PTask address, the slice ends where the plan's
    /// next switch begins — and exhausting one is the [`AllocationError`]
    /// the control socket hands back as the registration's failure.
    ///
    /// An address is spent for good: withdrawing its row does not return it
    /// to the cursor, and neither does an allocation whose other run is
    /// exhausted. A spent address's host-side state — the gate's
    /// rate-limit slots, the switch's static lease table — is keyed by it,
    /// and re-issuing it to a new box would inherit all of that; a fresh
    /// address starts clean.
    ///
    /// While a row this registration filled stands, the box's frames are
    /// decided by its rules; a box with **no** row — one whose registration
    /// never reached the daemon, or whose row was withdrawn — is an
    /// unregistered source the gate drops unconditionally (NET-085), so no
    /// flip that lands with the last row source (T66's follow-up) changes
    /// it, and this registration makes none.
    ///
    /// The box's id is always minted here, for this creation
    /// ([`crate::bep_attach::mint_box_id`]): a spec carries none, so no
    /// client can present an id, and a re-registration under the same
    /// name and addresses is a new box with a new id. Ids are never reused.
    /// A mint that collides with an id a live row or attachment already
    /// holds is refused ([`AllocationError::CollidingBoxId`], BEP-070) —
    /// never re-minted — before any address is spent, and said as one warn
    /// line naming the id.
    pub fn register_client_box(
        &self,
        spec: ClientBoxSpec,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        self.register_client_box_as(spec, crate::bep_attach::mint_box_id())
    }

    /// [`Self::register_client_box`] with the freshly minted `id` it
    /// creates the box as: the one door the collision check guards, split
    /// out so a test can drive a colliding mint.
    fn register_client_box_as(
        &self,
        spec: ClientBoxSpec,
        id: BoxId,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
        // One id names one box (BEP-070): the check runs before any
        // address is spent, so a refused registration leaves nothing
        // behind — no row, no share, no attachment, no spent address.
        // A colliding mint is refused, never re-minted: a collision means
        // the mint is broken, and a second draw would hide it.
        if self.holds_box_id(id) {
            tracing::warn!(
                box_id = %crate::bep_attach::BoxIdText(&id),
                "refused a box registration whose id a live row or attachment already holds"
            );
            return Err(AllocationError::CollidingBoxId { id });
        }
        let slice = self
            .loopback_slice
            .ok_or(AllocationError::UnplannedSubnet(self.subnet))?;
        let (hand_out_first, hand_out_last) = hand_out_run(self.subnet);
        let switch_addr = take_next(&self.next_switch_addr, hand_out_first, hand_out_last)
            .ok_or(AllocationError::SwitchExhausted)?;
        let loopback_addr = take_next(
            &self.next_loopback_addr,
            u32::from(slice.first()),
            u32::from(slice.last()),
        )
        .ok_or(AllocationError::LoopbackExhausted)?;
        let mut registration = BoxRegistration::new(spec.name, switch_addr, loopback_addr)
            .with_admitted_ports(spec.ingress_ports);
        if let Some(policy) = spec.egress {
            registration = registration.with_egress_policy(policy);
        }
        if let Some(declaration) = spec.credentialed_upstream {
            registration = registration.with_credentialed_upstream(declaration);
        }
        // The dynamic-ingress grant rides the same registration: the
        // stance's absent default is deny, so a pre-grant client's row
        // admits no runtime port — and a range declared without a stance
        // changes nothing under it, exactly as it does inside the VM.
        if let Some(stance) = spec.dynamic_ingress {
            registration = registration.with_dynamic_ingress(stance, spec.dynamic_allowed_range);
        }
        registration.box_id = Some(id);
        Ok(self.register(registration))
    }

    /// Whether some live row or attachment already holds `id` (BEP-070):
    /// the collision check every client-driven registration runs on the id
    /// it minted. It covers live records only, which is every record the
    /// host holds an id in today. An id is never reused because no client
    /// can present one and the mint never draws the same UUIDv7 twice, not
    /// because this check remembers spent ids. No box or revocation record
    /// outlives its box on this host yet, so a record type that does — a
    /// revocation scoped to an id, a retained box record — joins this check
    /// when it lands.
    fn holds_box_id(&self, id: BoxId) -> bool {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        if rows.values().any(|record| record.box_id == id) {
            return true;
        }
        self.attachments
            .as_ref()
            .is_some_and(|attachments| attachments.holds_id(id))
    }

    /// Withdraws the client box's row when the pair `(name, switch_addr,
    /// loopback_addr)` proves its client is the row's creator, returning the
    /// row removed — `Ok(None)` when no row is published at `switch_addr` at
    /// all: the row is already withdrawn, or the daemon restarted since the
    /// registration, and either way the goal state — nothing admits the
    /// pair's addresses by a row — already holds. Lookup, proof, and removal
    /// happen under one write of the row lock, so no registration can land
    /// between the proof and the removal.
    ///
    /// The proof is the same pair the registration handed back
    /// ([`ClientBoxSpec`]'s allocation), which only the registering session's
    /// record carries; a row published under another name or another
    /// loopback is not the requesting client's to remove and is refused with
    /// [`WithdrawError`]. The withdrawn addresses are not returned to the
    /// allocation cursors — spent for good, as [`Self::register_client_box`]
    /// documents — and what their frames do next is the gate phase's to say
    /// ([`Self::withdraw`]). The box's proxy attachment goes with the row
    /// (NET-133), retired under the same row lock that removes it.
    ///
    /// This is the host-side half of the withdrawal a destroyed or failed
    /// activation sends over the control socket
    /// ([`crate::control::serve_request`]) — the guest daemon never asserts
    /// or withdraws address→box facts (NET-138).
    pub fn withdraw_client_box(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
    ) -> Result<Option<Arc<BoxRecord>>, WithdrawError> {
        #[expect(
            clippy::unwrap_in_result,
            reason = "the expect is the lock's poison guard, not this function's error \
                      handling: the row lock is never held across a panic, so it cannot be \
                      poisoned"
        )]
        let mut rows = self
            .rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let Some(record) = rows.get(&switch_addr.octets()) else {
            return Ok(None);
        };
        if record.name() != name {
            return Err(WithdrawError::NotTheCreatorsRow {
                switch_addr,
                held_name: record.name().to_string(),
                asked_name: name.to_string(),
            });
        }
        if record.loopback_addr() != loopback_addr {
            return Err(WithdrawError::NotTheHandedPair {
                switch_addr,
                held_loopback: record.loopback_addr(),
                asked_loopback: loopback_addr,
            });
        }
        // The attachment goes with the row (NET-133), retired inside the
        // same critical section that removes the row: a registration
        // landing after cannot retire the new box's attachment, and one
        // landing before is the row the proof above matched. This is the
        // one path that holds a row lock across the attachment table's —
        // every other path takes the two locks one at a time, never
        // together — so the order never inverts.
        self.retire_proxy_attachment(switch_addr, Instant::now());
        let removed = rows.remove(&switch_addr.octets());
        drop(rows);
        self.retired(&removed);
        Ok(removed)
    }

    /// Retires a removed row's side facts: its stopped mark is stale with
    /// the row gone, and the change is a ping like any other.
    fn retired(&self, removed: &Option<Arc<BoxRecord>>) {
        if let Some(record) = removed {
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .remove(&record.switch_addr.octets());
            self.ping();
        }
    }

    /// Records the in-VM daemon's admit report of one runtime-published
    /// port (NET-138, NET-045) into the row at `switch_addr` — the one row
    /// dimension a guest's own report fills, and only within the grant the
    /// row's host-side registration holds. The checks, in order:
    ///
    /// 1. **A row exists** at the switch address the registration handed
    ///    back — a report keyed anywhere else is no row's and is refused.
    /// 2. **The stance** is `allow` or `ask`: `deny`, the default an absent
    ///    declaration carries, admits nothing.
    /// 3. **The port is inside the row's allowed range**, inclusively at
    ///    both ends; a row that declared no range permits nothing.
    /// 4. **The row holds fewer than [`RUNTIME_PORT_CAP`] runtime ports** —
    ///    the cap applies to duplicates too, so a full row admits nothing.
    /// 5. **The row is inside its admit rate** — at most
    ///    [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports per trailing
    ///    second, counting every report that passes the checks above,
    ///    duplicates included: the rate bounds the reporting, not the
    ///    ports.
    ///
    /// A report that passes records the port idempotently — the port and
    /// protocol pair the report named — and answers the row it recorded
    /// into, so the caller can name the box its line speaks for. A refusal
    /// answers [`PortReportRefusal`] naming the box where the row exists and
    /// the check that refused, and records nothing: no rate timestamp, no
    /// port, no fact the host did not hold.
    ///
    /// `now` is the instant the report arrived, injected so the rate and
    /// the cap are testable without waiting real seconds.
    ///
    /// # Errors
    ///
    /// [`PortReportRefusal`] — never a panic; the lock guards are poison
    /// guards only, and no lock is held across a panic.
    pub fn admit_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
        now: Instant,
    ) -> Result<Arc<BoxRecord>, PortReportRefusal> {
        // The rows guard is a read lock held for the whole call — the row's
        // registration-frozen facts first, then the runtime half nested
        // inside — so reports against different rows run concurrently and
        // the registration's write lock only waits out its own turn. No
        // path takes the two in the other order (a row's withdrawal drops
        // the row from the map without touching its runtime half), so the
        // nesting is acyclic.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record =
            rows.get(&switch_addr.octets())
                .ok_or(PortReportRefusal::NoRow {
                    switch_addr,
                    port,
                    proto,
                })?;
        let name = record.name().to_string();
        match record.dynamic_ingress() {
            DynamicIngress::Deny => {
                return Err(PortReportRefusal::DenyStance { name, port, proto });
            }
            // `ask` records a report the attached human answered yes to
            // (NET-045): the host cannot see the human's answer, so the
            // stance's grant is the recording bound the daemon's report
            // answers to.
            DynamicIngress::Allow | DynamicIngress::Ask => {}
        }
        let range = record
            .dynamic_range()
            .ok_or_else(|| PortReportRefusal::NoAllowedRange {
                name: name.clone(),
                port,
                proto,
            })?;
        if port < range.0 || port > range.1 {
            return Err(PortReportRefusal::OutsideAllowedRange {
                name,
                port,
                proto,
                range,
            });
        }
        // The row's runtime half: cap, then rate, then the recording — one
        // lock section, so a report that passes every check is recorded in
        // the order it arrived.
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if runtime.ports.len() >= RUNTIME_PORT_CAP {
            return Err(PortReportRefusal::RowCapReached {
                name,
                port,
                proto,
                cap: RUNTIME_PORT_CAP,
            });
        }
        // The trailing-second window: every recorded report inside it
        // counts, and a report over the rate is refused without pacing.
        while runtime
            .admits
            .front()
            .is_some_and(|at| now.duration_since(*at) >= ADMIT_RATE_WINDOW)
        {
            runtime.admits.pop_front();
        }
        if runtime.admits.len() >= ROW_ADMIT_RATE_PER_SECOND {
            return Err(PortReportRefusal::RateExceeded {
                name,
                port,
                proto,
                rate: ROW_ADMIT_RATE_PER_SECOND,
            });
        }
        runtime.admits.push_back(now);
        let reported = RuntimePort { port, proto };
        if !runtime.ports.contains(&reported) {
            runtime.ports.push(reported);
        }
        Ok(Arc::clone(record))
    }

    /// Applies the in-VM daemon's withdrawal report of one runtime-published
    /// port: the port leaves the row's runtime set, so the gate no longer
    /// admits a retraction of it and the read-only row verb no longer lists
    /// it. Never refused — the cap and the rate are the admit path's bounds,
    /// and removing a fact the row holds (or already lacks) is always the
    /// goal state — and never counted against the rate. Answers the row the
    /// port was withdrawn from, `None` when no row is held at the address:
    /// the report was accepted either way.
    pub fn withdraw_runtime_port(
        &self,
        switch_addr: Ipv4Addr,
        port: u16,
        proto: IpProto,
    ) -> Option<Arc<BoxRecord>> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let record = rows.get(&switch_addr.octets())?;
        let mut runtime = record
            .runtime_ports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        runtime
            .ports
            .retain(|reported| !(reported.port == port && reported.proto == proto));
        Some(Arc::clone(record))
    }

    /// The live row registered under `name` (the read-only row verb's
    /// resolution, NET-138): a box's id on the host is its name, so the
    /// name is the whole key, and liveness is the table's own fact — a box
    /// whose row is withdrawn is gone, not archived, so a name no live box
    /// holds answers no row, never a destroyed box's last row. `None` when
    /// no live row carries the name.
    #[must_use]
    pub fn row_by_name(&self, name: &str) -> Option<Arc<BoxRecord>> {
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        rows.values().find(|record| record.name() == name).cloned()
    }

    /// Marks the namespace published at `switch_addr` stopped: its row
    /// stays — a stopped namespace is never mistaken for one that never
    /// existed, so its zone name stays held and answers NODATA rather than
    /// NXDOMAIN (NET-128) — but it answers no address while the mark
    /// stands. A registration at the same address clears the mark, because
    /// the newest declaration is a namespace that is running. Returns
    /// whether a row was published at the address: marking an address no
    /// row holds marks nothing.
    ///
    /// No production path marks a row stopped yet. A box's lifecycle lives
    /// with the guest daemon that runs it, and the host learns a box
    /// stopped when the task that carries box lifecycle over the host's
    /// control path lands; this mutator is the seam that task writes
    /// through, and the zone view and the state dump already carry the
    /// mark.
    pub fn mark_stopped(&self, switch_addr: Ipv4Addr) -> bool {
        let held = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .contains_key(&switch_addr.octets());
        if held {
            self.stopped
                .write()
                .expect(
                    "the stopped set's lock is never held across a panic, so it cannot be \
                     poisoned",
                )
                .insert(switch_addr.octets());
            self.ping();
        }
        held
    }

    /// Subscribes to the table's change pings: one `()` per registration,
    /// withdrawal, and stopped mark, for as long as the returned receiver
    /// lives. The host answerer subscribes — a daemon that does not hold
    /// the answerer port re-registers its zone rows with the one that does
    /// on every change — and so does the zone-table dump
    /// ([`crate::diag`]); a subscriber is pruned with its receiver, and a
    /// ping to a dead one is dropped, never a registration held back. The
    /// channel is unbounded and every sender drops a refused send, so a
    /// slow registrar holds its own pings back, never the table's.
    pub fn subscribe_table_pings(&self) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .push(sender);
        receiver
    }

    /// Files one change ping to every live subscriber, pruning the dead
    /// ones as it goes.
    fn ping(&self) {
        self.table_pings
            .lock()
            .expect("the ping channels' lock is held only across pushes and pings")
            .retain(|sender| sender.send(()).is_ok());
    }

    /// The zone view the host answerer answers the box zone from (NET-138):
    /// every published row's name under the zone apex —
    /// `<name>.min.internal`, the form the shared decision matches — with
    /// the host-answerable address a lookup may be told (NET-127) and the
    /// row's liveness (NET-128). One row per namespace, held in name
    /// order, so the view a lookup answers from and the table the state
    /// dump writes are the same rows.
    ///
    /// The address is the row's published loopback address when it is one
    /// the host may be told and `None` when it is not: a row's switch
    /// lease is inside the guest's fabric, nothing on the host OS routes
    /// to it, and a name held only there answers NODATA rather than
    /// pointing a lookup somewhere it cannot go (the same gate the native
    /// daemon's registry applies, [`is_host_answerable`]). The node's own
    /// namespace is a row like any other — its services sit at the
    /// machine's shared loopback address, which is answerable, so the row
    /// answers with it.
    ///
    /// Liveness is the table's own fact: a row is live from its
    /// registration, and [`Self::mark_stopped`] holds it NODATA while the
    /// namespace it names is not running. The view is a snapshot, built
    /// fresh by whoever asks — a lookup, a dump, a registration — so it
    /// can never hold a row the table has already let go.
    #[must_use]
    pub fn zone_view(&self) -> zone_answer::ZoneView {
        // The rows lock first, the stopped set inside it — the order every
        // other path through both takes (`register`, `retired`,
        // `mark_stopped`), so the two locks never wait on each other.
        let rows = self
            .rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned");
        let stopped = self.stopped.read().expect(
            "the stopped set's lock is never held across a panic, so it cannot be \
                 poisoned",
        );
        let mut view = zone_answer::ZoneView::new();
        for record in rows.values() {
            view.hold(
                zone_name(record.name()),
                zone_answer::ZoneRow {
                    address: is_host_answerable(record.loopback_addr())
                        .then_some(record.loopback_addr()),
                    live: !stopped.contains(&record.switch_addr.octets()),
                },
            );
        }
        view
    }

    /// Publishes the guest **node's** own namespace: the in-VM daemon's
    /// root-netns tap, the plane design §5.1 names node-plane. The address is
    /// the host's own derivation from the subnet it configured the switch
    /// with ([`SwitchSubnet::daemon_ip`]) — the guest is neither asked nor
    /// able to influence what this row holds.
    ///
    /// The admitted port is the one the daemon's own setup publishes at its
    /// address: the hostname proxy's, assigned by the VM host before the VM
    /// boots ([`crate::cmd::run`] hands it to the guest on the kernel command
    /// line) and bound by the guest daemon as handed — so the publishes the
    /// daemon makes to attach it are publishes of a port this row already
    /// names, not requests for the host to open its own. The zone answerer is
    /// not the node's to admit (NET-138): on a VM-backed host the in-VM daemon
    /// starts no answerer — the host answerer serves the zone — so an
    /// answerer port on this row would be an admitted port with nothing
    /// behind it, a standing grant.
    ///
    /// The rules are the allow-all interim the absent-policy default ships:
    /// the node-plane baseline set is un-enrolled until NET-130's enumeration
    /// lands, and until then the daemon keeps the reach it had before the
    /// gate existed — its own package fetches above all, which is the
    /// VM-side shape of NET-080. NET-130 tightens this row to the categories
    /// design §5.1 enumerates.
    pub fn register_node_namespace(&self, proxy_port: u16) -> Arc<BoxRecord> {
        self.register(
            BoxRegistration::new(NODE_NAMESPACE, self.subnet.daemon_ip(), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([proxy_port]),
        )
    }

    /// Takes the receiving end of the gate's withdrawal reports, once: every
    /// [`BoxTable`] clone holds the sending end, and the reports a relay
    /// files at its end — the switch addresses whose traffic it relayed —
    /// arrive here for the registry to withdraw by. `None` once taken; the
    /// caller that wants them drained by a thread wants
    /// [`Self::spawn_withdrawal_drainer`] instead.
    pub fn take_withdrawal_reports(&self) -> Option<std::sync::mpsc::Receiver<WithdrawalReport>> {
        self.withdrawal_reports_rx
            .lock()
            .expect("the report channel's lock is held only across this take")
            .take()
    }

    /// Spawns the thread that applies the gate's withdrawal reports: one
    /// report — the switch addresses whose relayed traffic ended with a
    /// connection — drives one [`Self::withdraw`] per address, so a box's
    /// row goes with its connection. The bound the withdrawal keeps is
    /// NET-133's, keyed to the relay's end: the box's own shuttle
    /// connection, the one its frames travel by, is what the report rides
    /// (and a row whose traffic never ends is never withdrawn). The
    /// thread holds a clone of this registry, so it withdraws the same
    /// rows every other handle sees. That clone carries one of the
    /// reports' senders — the very channel the thread drains — so the
    /// senders are never all gone while the thread runs and `recv()`
    /// never reports the channel dead: the loop cannot exit. The thread
    /// is for the process's lifetime, which is the design's intent, and
    /// nothing in teardown may rely on its exit.
    ///
    /// Idempotent by the take underneath: a second call finds no receiver
    /// and spawns nothing.
    pub fn spawn_withdrawal_drainer(&self) {
        // Taken from this registry, never a clone: the receiver lives only
        // on the registry that created the channel, and a clone carries
        // `None` for it, so a clone's take would return `None` and spawn
        // nothing.
        let Some(reports) = self.take_withdrawal_reports() else {
            return;
        };
        let registry = self.clone();
        let spawned = std::thread::Builder::new()
            .name("box-row-withdrawals".to_string())
            .spawn(move || {
                while let Ok(report) = reports.recv() {
                    for addr in report {
                        registry.withdraw(Ipv4Addr::from(addr));
                    }
                }
            });
        if let Err(error) = spawned {
            // The reports keep buffering; the rows stay held. A thread the
            // host could not spare is a host that is not running a VM long —
            // but a silent drop of the withdrawal path would leave rows
            // published past their boxes, so say so.
            tracing::warn!(
                %error,
                "could not spawn the box-row withdrawal drainer; rows will \
                 outlive their shuttle connections until it starts"
            );
        }
    }

    /// The read-only view the egress gate decides by — the same rows this
    /// registry holds, shared, so every later registration reaches the
    /// running gate. The view carries a clone of the withdrawal reports'
    /// sender with it: filing one is the view's single write-shaped act, and
    /// it is a report to this process, not a row operation — see
    /// [`BoxTable`].
    #[must_use]
    pub fn table(&self) -> BoxTable {
        BoxTable {
            rows: Arc::clone(&self.rows),
            subnet: self.subnet,
            withdrawal_reports: self.withdrawal_reports.clone(),
        }
    }
}

/// Takes the next unspent address from `cursor`, when `first..=last` still
/// holds one. Relaxed ordering: a cursor's only invariant is that no two
/// takes return the same address, which an atomic add gives on every
/// ordering; the run's bounds are checked on the taken value, so even a
/// cursor advanced past its run's end (or wrapped) hands out nothing.
fn take_next(cursor: &AtomicU32, first: u32, last: u32) -> Option<Ipv4Addr> {
    let next = cursor.fetch_add(1, Ordering::Relaxed);
    (first <= next && next <= last).then(|| Ipv4Addr::from(next))
}

/// A namespace's name under the zone apex, as the zone view holds it:
/// `<name>.min.internal`. The view normalizes what it is given, so the
/// row's name passes through exactly as the declaration spelled it.
fn zone_name(name: &str) -> String {
    format!("{name}.{}", zone_answer::ZONE_APEX)
}

/// Whether `addr` is one an A answer in the box zone may carry (NET-127):
/// the host's shared loopback address, or an address from the reserved
/// local range the address plan publishes boxes at. Anything else — a box's
/// switch lease inside the guest's fabric, an address another host holds —
/// is not one the host OS can reach, and a name held only there answers
/// NODATA rather than pointing a lookup somewhere it cannot go. The same
/// gate the native daemon's registry applies
/// (`minimald::net::dns::is_host_answerable`), restated against the range's
/// one definition in the switch crate so the two cannot drift.
pub(crate) fn is_host_answerable(addr: Ipv4Addr) -> bool {
    addr == Ipv4Addr::LOCALHOST || in_reserved_local_range(addr)
}

/// Whether `addr` falls in the reserved local range the address plan
/// publishes boxes at.
fn in_reserved_local_range(addr: Ipv4Addr) -> bool {
    let (network, prefix) = switch::RESERVED_LOCAL_RANGE;
    let host_bits = 32 - u32::from(prefix);
    // A /0 range would mean "every address"; the shift below needs a
    // network part to keep.
    if host_bits >= 32 {
        return true;
    }
    let mask = u32::MAX << host_bits;
    u32::from(network) & mask == u32::from(addr) & mask
}

/// The read-only view of the published rows the egress gate decides by: the
/// lookup a frame's source address resolves through, and nothing else that
/// touches a row. The registry hands the gate this view because its row
/// operations are lookups only — the component that reads guest frames
/// cannot add, replace, or withdraw a row (NET-138: the table is filled on
/// the host, never from the guest).
///
/// What the view carries beside the lookups is one channel: filing a
/// withdrawal report at a relay's end. It is deliberately **not** a row
/// operation — the report leaves this process as a fact the host acts on
/// ([`BoxRegistry::withdraw`], through the drainer), so the guest's
/// influence on the table is still bounded by what it can make the host
/// observe: that a connection whose relayed traffic named an address is
/// over. Which is the withdrawal NET-133 asks for, and nothing more.
///
/// Cheap to clone; every clone shares the registry's rows, carries the
/// registry's plan beside them, and files its reports into the one channel.
#[derive(Debug, Clone)]
pub struct BoxTable {
    rows: Arc<RwLock<Rows>>,
    subnet: SwitchSubnet,
    withdrawal_reports: std::sync::mpsc::Sender<WithdrawalReport>,
}

impl BoxTable {
    /// The published namespace holding the switch address `src`, when one
    /// does. This is the whole of the gate's per-frame routing: an address a
    /// row holds is decided by that row's rules, and an address no row holds
    /// is the phase's to decide ([`crate::net::egress_gate`]), never a
    /// rule's.
    #[must_use]
    pub fn by_source(&self, src: [u8; 4]) -> Option<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .get(&src)
            .cloned()
    }

    /// Whether the plan could ever hand `src` to a box: inside the registry's
    /// subnet, and inside the run its address plan allocates PTask leases from
    /// ([`SwitchSubnet::first_ptask`] through [`SwitchSubnet::last_ptask`]) —
    /// the one set of addresses a published row is ever keyed by, and so the
    /// one set whose rows the host-side creator will supply (T66's registration
    /// path). The run spans both of the plan's sub-runs — the daemon's
    /// self-allocation reserve included, because a task sandbox holds a
    /// reserve address and stays an unregistered source; the host hands
    /// registered boxes only from the upper half
    /// (`hand_out_run`). The subnet's own infrastructure sits outside that
    /// run: the gateway the resolver carve-out is keyed to, the host alias,
    /// and the guest daemon's own tap, which the registry publishes a row for
    /// itself. The gate's unregistered drop (NET-085) refuses a source only
    /// from here, so no amount of it can borrow the plan's infrastructure as
    /// a source, and this predicate is what keeps that drop and the
    /// unknown-source refusal one address range apart.
    #[must_use]
    pub fn is_allocatable(&self, src: [u8; 4]) -> bool {
        let addr = u32::from(Ipv4Addr::from(src));
        self.subnet.first_ptask() <= addr && addr <= self.subnet.last_ptask()
    }

    /// Every published row, in switch-address order.
    #[must_use]
    pub fn rows(&self) -> Vec<Arc<BoxRecord>> {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Whether no namespace is published.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows
            .read()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .is_empty()
    }

    /// The plan's lease run — `first_ptask` through `last_ptask` — as the
    /// octet arrays the publish decision compares a request's switch address
    /// by. The same bounds [`Self::is_allocatable`] decides frames by; the
    /// publish decision needs them as values because its table is an owned,
    /// pure one ([`sessions::core::switch_request`]), built fresh per
    /// request.
    #[must_use]
    pub fn ptask_run(&self) -> ([u8; 4], [u8; 4]) {
        (
            Ipv4Addr::from(self.subnet.first_ptask()).octets(),
            Ipv4Addr::from(self.subnet.last_ptask()).octets(),
        )
    }

    /// The switch's own address — the plan's gateway, the address the
    /// resolver answers at ([`SwitchSubnet::dns_server`], which is the same
    /// address) — as the octet array a frame's destination is compared by.
    /// The one destination inside the fabric that is a control surface, not
    /// a destination a box's egress rules decide: the gate refuses every
    /// frame headed here but a TCP or UDP query to the resolver's port,
    /// before any row or phase is consulted — a row's admitted ports are its
    /// own ingress, never a flow to the gateway.
    #[must_use]
    pub fn gateway(&self) -> [u8; 4] {
        self.subnet.gateway().octets()
    }

    /// The subnet the rows live in — the node's own switch block, the one
    /// slice of the fabric plane a box's frames may name as local reach
    /// (a sibling, the host alias, the daemon), decided by the row's own
    /// rules and the target's ingress rather than by the gate's
    /// infrastructure rule ([`crate::net::egress_gate`]).
    #[must_use]
    pub fn subnet(&self) -> SwitchSubnet {
        self.subnet
    }

    /// Files a withdrawal report: `sources` are the switch addresses whose
    /// relayed traffic the calling connection carried, and the connection is
    /// at its end — the guest closed it, it errored, or the gate refused
    /// what followed. The registry's drainer withdraws a row per reported
    /// address that still holds one (NET-133: a box's row goes with its
    /// shuttle connection), so a re-attachment starts from a table the
    /// withdrawn namespace no longer holds.
    ///
    /// Filing is the view's one write-shaped act and never blocks: the
    /// channel is unbounded and the drainer consumes it, and a send that
    /// fails — every receiver gone, which is a host shutting down — is
    /// dropped silently, because there is nothing left to withdraw for.
    pub fn report_withdrawals(&self, sources: Vec<[u8; 4]>) {
        if sources.is_empty() {
            return;
        }
        if let Err(_disconnected) = self.withdrawal_reports.send(sources) {
            // Every receiver is gone: the drainer was never started or the
            // host is shutting down. Nothing to withdraw for, nowhere to
            // say so that is not noise at teardown.
        }
    }
}

/// The registered boxes the proxy's pool partitions its listeners by
/// (NET-132): the box rows this registry publishes — every one a
/// host-side fact the guest never asserts — polled by the pool every
/// stack turn, so a row that lands grows its box's share within a turn
/// and a row that leaves takes its sockets with it. The box id a
/// delivery's header is filled from resolves through the same source
/// (NET-133): the attachment the source's row holds, issued by the
/// registration and withdrawn with it.
///
/// The guest node namespace's row is not one of them, so it buys no
/// share (see the [`BepBoxSource`](switch::bep_host::BepBoxSource)
/// impl) — and it holds no attachment either, so a delivery from it
/// names nothing. The host's own address outside the box host — the
/// cohort address host-address boxes arrive from (NET-078) — is a row
/// like a box's when the host published one there: its attachment is
/// the cohort's, and a delivered connection from it carries the
/// cohort's id.
pub struct RegisteredBoxes {
    /// The registry's live read-only view: every registration and
    /// withdrawal the table sees reaches the pool through it.
    table: BoxTable,
    /// The proxy's attachment table: what a delivery's box id resolves
    /// by, looked up through and never written — the registry is the one
    /// writer (NET-133).
    attachments: crate::bep_attach::Attachments,
}

impl RegisteredBoxes {
    /// The source over `table`'s rows and the proxy's `attachments` —
    /// the two tables one registry writes, handed to the supervisor
    /// that owns both.
    #[must_use]
    pub fn new(table: BoxTable, attachments: crate::bep_attach::Attachments) -> Self {
        Self { table, attachments }
    }
}

impl switch::bep_host::BepBoxSource for RegisteredBoxes {
    fn box_switch_addresses(&self) -> Vec<Ipv4Addr> {
        // The guest node namespace's row is the VM's own root netns, the
        // daemon's tap — never a box, and a share in its name would
        // partition the pool by a row no box ever speaks from. Its
        // address is fixed, the subnet's daemon address, which sits
        // outside the hand-out run every client box is allocated from,
        // so excluding that one address names exactly the node row.
        let node_addr = self.table.subnet().daemon_ip();
        self.table
            .rows()
            .iter()
            .map(|row| row.switch_addr())
            .filter(|addr| *addr != node_addr)
            .collect()
    }

    fn box_id_for_source(&self, source: Ipv4Addr) -> Option<crate::bep_attach::BoxId> {
        // The delivery's id is the box's own — resolved through the
        // attachment its source holds, the same host-side table the row
        // the source is keyed by came from, never a fact the flow
        // carries. A source with no attachment — the node namespace
        // above all, which holds none — names nothing, and the pool
        // aborts what it accepts from it rather than deliver a
        // connection it cannot attribute. The host's cohort row
        // (NET-078) holds one like any box's, so a host-address box's
        // delivery carries the cohort's own id.
        self.attachments
            .by_source(source.octets())
            .map(|attachment| attachment.box_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sessions::IpProto;
    use sessions::core::egress::FrameVerdict;
    use switch::SwitchSubnet;
    use tokio::io::AsyncWriteExt;

    use crate::net::egress_gate::test_support::{
        DEADLINE, arp_frame, expect_frame, expect_silence, gate_over, ipv4_frame, send_frame,
    };

    use super::*;

    /// The default switch subnet, the plan every registry below is built for.
    const SUBNET: SwitchSubnet = switch::DEFAULT_SUBNET;

    /// A published namespace's identity, as a comparable value: the row's
    /// whole content, flattened — what a before/after comparison of the table
    /// asserts on (see `host_table_never_sourced_from_guest`).
    fn row_identity(record: &BoxRecord) -> (Ipv4Addr, String, Ipv4Addr, Vec<u16>, EgressRules) {
        (
            record.switch_addr(),
            record.name().to_string(),
            record.loopback_addr(),
            record.admitted_ports().to_vec(),
            record.egress().clone(),
        )
    }

    /// NET-138: the host-side table holds every published namespace — one
    /// row each, keyed by the switch address the gate resolves frames by,
    /// carrying the name, both addresses, the admitted ports, and the rules
    /// compiled from the declaration; the guest node's own namespace is a row
    /// like any other; a withdrawn namespace's row is gone; and the table the
    /// gate holds is the registry's live rows, so a registration made after
    /// the table was handed out is decided by from that moment on.
    #[test]
    fn host_table_holds_every_published_namespace() {
        let registry = BoxRegistry::new(SUBNET);
        let table = registry.table();
        assert!(
            table.is_empty(),
            "a fresh registry publishes nothing until the host fills it"
        );

        // Two boxes, each with a declared policy; the node namespace beside
        // them, as run.rs publishes it.
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let db = registry.register(
            BoxRegistration::new("db", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([5432, 5433]),
        );
        let node = registry.register_node_namespace(7654);

        // Every published namespace holds a row, resolved by the address the
        // gate's per-frame lookup uses.
        let rows = table.rows();
        assert_eq!(
            rows.iter().map(|row| row.switch_addr()).collect::<Vec<_>>(),
            [
                Ipv4Addr::new(100, 64, 0, 9),
                Ipv4Addr::new(100, 64, 0, 10),
                SUBNET.daemon_ip(),
            ],
            "every published namespace holds a row, in switch-address order"
        );
        assert_eq!(web.name(), "web");
        assert_eq!(web.loopback_addr(), Ipv4Addr::LOCALHOST);
        assert_eq!(web.admitted_ports(), [8080]);
        assert_eq!(db.name(), "db");
        assert_eq!(db.admitted_ports(), [5432, 5433]);
        assert_eq!(node.name(), "minimald");
        assert_eq!(node.switch_addr(), SUBNET.daemon_ip());
        assert_eq!(
            node.admitted_ports(),
            [7654],
            "the node's row names the proxy port the VM host assigned and \
             handed over — the answerer is not the node's to admit (NET-138) — \
             so the daemon's own publishes are publishes of a port the row \
             already declares"
        );

        // The table carries the plan its rows are addressed on, and the plan's
        // own answer to which addresses a box could ever hold: every row's
        // switch address is allocatable, and the subnet's infrastructure — the
        // gateway the resolver carve-out is keyed to, the host alias, the
        // daemon address the node row holds — is not, nor is anything outside
        // the subnet. That answer is what the gate's interim keys its one
        // concession on, so it is pinned here, against the plan itself.
        for row in [web.clone(), db.clone()] {
            assert!(
                table.is_allocatable(row.switch_addr().octets()),
                "a box's lease is an address the plan could hand out"
            );
        }
        for infra in [
            SUBNET.dns_server(),
            SUBNET.host_alias(),
            SUBNET.daemon_ip(),
            Ipv4Addr::new(203, 0, 113, 7),
        ] {
            assert!(
                !table.is_allocatable(infra.octets()),
                "the plan never hands out {infra}"
            );
        }
        for row in [web.clone(), db.clone(), node.clone()] {
            assert_eq!(
                table.by_source(row.switch_addr().octets()).as_deref(),
                Some(row.as_ref()),
                "the row is resolved by the address the gate looks frames up by"
            );
        }

        // The row's rules are the declaration, compiled against the registry's
        // subnet: the lease is the row's own switch address (NET-084) and the
        // resolver carve-out is keyed to the switch this registry serves —
        // and the node's interim row compiles from no declaration at all.
        let web_policy = EgressPolicy {
            allow_protocols: Some(vec![IpProto::Tcp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
            allow_dns_hosts: None,
            deny_subnets: None,
        };
        assert_eq!(
            web.egress(),
            &EgressRules::from_policy(
                Some(&web_policy),
                SUBNET.dns_server().octets(),
                Ipv4Addr::new(100, 64, 0, 9).octets(),
            )
        );
        assert_eq!(
            db.egress(),
            &EgressRules::from_policy(
                None,
                SUBNET.dns_server().octets(),
                db.switch_addr().octets()
            )
        );

        // Withdrawal retires the row: the address is held by no namespace and
        // no rules are decided by it. Whether its frames are dropped with it
        // is the phase's to say, not the table's — see `withdraw`'s docs.
        assert!(registry.withdraw(db.switch_addr()).is_some());
        assert!(
            table.by_source(db.switch_addr().octets()).is_none(),
            "a withdrawn namespace holds no row"
        );
        assert!(registry.withdraw(db.switch_addr()).is_none());
        assert_eq!(table.rows().len(), 2);

        // The table is the registry's live rows, shared: a registration made
        // through another handle — the shape T66's client-driven path will
        // use — is decided by from the moment it lands.
        let peer = registry.clone();
        let late = peer.register(BoxRegistration::new(
            "late",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::LOCALHOST,
        ));
        assert_eq!(
            table.by_source(late.switch_addr().octets()).as_deref(),
            Some(late.as_ref()),
            "a registration after the table was handed out reaches it"
        );

        // Re-registering an address replaces the row with the newest
        // declaration, compared against nothing: this restatement is wider
        // than the one it replaces — no declared policy, so allow-all where
        // the first said TCP to a LAN — and the table holds it anyway,
        // because the reach a row grants is its latest registration's, and
        // whether a re-declaration may widen is the registering side's
        // contract (T66's path), not the table's.
        let restated = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
        ));
        let rows = table.rows();
        assert_eq!(rows.len(), 3);
        let restated_row = table
            .by_source(Ipv4Addr::new(100, 64, 0, 9).octets())
            .expect("the address is still published");
        assert_eq!(restated_row.egress(), restated.egress());
        assert!(
            restated_row.egress() != web.egress(),
            "the re-registration replaced the row the gate resolves"
        );
        // And it widens, visibly: the shared verdict — the decision the gate
        // applies — drops a frame to an address outside the LAN the first
        // declaration allowed, and admits the same frame under the row the
        // re-registration left.
        let outside = sessions::core::egress::summarize(&ipv4_frame(
            Ipv4Addr::new(100, 64, 0, 9).octets(),
            6,
            [203, 0, 113, 7],
            443,
        ));
        assert!(matches!(
            sessions::core::egress::verdict(&outside, web.egress()),
            FrameVerdict::Drop(_)
        ));
        assert!(
            matches!(
                sessions::core::egress::verdict(&outside, restated_row.egress()),
                FrameVerdict::Admit
            ),
            "the re-registration's reach is what the gate now decides by"
        );
    }

    /// The host hands registered boxes only from the hand-out run — the plan
    /// run's upper half, above the daemon's self-allocation reserve — and
    /// the loopback run's exhaustion stays an explicit refusal, with no
    /// wrap. Driven on a planned carved /24, whose runs are small enough to
    /// see both edges of.
    #[test]
    fn client_boxes_hand_out_from_the_run_above_the_reserve() {
        // The plan's default subnet splits at 100.64.127.255 — pinned
        // literally, mirrored from `minimald::net::self_allocation_run`:
        // the first box takes the hand-out run's first address, never the
        // PTask run's first (that is the daemon's reserve).
        let registry = BoxRegistry::new(SUBNET);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the default plan has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 127, 255),
            "the first box takes the hand-out run's first address, above the \
             daemon's reserve"
        );

        // A planned carved /24: its PTask run is 100.64.1.2 through
        // 100.64.1.252, so its hand-out run starts at .127 — and its
        // loopback slice holds 32 addresses, which run out first. The
        // refusal is explicit and repeats: no wrap, no reuse.
        let carved = SwitchSubnet::new(Ipv4Addr::new(100, 64, 1, 0), 24).expect("valid");
        assert!(
            switch::AddressPlan::default()
                .loopback_slice_for_switch(carved)
                .is_some(),
            "the carved subnet is planned, so a refusal is a run's exhaustion, not the plan's absence"
        );
        let registry = BoxRegistry::new(carved);
        let first = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the carved subnet has hand-out addresses");
        assert_eq!(
            first.switch_addr(),
            Ipv4Addr::new(100, 64, 1, 127),
            "the carved /24's hand-out run also starts above its reserve"
        );
        for index in 1..32 {
            registry
                .register_client_box(ClientBoxSpec {
                    name: format!("box{index}"),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                })
                .expect("the slice holds 32 published addresses");
        }
        for _ in 0..2 {
            assert!(
                matches!(
                    registry.register_client_box(ClientBoxSpec {
                        name: "late".to_string(),
                        ingress_ports: Vec::new(),
                        egress: None,
                        credentialed_upstream: None,
                        dynamic_ingress: None,
                        dynamic_allowed_range: None,
                    }),
                    Err(AllocationError::LoopbackExhausted)
                ),
                "exhaustion is explicit and never wraps"
            );
        }
    }

    /// BEP-070, one id names one box, so a registration whose minted id a
    /// live row or attachment already holds is refused — never re-minted,
    /// and before any address is spent, so the refusal leaves no new fact
    /// on the host — and said as one warn line naming the id. A real mint
    /// does not collide, so the test drives the collision through the
    /// registration's own door with the id it would have minted fixed.
    #[test]
    fn colliding_box_id_refused() {
        let (log, _guard) = crate::net::egress_gate::test_support::capture_log();
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let web = registry
            .register_client_box(ClientBoxSpec {
                name: "web".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has an address for the first box");
        assert!(
            attachments.holds_id(web.box_id()),
            "the box's id is held by its row's attachment, the half of the live \
             set a source's delivery resolves through"
        );

        // A registration whose mint landed on the live row's id would name
        // the web box: refused, and the refusal names the colliding id.
        let refused = registry
            .register_client_box_as(
                ClientBoxSpec {
                    name: "impostor".to_string(),
                    ingress_ports: Vec::new(),
                    egress: None,
                    credentialed_upstream: None,
                    dynamic_ingress: None,
                    dynamic_allowed_range: None,
                },
                web.box_id(),
            )
            .expect_err("an id a live box holds is not a second box's");
        assert_eq!(
            refused,
            AllocationError::CollidingBoxId { id: web.box_id() },
            "the refusal names the colliding id, the one the registration claimed"
        );

        // The refusal spent nothing: no row was published for the impostor,
        // the live row is untouched, and the hand-out run's next address is
        // still the next registration's to take.
        let rows = registry.table().rows();
        assert_eq!(rows.len(), 1, "a refused registration publishes no row");
        assert_eq!(
            row_identity(&rows[0]),
            row_identity(&web),
            "the live row is the live box's, untouched by the refusal"
        );
        let next = registry
            .register_client_box(ClientBoxSpec {
                name: "db".to_string(),
                ingress_ports: Vec::new(),
                egress: None,
                credentialed_upstream: None,
                dynamic_ingress: None,
                dynamic_allowed_range: None,
            })
            .expect("the plan has a second hand-out address");
        assert_eq!(
            next.switch_addr(),
            Ipv4Addr::from(u32::from(web.switch_addr()) + 1),
            "the refusal spent no address: the next registration takes the \
             hand-out run's next, the address the refused one would have spent"
        );

        // One warn line names the refusal and the id it refused — the line a
        // bundle's daemon log tail reads a refused registration by.
        let logged = log.contents();
        assert_eq!(
            logged
                .matches(
                    "refused a box registration whose id a live row or attachment already holds"
                )
                .count(),
            1,
            "one warn line per refused registration, got: {logged}"
        );
        assert!(
            logged.contains(&format!(
                "box_id={}",
                crate::bep_attach::BoxIdText(&web.box_id())
            )),
            "the warn line names the colliding id, got: {logged}"
        );
    }

    /// BEP-070: ids are never reused. A box registered, withdrawn, and
    /// registered again under the same name is a new creation with a new
    /// id — through the client-driven door, which spends fresh addresses,
    /// and through the explicit one on the very addresses the first box
    /// held — so a revocation scoped to the first id never names the
    /// second box.
    #[test]
    fn re_registration_never_reuses_an_id() {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let spec = || ClientBoxSpec {
            name: "web".to_string(),
            ingress_ports: vec![8080],
            egress: None,
            credentialed_upstream: None,
            dynamic_ingress: None,
            dynamic_allowed_range: None,
        };
        let first = registry
            .register_client_box(spec())
            .expect("the plan has an address for the first box");
        assert!(
            registry
                .withdraw_client_box("web", first.switch_addr(), first.loopback_addr())
                .expect("the withdrawing client is the row's creator")
                .is_some(),
            "the first box's row was published"
        );

        // The client-driven re-registration under the same name: a new id.
        let second = registry
            .register_client_box(spec())
            .expect("the plan has an address for the second box");
        assert_ne!(
            second.box_id(),
            first.box_id(),
            "a re-registration under the same name is a new box with a new id"
        );

        // The explicit door on the first box's own name and addresses: a
        // new id again, neither of the two before it.
        let third = registry.register(
            BoxRegistration::new("web", first.switch_addr(), first.loopback_addr())
                .with_admitted_ports([8080]),
        );
        assert_eq!(
            (third.switch_addr(), third.loopback_addr()),
            (first.switch_addr(), first.loopback_addr()),
            "the third box sits on the first box's addresses"
        );
        assert!(
            third.box_id() != first.box_id() && third.box_id() != second.box_id(),
            "a box on the same name and addresses is a new box with a new id"
        );
        assert!(
            !attachments.holds_id(first.box_id())
                && attachments.holds_id(second.box_id())
                && attachments.holds_id(third.box_id()),
            "the live attachments carry the new ids; the withdrawn id is never handed out again"
        );
    }

    /// NET-138's trust boundary: the guest never sources a row. The table the
    /// gate holds is read-only by construction — `BoxTable`'s only operations
    /// are lookups — and what that means behaviourally is that no amount of
    /// guest traffic changes it: frames driven through a live gate, hostile
    /// ones included, leave the published rows exactly as they were.
    #[tokio::test]
    async fn host_table_never_sourced_from_guest() {
        // One published box, declared as a real one is (TCP to a LAN, nothing
        // else), and the guest node beside it — the shape run.rs boots with.
        let registry = BoxRegistry::new(SUBNET);
        let lease = [100, 64, 0, 9];
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        registry.register_node_namespace(7654);
        let mut harness = gate_over(registry).await;

        let before: Vec<_> = harness
            .table
            .rows()
            .iter()
            .map(|row| row_identity(row))
            .collect();

        // Guest-side traffic, hostile included: a frame the published box did
        // not declare, a frame from an address no namespace holds but the plan
        // could lease, a frame carrying the node namespace's own address, and
        // an ARP announcing a foreign address. The gate decides each against
        // the table — the undeclared frame by its row's own rules, the
        // made-up lease by the unregistered drop (NET-085), the node's by
        // its row, and the foreign ARP by rule 0 — and the marker after them
        // proves the whole lot was decided before the comparison.
        let undeclared = ipv4_frame(lease, 6, [203, 0, 113, 7], 443);
        let unknown = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame([203, 0, 113, 7]);
        let marker = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        for frame in [&undeclared, &unknown, &node_frame, &foreign_arp] {
            send_frame(&mut harness.guest, frame).await;
        }
        send_frame(&mut harness.guest, &marker).await;
        // What the gate admitted, in order: the node namespace's frame, then
        // the published box's marker. The undeclared frame, the foreign ARP,
        // and the made-up lease — the in-plan address no row holds — are
        // simply absent.
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            node_frame,
            "the node namespace's frame is decided by its own row"
        );
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            marker,
            "the marker arrives: everything before it was decided"
        );
        expect_silence(&mut harness.switch).await;

        let after: Vec<_> = harness
            .table
            .rows()
            .iter()
            .map(|row| row_identity(row))
            .collect();
        assert_eq!(
            before, after,
            "no guest frame published, replaced, or withdrew a row: the gate reads \
             the table, it is never sourced from the guest"
        );
        assert!(
            harness.table.by_source(lease).is_some(),
            "the published box's row survived the guest's traffic"
        );
        assert!(
            harness.table.by_source([100, 64, 0, 99]).is_none(),
            "the guest's made-up address published no row — the drop that \
             refused its frame published nothing either"
        );
    }

    /// The zone view the host answerer answers from (NET-138): every
    /// published row's name under the zone apex, the host-answerable
    /// address a lookup may be told (NET-127), and the row's liveness
    /// (NET-128) — a row live from its registration, held NODATA once it
    /// is marked stopped, and gone with its withdrawal, never NXDOMAIN for
    /// a namespace that exists.
    #[test]
    fn the_zone_view_exposes_every_row_s_name_address_and_liveness() {
        let registry = BoxRegistry::new(SUBNET);
        assert!(
            registry.zone_view().is_empty(),
            "a fresh table's zone view holds nothing"
        );

        // One published box at its own address from the reserved local
        // range, one whose declared loopback address is not one the host
        // may be told — its switch lease, inside the guest's fabric — and
        // the node's own namespace at the shared loopback.
        let web = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::new(127, 0, 64, 9),
        ));
        registry.register(BoxRegistration::new(
            "lease-only",
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::new(100, 64, 0, 10),
        ));
        registry.register_node_namespace(7654);

        let view = registry.zone_view();
        let rows: Vec<(String, Option<Ipv4Addr>, bool)> = view
            .rows()
            .map(|(name, row)| (name.to_string(), row.address, row.live))
            .collect();
        assert_eq!(
            rows,
            [
                ("lease-only.min.internal".to_string(), None, true),
                (
                    "minimald.min.internal".to_string(),
                    Some(Ipv4Addr::LOCALHOST),
                    true
                ),
                (
                    "web.min.internal".to_string(),
                    Some(web.loopback_addr()),
                    true
                ),
            ],
            "every published row is held under its name, its host-answerable \
             address, and its liveness, in name order"
        );

        // The decision over the view answers the same shapes the native
        // daemon's registry does: an A lookup for the published address,
        // NODATA for the name held at an address the host may not be told,
        // NXDOMAIN for a name no row holds.
        let a = sessions::core::zone_answer::Lookup {
            name: "web.min.internal".to_string(),
            record: sessions::core::zone_answer::RecordType::A,
            origin: sessions::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &view),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a held live name answers A with its published address"
        );
        let lease_only = sessions::core::zone_answer::Lookup {
            name: "lease-only.min.internal".to_string(),
            record: sessions::core::zone_answer::RecordType::A,
            origin: sessions::core::zone_answer::Origin::OnMachine,
        };
        assert_eq!(
            sessions::core::zone_answer::decide(&lease_only, &view),
            sessions::core::zone_answer::Verdict::Nodata,
            "a name held only at an address the host may not be told is NODATA"
        );

        // A stopped namespace keeps its name held and answers NODATA, never
        // NXDOMAIN (NET-128), and its re-registration clears the mark: the
        // newest declaration is a namespace that is running.
        assert!(registry.mark_stopped(web.switch_addr()));
        let view = registry.zone_view();
        assert_eq!(
            view.rows()
                .find(|(name, _)| *name == "web.min.internal")
                .map(|(_, row)| *row),
            Some(zone_answer::ZoneRow {
                address: Some(web.loopback_addr()),
                live: false,
            }),
            "a stopped namespace keeps its name held, live: false"
        );
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &view),
            sessions::core::zone_answer::Verdict::Nodata,
            "a stopped namespace answers NODATA, held"
        );
        registry.register(BoxRegistration::new(
            "web",
            web.switch_addr(),
            web.loopback_addr(),
        ));
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Address(web.loopback_addr()),
            "a re-registration is a namespace that is running again"
        );

        // And a withdrawn namespace's name is gone with its row — held by
        // no name, so NXDOMAIN, never a stopped name held forever.
        assert!(registry.withdraw(web.switch_addr()).is_some());
        assert_eq!(
            sessions::core::zone_answer::decide(&a, &registry.zone_view()),
            sessions::core::zone_answer::Verdict::Nxdomain,
            "a withdrawn namespace's name is held by nothing"
        );
    }

    /// NET-133's trust boundary, on the proxy's attachments: the guest never
    /// sources one. The registry is the attachment table's one writer, and
    /// what that means behaviourally is that no amount of guest traffic
    /// changes what the proxy holds: frames driven through a live gate,
    /// hostile ones included, leave the attachments exactly as the
    /// registrations issued them — the same traffic, frame for frame, that
    /// `host_table_never_sourced_from_guest` proves leaves the rows alone.
    #[tokio::test]
    async fn proxy_attachment_never_sourced_from_guest() {
        // One published box, declared as a real one is, and the guest node
        // beside it — the shape run.rs boots with — over a registry that
        // feeds the proxy's table.
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let lease = [100, 64, 0, 9];
        registry.register(
            BoxRegistration::new("web", Ipv4Addr::from(lease), Ipv4Addr::LOCALHOST)
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        registry.register_node_namespace(7654);
        let mut harness = gate_over(registry).await;

        // The host's own issuances, before any guest byte is written: the
        // published box's attachment, and no attachment for the node
        // namespace, which is not a box.
        let before = attachments.rows();
        assert_eq!(
            before.len(),
            1,
            "the registry issued one attachment: the published box's, not the \
             node namespace's"
        );
        assert!(
            attachments.by_source(SUBNET.daemon_ip().octets()).is_none(),
            "the guest node's namespace is not a box: its row buys no attachment"
        );

        // Guest-side traffic, hostile included — the same set the row
        // table's own test drives: a frame the published box did not
        // declare, a frame from an address no namespace holds but the plan
        // could lease, a frame carrying the node namespace's own address,
        // an ARP announcing a foreign address, and the marker after them
        // that proves the whole lot was decided before the comparison.
        let undeclared = ipv4_frame(lease, 6, [203, 0, 113, 7], 443);
        let unknown = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame([203, 0, 113, 7]);
        let marker = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        for frame in [&undeclared, &unknown, &node_frame, &foreign_arp] {
            send_frame(&mut harness.guest, frame).await;
        }
        send_frame(&mut harness.guest, &marker).await;
        // What the gate admitted, in order — the node namespace's frame by
        // its own row, and the published box's marker: everything was
        // decided. The undeclared frame, the foreign ARP, and the made-up
        // lease — the in-plan address no row holds — are simply absent.
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            node_frame,
            "the node namespace's frame is decided by its own row"
        );
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            marker,
            "the marker arrives: everything before it was decided"
        );
        expect_silence(&mut harness.switch).await;

        // The attachments are exactly what the host issued: no guest frame
        // issued, replaced, or withdrew one.
        let after = attachments.rows();
        assert_eq!(
            before, after,
            "no guest frame reached the attachment table: it is written by \
             the registry alone, and never sourced from the guest"
        );
        assert!(
            attachments.by_source(lease).is_some(),
            "the published box's attachment survived the guest's traffic"
        );
        assert!(
            attachments.by_source([100, 64, 0, 99]).is_none(),
            "the guest's made-up address bought no attachment — the drop \
             that refused its frame attached nothing either"
        );
    }

    /// NET-133: an ended box's attachment is withdrawn within the
    /// requirement's bound of its end. The event the withdrawal keys to is
    /// the same one the row's own withdrawal keys to (NET-138, the row
    /// test above): the box's own shuttle connection — the one its frames
    /// travel by — ending, reported by the relay and applied by the
    /// registry's drainer, so the attachment goes with the row. From the
    /// moment the drainer applies the report the proxy attributes nothing
    /// to the box, even though the box's revocation was never recorded
    /// anywhere: the attachment that would have named it is gone. Here that
    /// is immediate — the report rides the same close that ended the
    /// traffic, and the poll bounds it at the harness's deadline, nowhere
    /// near the requirement's own.
    #[tokio::test]
    async fn proxy_attachment_withdrawn_within_60s_of_box_end() {
        let attachments = crate::bep_attach::Attachments::new();
        let registry = BoxRegistry::new(SUBNET).feeding_proxy_attachments(attachments.clone());
        let lease = [100, 64, 0, 9];
        let row = registry.register(BoxRegistration::new(
            "web",
            Ipv4Addr::from(lease),
            Ipv4Addr::LOCALHOST,
        ));
        registry.spawn_withdrawal_drainer();
        let mut harness = gate_over(registry).await;

        // The box's attachment is held before its traffic: issued by the
        // registration, ahead of the row, carrying the box's own id — the
        // one its row holds.
        let attachment = attachments
            .by_source(lease)
            .expect("the registration issued the box's attachment");
        assert_eq!(attachment.switch_addr(), Ipv4Addr::from(lease));
        assert_eq!(
            attachment.box_id(),
            row.box_id(),
            "the attachment carries the box's own id, the one its row holds"
        );
        assert_ne!(
            attachment.box_id(),
            [0u8; 16],
            "the attachment names the box, never the all-zero non-id"
        );

        // The box's frame, admitted by its row: the traffic the
        // connection will attribute.
        let frame = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        send_frame(&mut harness.guest, &frame).await;
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            frame,
            "the box's declared frame reaches the switch"
        );

        // The box's connection ends: the guest closes its side.
        harness
            .guest
            .shutdown()
            .await
            .expect("closing the guest's side");

        // The attachment goes with it, and the row goes with the
        // attachment: withdrawn together, the attachment first.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while attachments.by_source(lease).is_some() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the attachment outlived its shuttle connection past {DEADLINE:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            harness.table.by_source(lease).is_none(),
            "the row went with the attachment: the two are withdrawn together"
        );
    }

    /// NET-138, NET-045: an admit report inside the grant the host-side
    /// registration holds records into the row it named — the port and
    /// protocol pair, idempotently — and the row's derived egress allow-list
    /// answers the declaration's own spelling, the allow-all one when the
    /// declaration named no subnets.
    #[test]
    fn admit_report_recorded_within_host_grant() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([8080])
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999)))
                .with_egress_policy(EgressPolicy {
                    allow_protocols: Some(vec![IpProto::Tcp]),
                    allow_subnets: Some(vec!["10.0.0.0/8".to_string()]),
                    allow_dns_hosts: None,
                    deny_subnets: None,
                }),
        );
        let db = registry.register(
            BoxRegistration::new("db", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Ask, Some((5000, 5999))),
        );

        // The derived allow-list: the declaration's own spelling where the
        // declaration named one, the allow-all one where it did not — the
        // read-only row verb's answer, so a person reads the policy as it
        // was declared.
        assert_eq!(web.egress_allow_list(), ["10.0.0.0/8"]);
        assert_eq!(
            db.egress_allow_list(),
            ["0.0.0.0/0"],
            "an absent allow_subnets dimension is allow-all, the compiled rules' own meaning"
        );

        // A report within the grant records, and answers the row it
        // recorded into — the row a serving line names the box by.
        let now = Instant::now();
        let recorded = registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("a report within the grant records");
        assert_eq!(
            recorded.name(),
            "web",
            "the report is answered with the row it recorded into"
        );
        assert_eq!(
            recorded.runtime_port_numbers(),
            [3000],
            "the recorded port is the row's one runtime-admitted port"
        );
        assert_eq!(
            registry
                .row_by_name("web")
                .expect("the row is live under the name the read resolves by")
                .runtime_port_numbers(),
            [3000],
            "the row the read resolves to carries the recorded port"
        );

        // Idempotent by the port and protocol pair: a report the row already
        // answered records the same fact again, not a second one.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("a duplicate report re-records the same fact");
        assert_eq!(
            web.runtime_port_numbers(),
            [3000],
            "the same port and protocol pair records once, not twice"
        );

        // One port number under two protocols is two admissions — the pair
        // the report names is the unit — and the ask stance records what
        // the attached human answered yes to, inside its own grant.
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Udp, now)
            .expect("the same port under another protocol is another admission");
        assert_eq!(
            web.runtime_port_numbers(),
            [3000],
            "the numbers stay distinct while the pair-keyed set holds two"
        );
        registry
            .admit_runtime_port(db.switch_addr(), 5000, IpProto::Tcp, now)
            .expect("an ask stance records the report the human answered yes to");
        assert_eq!(db.runtime_port_numbers(), [5000]);
    }

    /// NET-138, NET-045: every grant check refuses its own case, naming the
    /// box where a row exists and the check that refused — a report at an
    /// address no row holds, a deny stance (declared or the absent
    /// declaration's default), a stance whose declaration named no range, and
    /// a port outside the range — and a refusal records nothing: not the
    /// port, not a rate timestamp, no fact the host did not already hold.
    #[test]
    fn admit_report_refused_outside_range_or_under_deny() {
        let registry = BoxRegistry::new(SUBNET);
        let allow = registry.register(
            BoxRegistration::new(
                "allow-box",
                Ipv4Addr::new(100, 64, 0, 9),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let denied = registry.register(
            BoxRegistration::new(
                "denied-box",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Deny, Some((3000, 3999))),
        );
        let ungranted = registry.register(BoxRegistration::new(
            "ungranted-box",
            Ipv4Addr::new(100, 64, 0, 11),
            Ipv4Addr::LOCALHOST,
        ));
        let rangeless = registry.register(
            BoxRegistration::new(
                "rangeless-box",
                Ipv4Addr::new(100, 64, 0, 12),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, None),
        );

        // No row at the address the report named: the box is exactly what the
        // report could not prove.
        let refused = registry
            .admit_runtime_port(
                Ipv4Addr::new(100, 64, 0, 99),
                3000,
                IpProto::Tcp,
                Instant::now(),
            )
            .expect_err("a report at an address no row holds is refused");
        assert_eq!(
            refused,
            PortReportRefusal::NoRow {
                switch_addr: Ipv4Addr::new(100, 64, 0, 99),
                port: 3000,
                proto: IpProto::Tcp
            },
            "the refusal names the address no row answered at and the report it refused"
        );
        assert_eq!(
            refused.to_string(),
            "no box row is held at switch address 100.64.0.99; the reported port 3000 records \
             nowhere",
            "the wire carries the refusal's sentence verbatim"
        );

        // The deny stance — and the absent declaration's own default, which
        // is the same stance — admits nothing, whatever its range says.
        let refused = registry
            .admit_runtime_port(denied.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a report under a deny stance is refused");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "denied-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        let refused = registry
            .admit_runtime_port(ungranted.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a registration that carried no grant admits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::DenyStance {
                name: "ungranted-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            },
            "an absent stance is the declaration's deny default, not a permissive one"
        );

        // A stance without a range permits nothing, and a port outside the
        // range is refused naming the range it missed — inclusive at both
        // ends, so the boundaries themselves record.
        let refused = registry
            .admit_runtime_port(rangeless.switch_addr(), 3000, IpProto::Tcp, Instant::now())
            .expect_err("a stance with no range permits nothing");
        assert_eq!(
            refused,
            PortReportRefusal::NoAllowedRange {
                name: "rangeless-box".to_string(),
                port: 3000,
                proto: IpProto::Tcp
            }
        );
        for outside in [2999, 4000] {
            let refused = registry
                .admit_runtime_port(allow.switch_addr(), outside, IpProto::Tcp, Instant::now())
                .expect_err("a report outside the range is refused");
            assert_eq!(
                refused,
                PortReportRefusal::OutsideAllowedRange {
                    name: "allow-box".to_string(),
                    port: outside,
                    proto: IpProto::Tcp,
                    range: (3000, 3999)
                },
                "the range is inclusive, so {outside} alone is outside it"
            );
            assert_eq!(
                refused.to_string(),
                format!(
                    "runtime port {outside} is outside box allow-box's allowed range 3000-3999"
                ),
                "the refusal names the port, the box and the range it missed"
            );
        }
        for boundary in [3000, 3999] {
            registry
                .admit_runtime_port(allow.switch_addr(), boundary, IpProto::Tcp, Instant::now())
                .unwrap_or_else(|refusal| panic!("the range's own ends record, got {refusal}"));
        }

        // Every refusal recorded nothing: no port a refused report named
        // sits on any row it was checked against — the allow row holds only
        // the boundaries that recorded, and the refusals paced no rate
        // timestamp the rows' later reports answer to.
        assert_eq!(
            allow.runtime_port_numbers(),
            vec![3000, 3999],
            "only the range's own ends recorded on the allow row: no refused \
             report's port joined them"
        );
        assert!(
            denied.runtime_port_numbers().is_empty()
                && ungranted.runtime_port_numbers().is_empty()
                && rangeless.runtime_port_numbers().is_empty(),
            "a refused report records no port on any row it was checked against"
        );
        let refused = registry
            .admit_runtime_port(allow.switch_addr(), 3001, IpProto::Tcp, Instant::now())
            .expect("the refusals above did not spend the row's rate");
        assert_eq!(refused.name(), "allow-box");
    }

    /// NET-138: the per-row cap and the per-row admit rate bound what the
    /// reports can do to the host's state. A row holding
    /// [`RUNTIME_PORT_CAP`] ports refuses any report — a duplicate included —
    /// and a row over [`ROW_ADMIT_RATE_PER_SECOND`] recorded reports in a
    /// trailing second refuses until the second passes, while a refusal paces
    /// nothing and a withdrawal never counts.
    #[test]
    fn admit_report_refused_past_row_cap_or_rate() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );

        // The cap: one report per port of a 256-port span, each a second
        // apart — past the rate window, so the cap is the only bound the
        // reports meet — and then the 257th is refused.
        let base = Instant::now();
        for (spent, port) in (3000..3000 + RUNTIME_PORT_CAP as u16).enumerate() {
            registry
                .admit_runtime_port(
                    web.switch_addr(),
                    port,
                    IpProto::Tcp,
                    base + Duration::from_secs(spent as u64),
                )
                .unwrap_or_else(|refusal| {
                    panic!("report {spent} records inside the cap, got {refusal}")
                });
        }
        assert_eq!(
            web.runtime_port_numbers().len(),
            RUNTIME_PORT_CAP,
            "the row holds the cap's worth of runtime ports"
        );
        let refused = registry
            .admit_runtime_port(
                web.switch_addr(),
                3999,
                IpProto::Tcp,
                base + Duration::from_secs(300),
            )
            .expect_err("a report past the cap is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RowCapReached {
                name: "web".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                cap: RUNTIME_PORT_CAP
            }
        );
        let refused = registry
            .admit_runtime_port(
                web.switch_addr(),
                3000,
                IpProto::Tcp,
                base + Duration::from_secs(301),
            )
            .expect_err("a full row refuses a duplicate too");
        assert!(
            matches!(refused, PortReportRefusal::RowCapReached { .. }),
            "the cap applies to duplicates: a full row admits nothing, got {refused}"
        );
        assert_eq!(
            refused.to_string(),
            "box web already holds 256 runtime-admitted ports, its per-row cap; the reported \
             port 3000 records nothing"
        );

        // The rate: a fresh row's own trailing second. Ten distinct ports
        // record in one instant; the eleventh is refused, is still refused
        // half a second later, and records again once the second has passed.
        let ratebound = registry.register(
            BoxRegistration::new(
                "ratebound",
                Ipv4Addr::new(100, 64, 0, 10),
                Ipv4Addr::LOCALHOST,
            )
            .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let at = Instant::now();
        for port in 3000..3000 + ROW_ADMIT_RATE_PER_SECOND as u16 {
            registry
                .admit_runtime_port(ratebound.switch_addr(), port, IpProto::Tcp, at)
                .unwrap_or_else(|refusal| {
                    panic!("report {port} records inside the rate, got {refusal}")
                });
        }
        let refused = registry
            .admit_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp, at)
            .expect_err("the eleventh report inside one second is refused");
        assert_eq!(
            refused,
            PortReportRefusal::RateExceeded {
                name: "ratebound".to_string(),
                port: 3999,
                proto: IpProto::Tcp,
                rate: ROW_ADMIT_RATE_PER_SECOND
            }
        );
        // A refused report paces nothing: the row's window still holds the
        // ten recorded reports, so the half-second mark refuses the same way.
        let refused = registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_millis(500),
            )
            .expect_err("a refused report does not spend the window it was refused in");
        assert!(
            matches!(refused, PortReportRefusal::RateExceeded { .. }),
            "the window holds recorded reports alone: got {refused}"
        );
        registry
            .admit_runtime_port(
                ratebound.switch_addr(),
                3999,
                IpProto::Tcp,
                at + Duration::from_secs(1),
            )
            .expect("the rate is a trailing second, so the second's passing records again");
        assert_eq!(
            ratebound.runtime_port_numbers().len(),
            ROW_ADMIT_RATE_PER_SECOND + 1,
            "eleven ports record across the window's passing"
        );

        // A withdrawal never counts against the rate and is never refused:
        // the eleventh report that the rate refused records the instant a
        // withdrawal answered between it and the window's edge.
        registry
            .withdraw_runtime_port(ratebound.switch_addr(), 3999, IpProto::Tcp)
            .expect("a withdrawal report is answered with the row it named");
    }

    /// NET-138: a withdrawal report removes the port and protocol pair it
    /// named — never refused by the cap or the rate — and a row's withdrawal
    /// takes its runtime set with it structurally: a re-registration at the
    /// same address starts empty, never inheriting the box it replaced's
    /// runtime facts.
    #[test]
    fn runtime_port_withdrawn_on_report_and_on_row_withdrawal() {
        let registry = BoxRegistry::new(SUBNET);
        let web = registry.register(
            BoxRegistration::new("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        let now = Instant::now();
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now)
            .expect("the first report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3001, IpProto::Tcp, now)
            .expect("the second report records");
        registry
            .admit_runtime_port(web.switch_addr(), 3000, IpProto::Udp, now)
            .expect("the third report records");

        // The withdrawal report removes the pair it named and only that pair:
        // the same port number under the other protocol stays — the pair is
        // the unit the report names and the withdrawal removes.
        let row = registry
            .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
            .expect("the withdrawal is answered with the row it named");
        assert_eq!(row.name(), "web");
        assert_eq!(
            web.runtime_port_numbers(),
            [3001, 3000],
            "the withdrawn pair is gone and the same number under the other protocol stays, \
             in report order"
        );

        // Withdrawing a pair the row no longer holds is accepted all the
        // same: the row already at the report's goal state.
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3000, IpProto::Tcp)
                .is_some(),
            "a repeated withdrawal is answered with the row, never refused"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3999, IpProto::Tcp)
                .is_some(),
            "a withdrawal of a port the row never held is accepted: the goal state already holds"
        );

        // The row's own withdrawal takes the runtime set with it: the row is
        // gone, a report at its address finds no row, and the re-registration
        // that follows starts the set empty.
        let removed = registry
            .withdraw(web.switch_addr())
            .expect("the row's withdrawal answers with the row it removed");
        assert_eq!(removed.name(), "web");
        assert!(
            registry.row_by_name("web").is_none(),
            "a withdrawn row is gone, not archived"
        );
        assert!(
            matches!(
                registry.admit_runtime_port(web.switch_addr(), 3000, IpProto::Tcp, now),
                Err(PortReportRefusal::NoRow { .. })
            ),
            "a report at the withdrawn row's address records nowhere"
        );
        assert!(
            registry
                .withdraw_runtime_port(web.switch_addr(), 3001, IpProto::Tcp)
                .is_none(),
            "a withdrawal report after the row's withdrawal answers no row, and is accepted"
        );
        let fresh = registry.register(
            BoxRegistration::new("web", web.switch_addr(), Ipv4Addr::LOCALHOST)
                .with_dynamic_ingress(DynamicIngress::Allow, Some((3000, 3999))),
        );
        assert!(
            fresh.runtime_port_numbers().is_empty(),
            "a re-registration starts the runtime set empty — the newest declaration never \
             inherits the row it replaced's runtime facts"
        );
    }
}
