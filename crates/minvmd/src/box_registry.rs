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

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use sessions::EgressPolicy;
use sessions::core::egress::EgressRules;
use switch::SwitchSubnet;

/// The addresses of one relay's end, as the host reports them: the switch
/// addresses whose relayed traffic that connection carried, for the
/// registry to withdraw by. Reported, not held — the gate has no say over
/// whether a row goes with its report.
type WithdrawalReport = Vec<[u8; 4]>;

/// The guest node namespace's name in the table: the in-VM daemon, whose own
/// root-netns tap [`BoxRegistry::register_node_namespace`] publishes.
const NODE_NAMESPACE: &str = "minimald";

/// The published rows, keyed by switch address in wire octets — the key the
/// gate's per-frame lookup uses, straight off the frame summary. A `BTreeMap`
/// because the row set's order escapes to diagnostics and to
/// [`BoxTable::rows`], and the same declarations must produce the same order
/// every time (a hash map's would vary run to run).
type Rows = BTreeMap<[u8; 4], Arc<BoxRecord>>;

/// One published namespace's row in the host-side table. Of what it holds,
/// two dimensions decide a frame from this namespace's address: its switch
/// address, the lease the shared verdict checks every frame's source against
/// (NET-084), and its compiled egress rules. The rest — its name
/// (diagnostics), its loopback address, the ports it admitted, the names it
/// declared — is the declaration itself, carried for the host-side paths that
/// attach and name the namespace, and for the publish half of the gate, which
/// reads the ports and names as the records a switch publish may carry. Owned
/// outright, so no borrow of a client's declaration survives the registration
/// that built it.
#[derive(Debug, PartialEq, Eq)]
pub struct BoxRecord {
    name: String,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: EgressRules,
    resolves_names: bool,
}

impl BoxRecord {
    /// The namespace's name — what a diagnostic names a row by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
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

    /// Whether the namespace's own relay can lift an undeclared-destination
    /// drop by itself: `true` when its declaration named DNS hosts, because
    /// the name-based admission (`allow_dns_hosts`, NET-066) lives in the
    /// in-guest gate — resolution-time pins, held for their admission window
    /// — and compiles to nothing in the frame rules. A row that named hosts
    /// drops a frame outside its allowed subnets *in the guest* unless its
    /// box's gate holds a pin for the destination, so the host-side verdict
    /// for such a row defers exactly that one drop class to the guest's,
    /// keeping the two decisions consistent for the frames a resolved name
    /// admits. `false` — no names declared — means the guest lifts nothing
    /// either, and the host-side drop is the whole story.
    #[must_use]
    pub fn resolves_names(&self) -> bool {
        self.resolves_names
    }
}

/// A namespace's declaration as it arrives on the host, before any frame
/// exists: the facts a row is compiled from. Builder-shaped (the crate's
/// `VmEgressPolicy` style) because the addresses alone make a namespace and
/// everything else is optional.
#[derive(Debug, Clone)]
pub struct BoxRegistration {
    name: String,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    admitted_ports: Vec<u16>,
    declared_names: Vec<String>,
    egress: Option<EgressPolicy>,
}

impl BoxRegistration {
    /// A declaration for the namespace `name`, addressed at `switch_addr` on
    /// the switch and `loopback_addr` on the guest's loopback. The egress
    /// policy is absent (allow-all, the shipped default) until
    /// [`with_egress_policy`](Self::with_egress_policy) declares one.
    #[must_use]
    pub fn new(name: impl Into<String>, switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> Self {
        Self {
            name: name.into(),
            switch_addr,
            loopback_addr,
            admitted_ports: Vec::new(),
            declared_names: Vec::new(),
            egress: None,
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
            withdrawal_reports: self.withdrawal_reports.clone(),
            withdrawal_reports_rx: Mutex::new(None),
            next_switch_addr: Arc::clone(&self.next_switch_addr),
            next_loopback_addr: Arc::clone(&self.next_loopback_addr),
            loopback_slice: self.loopback_slice,
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
            withdrawal_reports: reports,
            withdrawal_reports_rx: Mutex::new(Some(reports_rx)),
            next_switch_addr: Arc::new(AtomicU32::new(hand_out_run(subnet).0)),
            next_loopback_addr: Arc::new(AtomicU32::new(
                loopback_slice.map_or(0, |slice| u32::from(slice.first())),
            )),
            loopback_slice,
        }
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
    /// A row that declared DNS hosts is announced once, here, at `info`: its
    /// undeclared-destination drop is the one class the host-side gate
    /// defers to the guest's ([`BoxRecord::resolves_names`]), and the host's
    /// log says so where the row enters the table rather than leaving it to
    /// be inferred from a frame that reached the switch. The line goes away
    /// with the deferral: moving that decision host-side is #1808's task.
    ///
    /// # Panics
    ///
    /// Never: the row lock is only ever held across this map update, never
    /// across a panic.
    pub fn register(&self, registration: BoxRegistration) -> Arc<BoxRecord> {
        // The name-based admission lives in the guest's gate, not in the
        // frame rules: whether this row's host-side verdict may defer the
        // undeclared-destination drop to the in-guest one is the
        // declaration's own fact, read off the policy here and carried
        // beside the rules for the verdict to consult.
        let resolves_names = registration
            .egress
            .as_ref()
            .and_then(|policy| policy.allow_dns_hosts.as_ref())
            .is_some_and(|hosts| !hosts.is_empty());
        if resolves_names {
            tracing::info!(
                switch_addr = %registration.switch_addr,
                name = %registration.name,
                "the row declared DNS hosts: its undeclared-destination rule is deferred to \
                 the guest's gate, because names resolve in-VM (#1808 moves it host-side)"
            );
        }
        let record = Arc::new(BoxRecord {
            name: registration.name,
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
            switch_addr: registration.switch_addr,
            loopback_addr: registration.loopback_addr,
            admitted_ports: registration.admitted_ports,
            declared_names: registration.declared_names,
        });
        self.rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .insert(record.switch_addr.octets(), Arc::clone(&record));
        record
    }

    /// Withdraws the row published for `switch_addr`, returning it when one
    /// was held. From here on the gate holds no namespace at that address, and
    /// no rules are decided by it: withdrawing is how the host retires a
    /// namespace's declaration, never a way to leave its address attributed.
    ///
    /// What the address's frames do next is the phase's to say
    /// ([`crate::net::egress_gate`]): under the per-box default they are
    /// dropped as any other unknown source's (NET-081's failure case), while
    /// the announced interim this build ships — which keeps own-address boxes
    /// alive until the creator-side registration (T66, #1711) supplies their
    /// rows — admits an address inside the plan's lease block, so a
    /// withdrawal inside that block costs the address no reach until the
    /// default binds. The row is gone either way, and a re-registration starts
    /// from the newest declaration.
    pub fn withdraw(&self, switch_addr: Ipv4Addr) -> Option<Arc<BoxRecord>> {
        self.rows
            .write()
            .expect("the row lock is never held across a panic, so it cannot be poisoned")
            .remove(&switch_addr.octets())
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
    /// decided by its rules; what a box with **no** row runs as — one whose
    /// registration never reached the daemon, or whose row was withdrawn —
    /// is the gate's announced unregistered-source interim, and putting the
    /// per-box default that eventually refuses it in force is the flip that
    /// lands with the last row source (T66's follow-up), not a change this
    /// registration makes.
    pub fn register_client_box(
        &self,
        spec: ClientBoxSpec,
    ) -> Result<Arc<BoxRecord>, AllocationError> {
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
        Ok(self.register(registration))
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
    /// ([`Self::withdraw`]).
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
        Ok(rows.remove(&switch_addr.octets()))
    }

    /// Publishes the guest **node's** own namespace: the in-VM daemon's
    /// root-netns tap, the plane design §5.1 names node-plane. The address is
    /// the host's own derivation from the subnet it configured the switch
    /// with ([`SwitchSubnet::daemon_ip`]) — the guest is neither asked nor
    /// able to influence what this row holds.
    ///
    /// The admitted ports are the two the daemon's own setup publishes at
    /// its address: the hostname proxy's and the zone answerer's, both
    /// assigned by the VM host before the VM boots
    /// ([`crate::cmd::run`] hands them to the guest on the kernel command
    /// line) and bound by the guest daemon as handed — so the publishes the
    /// daemon makes to attach them are publishes of ports this row already
    /// names, not requests for the host to open its own.
    ///
    /// The rules are the allow-all interim the absent-policy default ships:
    /// the node-plane baseline set is un-enrolled until NET-130's enumeration
    /// lands, and until then the daemon keeps the reach it had before the
    /// gate existed — its own package fetches above all, which is the
    /// VM-side shape of NET-080. NET-130 tightens this row to the categories
    /// design §5.1 enumerates.
    pub fn register_node_namespace(&self, proxy_port: u16, answerer_port: u16) -> Arc<BoxRecord> {
        self.register(
            BoxRegistration::new(NODE_NAMESPACE, self.subnet.daemon_ip(), Ipv4Addr::LOCALHOST)
                .with_admitted_ports([proxy_port, answerer_port]),
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
    /// (and a row whose traffic never ends is never withdrawn). The thread
    /// holds a clone of this registry, so it withdraws the same rows
    /// every other handle sees, and it runs until the reports' senders are
    /// all gone — the gate and every table handed out — because that is
    /// when there is nothing left to withdraw.
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
    /// reserve address and stays an unregistered source the interim admits;
    /// the host hands registered boxes only from the upper half
    /// (`hand_out_run`). The subnet's own infrastructure sits outside that
    /// run: the gateway the resolver carve-out is keyed to, the host alias,
    /// and the guest daemon's own tap, which the registry publishes a row for
    /// itself. The announced interim the gate ships admits an unregistered
    /// source only here, so no amount of it can borrow the plan's
    /// infrastructure as a source; the per-box default that replaces the
    /// interim admits nothing, and this predicate is what keeps the
    /// difference between them one address range wide.
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

#[cfg(test)]
mod tests {
    use sessions::IpProto;
    use sessions::core::egress::FrameVerdict;
    use switch::SwitchSubnet;

    use crate::net::egress_gate::test_support::{
        arp_frame, expect_frame, expect_silence, gate_over, ipv4_frame, send_frame,
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
        let node = registry.register_node_namespace(7654, 7656);

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
            [7654, 7656],
            "the node's row names the proxy and answerer ports the VM host \
             assigned and handed over, so the daemon's own publishes are \
             publishes of ports the row already declares"
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
                    }),
                    Err(AllocationError::LoopbackExhausted)
                ),
                "exhaustion is explicit and never wraps"
            );
        }
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
        registry.register_node_namespace(7654, 7656);
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
        // made-up lease by the announced interim, the node's by its row, and
        // the foreign ARP by rule 0 — and the marker after them proves the
        // whole lot was decided before the comparison.
        let undeclared = ipv4_frame(lease, 6, [203, 0, 113, 7], 443);
        let unknown = ipv4_frame([100, 64, 0, 99], 6, [10, 1, 2, 3], 80);
        let node_frame = ipv4_frame(SUBNET.daemon_ip().octets(), 6, [10, 1, 2, 3], 80);
        let foreign_arp = arp_frame([203, 0, 113, 7]);
        let marker = ipv4_frame(lease, 6, [10, 1, 2, 3], 80);
        for frame in [&undeclared, &unknown, &node_frame, &foreign_arp] {
            send_frame(&mut harness.guest, frame).await;
        }
        send_frame(&mut harness.guest, &marker).await;
        // What the gate admitted, in order: the made-up lease — admitted by
        // the announced interim, which is what keeps an own-address box whose
        // row no creator has supplied yet on the wire — then the node
        // namespace's frame, then the published box's marker. The undeclared
        // frame and the foreign ARP are simply absent.
        assert_eq!(
            expect_frame(&mut harness.switch).await,
            unknown,
            "the announced interim admits an in-plan lease no row holds, until \
             T66 (#1711) supplies the creator-side rows"
        );
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
            "the guest's made-up address published no row — the interim that \
             admitted its frame published nothing either"
        );
    }
}
