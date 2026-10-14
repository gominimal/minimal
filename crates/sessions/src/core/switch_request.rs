//! The publish-verb decision for the host-side egress gate (NET-081).
//!
//! The frame half of the gate decides every frame a box sends *out*;
//! [`super::egress`] is that decision. The other half is what the in-VM
//! daemon asks the switch to do on the host's behalf — publish a port
//! forwarder (`/services/forwarder/expose`), retract one
//! (`/services/forwarder/unexpose`), publish zone names
//! (`/services/dns/add`) — and this module is that half's decision: one pure
//! function, [`applied`], over an owned request [`SwitchRequest`], an owned
//! table [`SwitchTable`] (the host-side rows NET-138 fills), and the
//! unregistered-source phase the build ships. Nothing here knows about
//! sockets, HTTP, JSON, or clocks, which is what lets the Kani harness below
//! exhaust it.
//!
//! What the decision encodes, per verb:
//!
//! * **A publish is applied only where a row holds the address** — the
//!   switch address the request names (a forwarder's remote, a zone record's
//!   address) must be a published namespace's own address, and every record
//!   the request carries must be one that row admits: a port among the
//!   ports its declarations name, a name among the names it declares. A
//!   request asking to publish past a namespace's declaration is refused —
//!   the host's ports are the host's own, and the guest's say over which of
//!   them forward into the VM stops at what the host published.
//! * **An address no row holds is the phase's to decide** — the same
//!   cutover the frame half models with [`EgressDefaultPhase`]. Under the
//!   announced interim a publish at an address inside the plan's lease
//!   block is applied — the reach the box's own daemon had before the gate
//!   existed, which the in-guest relay still bounds — and everything
//!   outside the block is refused under either phase. With the per-box
//!   default in force, as this build ships it (the creator-side
//!   registration, T66, #1711, supplies the rows), only row-held addresses
//!   publish at all.
//! * **A retract is decided by the row at its own address, against what the
//!   row's runtime published** — the address a retraction's summary carries
//!   is the publication's own: the gate attributes each retraction to the
//!   address the publish it retracts was applied at, because the wire itself
//!   carries only the listener. The row it lands on is read by a different
//!   dimension than a publish's: a retraction is applied only when every
//!   record it names is in the row's *runtime-published* set — the ports the
//!   box's own listens published (NET-016, NET-017), which the guest may
//!   withdraw again — and refused with [`Refusal::Unheld`] otherwise. A
//!   declared port is never in that set: its forward is a bind the host
//!   holds for the session's lifetime, unbound only by host-side ingress
//!   revocation (design §7.1, NET-121), so no guest request withdraws it,
//!   and the refusal is the same whether the row declares the port or not.
//!   The runtime set is empty until listen-publishing lands. A retraction at
//!   an address no row holds is the phase's: refused when the phase grants
//!   no interim, applied under the announced interim inside the plan's lease
//!   block — the publications whose rows are still to come are the ones
//!   whose teardowns must work, and retracting what does not exist is a
//!   no-op on the switch.
//!
//! The record a request carries is a **port number or a name index**: the
//! port the forwarder listens on or dials, the name's index in the
//! per-decision dictionary the gate builds from the rows' declared names and
//! the request's own. Indices, not strings, are what the decision compares —
//! the arithmetic stays integer-only so the harness can exhaust it; the
//! gate owns the strings and renders them on the log lines.

use crate::EgressDefaultPhase;

/// How many records one request summary carries: the widest shape the
/// daemon's own client sends is two — the expose's listener and dial ports,
/// or the zone-add's two names — and four leaves headroom without making
/// the summary unbounded. A request with more is refused by the gate's
/// parse, not truncated here: a truncated request is a different request.
pub const MAX_REQUEST_RECORDS: usize = 4;

/// What the daemon asks the switch to do — the three verbs the control
/// socket carries, and the only ones the gate relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum SwitchVerb {
    /// `POST /services/forwarder/expose`: publish a host-port forwarder at
    /// the switch address the request names.
    Publish,
    /// `POST /services/forwarder/unexpose`: retract a forwarder, named by
    /// the listener it bound. The wire carries no address, so the summary's
    /// address is the one the gate attributes the retraction to — the
    /// address the publish it retracts was applied at — and the summary is
    /// decided by the row there, against the ports its runtime published.
    Retract,
    /// `POST /services/dns/add`: publish the zone records' names at the
    /// address the records carry.
    PublishName,
}

/// One record a request asks the table to admit. Ports are the forwarder's
/// two ends (the host-side listener, the in-VM dial); names are indices into
/// the per-decision dictionary, not the strings themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Record {
    /// A port number: the listener a publish binds, the port it dials, or
    /// the listener a retraction names.
    Port(u16),
    /// A name's index in the gate's per-decision dictionary.
    Name(u8),
}

/// The summary of one control request the gate decided on, owned outright:
/// no borrow of the head or body survives the extraction, so the decision is
/// a pure function of this value plus the table and the phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct SwitchRequest {
    verb: SwitchVerb,
    /// The switch address the request publishes at: the forwarder's remote
    /// for an expose, the zone records' address for a name publish, and for
    /// a retraction the address the gate attributes it to — the publication's
    /// own, or the unspecified address when the gate holds no publication
    /// for the forward the retraction names.
    switch_addr: [u8; 4],
    /// The records the request carries, in the order the wire gave them;
    /// the trailing slots are `None`.
    records: [Option<Record>; MAX_REQUEST_RECORDS],
}

impl SwitchRequest {
    /// Builds the summary of a request carrying `records`; `None` when the
    /// request is wider than the summary holds, which the gate refuses
    /// rather than truncates — a truncated request is a different request.
    #[must_use]
    pub fn of(verb: SwitchVerb, switch_addr: [u8; 4], records: &[Record]) -> Option<Self> {
        if records.len() > MAX_REQUEST_RECORDS {
            return None;
        }
        let mut slots = [const { None }; MAX_REQUEST_RECORDS];
        for (slot, record) in slots.iter_mut().zip(records) {
            *slot = Some(*record);
        }
        Some(Self {
            verb,
            switch_addr,
            records: slots,
        })
    }

    /// The verb the request speaks.
    #[must_use]
    pub fn verb(&self) -> SwitchVerb {
        self.verb
    }

    /// The switch address the request publishes at, unspecified for a
    /// retraction.
    #[must_use]
    pub fn switch_addr(&self) -> [u8; 4] {
        self.switch_addr
    }

    /// The records the request carries, in wire order.
    pub fn records(&self) -> impl Iterator<Item = Record> + '_ {
        self.records.iter().flatten().copied()
    }
}

/// One published namespace, as the decision reads it: the row NET-138's
/// table holds for a switch address, with the publish dimension the
/// registration path filled in — the ports the namespace's declarations
/// name (the union of the listener and dial ports its ingress mappings
/// carry), and the names it declares, as indices in the same dictionary the
/// request's name records index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchRow {
    switch_addr: [u8; 4],
    /// The ports the row admits publishing at its address. An empty list
    /// admits nothing: the publish dimension is an enumeration of what the
    /// namespace declared, not an allow-all default.
    ports: Vec<u16>,
    /// The names the row declares, as dictionary indices.
    names: Vec<u8>,
    /// The ports the row's runtime published — the box's own listens
    /// (NET-016, NET-017) — and so the only records a retraction at the
    /// row's address is applied for. Disjoint in meaning from `ports`: a
    /// declared port's forward is held for the session's lifetime and no
    /// guest request withdraws it. Empty until listen-publishing lands.
    published: Vec<u16>,
}

impl SwitchRow {
    /// A row published for `switch_addr`, admitting `ports` and declaring
    /// `names`, whose runtime has published nothing yet.
    #[must_use]
    pub fn of(switch_addr: [u8; 4], ports: Vec<u16>, names: Vec<u8>) -> Self {
        Self {
            switch_addr,
            ports,
            names,
            published: Vec::new(),
        }
    }

    /// The row with `published` as the ports its runtime published: the
    /// set a retraction at its address is decided against.
    #[must_use]
    pub fn with_published(mut self, published: Vec<u16>) -> Self {
        self.published = published;
        self
    }

    /// Whether the row admits `record`: the port among its declared ports,
    /// or the name among its declared names.
    #[must_use]
    fn holds(&self, record: Record) -> bool {
        match record {
            Record::Port(port) => self.ports.contains(&port),
            Record::Name(name) => self.names.contains(&name),
        }
    }

    /// Whether the row's runtime published `record`: the port among its
    /// listen-published ports. A name is never a runtime publication — no
    /// verb retracts one — so no name is.
    #[must_use]
    fn publishes(&self, record: Record) -> bool {
        match record {
            Record::Port(port) => self.published.contains(&port),
            Record::Name(_) => false,
        }
    }
}

/// The table the decision decides against: the rows published on the host,
/// and the plan's lease bounds — the one address range the announced
/// interim admits an unregistered publish inside, mirroring the frame
/// half's [`crate::core::egress`] lease block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwitchTable {
    rows: Vec<SwitchRow>,
    first_ptask: [u8; 4],
    last_ptask: [u8; 4],
}

impl SwitchTable {
    /// A table holding `rows`, whose plan leases from `first_ptask` through
    /// `last_ptask`.
    #[must_use]
    pub fn of(rows: Vec<SwitchRow>, first_ptask: [u8; 4], last_ptask: [u8; 4]) -> Self {
        Self {
            rows,
            first_ptask,
            last_ptask,
        }
    }

    /// The row published for `addr`, when one is.
    #[must_use]
    fn row_at(&self, addr: [u8; 4]) -> Option<&SwitchRow> {
        self.rows.iter().find(|row| row.switch_addr == addr)
    }

    /// Whether the plan could ever hand `addr` to a box: inside the lease
    /// run the rows are keyed by. The plan's own infrastructure — the
    /// gateway, the host alias, the node's own tap — sits outside it, and
    /// no interim reaches it.
    #[must_use]
    fn in_plan(&self, addr: [u8; 4]) -> bool {
        self.first_ptask <= addr && addr <= self.last_ptask
    }
}

/// What the gate applied a request by — the row that holds the address (or,
/// for a retraction, a record it declares), or the announced interim's
/// default. The relay that applies this distinguishes the two for the one
/// thing only the interim's application owes: a line that says it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// A published row admitted the request — its address holds it and
    /// every record it carries is one the row admits.
    Row,
    /// The announced interim applied the request: the address it publishes
    /// at is one the plan could lease but no row holds, so no row's
    /// declaration was consulted. The relay says so, rate-limited, naming
    /// T66 (#1711).
    Interim,
}

/// Why the gate refused a request: the one class per way a request can fail
/// the table, each carrying what the refusal line names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The address the request publishes at is held by no row, and the
    /// phase's interim does not admit it: outside the plan's lease block,
    /// or the per-box default in force.
    UnknownAddress {
        /// The address no row holds.
        addr: [u8; 4],
    },
    /// A row holds the address, but not every record the request carries;
    /// `record` is the first one it does not admit. The request asks the
    /// switch to publish past the namespace's declaration.
    Undeclared {
        /// The address whose row refused the record.
        addr: [u8; 4],
        /// The first record the row does not admit.
        record: Record,
    },
    /// A retraction the table refuses. Two shapes share it: no published
    /// row holds the address the retraction carries and the phase's interim
    /// does not admit it, or the row holding that address did not publish
    /// every record the retraction names at runtime — the retraction asks
    /// to withdraw what the guest never published there, a declared port's
    /// lifetime forward included. `record` is the first record the row's
    /// runtime did not publish when one holds the address, and `None` when
    /// no row held it (or the retraction carried no record at all — a shape
    /// the wire parse never builds, refused closed).
    Unheld {
        /// The address the retraction carries.
        addr: [u8; 4],
        /// The first record the row holding `addr` did not publish at
        /// runtime, when a row holds it.
        record: Option<Record>,
    },
}

impl std::fmt::Display for Refusal {
    /// The reason one refusal line carries, after its address and its port
    /// or name.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::UnknownAddress { .. } => {
                f.write_str("no published namespace holds the address it publishes at")
            }
            Self::Undeclared { .. } => {
                f.write_str("the namespace holding its address does not admit it")
            }
            Self::Unheld {
                record: Some(_), ..
            } => f.write_str("nothing published at its address admits what it retracts"),
            Self::Unheld { record: None, .. } => {
                f.write_str("nothing is published at the address it retracts at")
            }
        }
    }
}

/// The gate's apply-or-refuse decision for one control request against the
/// host-side table (NET-081's publish half): pure — a function of the
/// request, the table, and the phase, nothing else — and deliberately
/// separate from the relay loop that applies it, the same discipline the
/// frame verdict keeps.
///
/// The address is the whole of the routing for every verb: the row that
/// holds it supplies the records the request is decided by, and an address
/// no row holds is the phase's to decide ([`EgressDefaultPhase`] carries
/// what that means and why). A retraction's summary carries the address the
/// gate attributes it to — the publication's own — and is routed to the row
/// there like a publish, but decided by that row's runtime-published set,
/// not its declaration: applied when the row's runtime published every
/// record it names, refused otherwise. A declared port is never in the
/// runtime set, so a guest request never withdraws a declared forward.
///
/// # Errors
///
/// Returns [`Refusal::UnknownAddress`] when a publish names an address no
/// row of the table holds and the phase grants it no interim, and
/// [`Refusal::Undeclared`] when the row that holds the address does not
/// admit the port or name the request publishes. A retraction is refused
/// with [`Refusal::Unheld`] when no published namespace holds the address it
/// carries and the phase grants it no interim, or when the row holding that
/// address did not publish every record it names at runtime.
pub fn applied(
    request: &SwitchRequest,
    table: &SwitchTable,
    phase: EgressDefaultPhase,
) -> Result<Applied, Refusal> {
    match request.verb() {
        SwitchVerb::Publish | SwitchVerb::PublishName => {
            let addr = request.switch_addr();
            let Some(row) = table.row_at(addr) else {
                // No row holds the address. Inside the plan's lease block
                // the announced interim applied the publish, before the
                // creator-side registration (T66, #1711) published each
                // box's row. Outside that block, or with the default in
                // force, the failure case: an address no namespace holds
                // never gains a publication.
                if phase == EgressDefaultPhase::Announced && table.in_plan(addr) {
                    return Ok(Applied::Interim);
                }
                return Err(Refusal::UnknownAddress { addr });
            };
            let Some(record) = request.records().find(|record| !row.holds(*record)) else {
                return Ok(Applied::Row);
            };
            Err(Refusal::Undeclared { addr, record })
        }
        SwitchVerb::Retract => {
            // A retraction is routed to the row at the address its summary
            // carries — the publication's own — as a publish is: the
            // teardown it asks for is the owner's, never whoever else's row
            // happens to declare the same listener. The unspecified address
            // a retraction the gate could not attribute carries is read like
            // any other: no row holds it, it is outside the plan's lease
            // block, and nothing is applied by it.
            let addr = request.switch_addr();
            let Some(row) = table.row_at(addr) else {
                if phase == EgressDefaultPhase::Announced && table.in_plan(addr) {
                    return Ok(Applied::Interim);
                }
                return Err(Refusal::Unheld {
                    addr,
                    record: request.records().next(),
                });
            };
            // The row decides by what its runtime published, not by what it
            // declares: a declared port's forward is held for the session's
            // lifetime and withdrawn only by host-side ingress revocation
            // (design §7.1, NET-121), so the guest's say stops at the ports
            // its own listens published.
            let Some(record) = request.records().find(|record| !row.publishes(*record)) else {
                return Ok(Applied::Row);
            };
            Err(Refusal::Unheld {
                addr,
                record: Some(record),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Applied, EgressDefaultPhase, MAX_REQUEST_RECORDS, Record, Refusal, SwitchRequest,
        SwitchRow, SwitchTable, SwitchVerb, applied,
    };

    /// The plan every table below is built for: the lease run
    /// `100.64.0.10`–`100.64.0.20`. The infrastructure addresses sit
    /// outside it — the node's tap at `100.64.0.1`, the gateway at
    /// `100.64.0.2` — which is what keeps them out of every interim's
    /// reach.
    const FIRST_PTASK: [u8; 4] = [100, 64, 0, 10];
    const LAST_PTASK: [u8; 4] = [100, 64, 0, 20];
    /// The node namespace's own address, inside the plan's infrastructure
    /// and outside the lease run.
    const NODE_ADDR: [u8; 4] = [100, 64, 0, 1];
    /// A lease address the plan could hand to a box, held by no row below
    /// unless one is built for it.
    const FREE_LEASE: [u8; 4] = [100, 64, 0, 12];
    /// A lease address a published row holds.
    const ROW_LEASE: [u8; 4] = [100, 64, 0, 15];

    /// The node's row: the ports the VM host assigned it (the proxy's, the
    /// answerer's), no declared names — the shape [`crate`]'s node
    /// registration builds.
    fn node_row() -> SwitchRow {
        SwitchRow::of(NODE_ADDR, vec![7654, 7656], Vec::new())
    }

    /// A box's row at [`ROW_LEASE`]: one declared listener (`8080`), one
    /// declared name, nothing published at runtime.
    fn box_row() -> SwitchRow {
        SwitchRow::of(ROW_LEASE, vec![8080], vec![0])
    }

    /// The port a box's own listen published at runtime — the one record
    /// the guest may withdraw again — never a declared one.
    const LISTEN_PORT: u16 = 3000;

    /// [`box_row`] whose runtime published [`LISTEN_PORT`]: the shape
    /// listen-publishing will fill in.
    fn listening_box_row() -> SwitchRow {
        box_row().with_published(vec![LISTEN_PORT])
    }

    fn table(rows: Vec<SwitchRow>) -> SwitchTable {
        SwitchTable::of(rows, FIRST_PTASK, LAST_PTASK)
    }

    fn publish(addr: [u8; 4], records: &[Record]) -> SwitchRequest {
        SwitchRequest::of(SwitchVerb::Publish, addr, records)
            .expect("two port records fit the summary")
    }

    fn publish_name(addr: [u8; 4], records: &[Record]) -> SwitchRequest {
        SwitchRequest::of(SwitchVerb::PublishName, addr, records)
            .expect("two name records fit the summary")
    }

    /// A retraction of `record`, carried at `addr` — the address the gate
    /// attributes it to, which under the keyed decision is the publication's
    /// own.
    fn retract(addr: [u8; 4], record: Record) -> SwitchRequest {
        SwitchRequest::of(SwitchVerb::Retract, addr, &[record])
            .expect("one port record fits the summary")
    }

    #[test]
    fn switch_request_applied_only_when_table_admits() {
        a_held_address_publishes_what_its_row_admits();
        a_held_address_refuses_what_its_row_omits();
        an_unheld_address_publishes_as_its_phase_decides();
        a_retraction_is_applied_by_what_the_row_at_its_address_published();
        retract_of_declared_port_refused();
        a_retraction_of_a_record_its_row_never_published_is_refused();
        an_unheld_address_retracts_as_its_phase_decides();
        a_wider_request_has_no_summary();
    }

    /// The rollout phases every publish and retraction case is decided under.
    fn both_phases() -> [EgressDefaultPhase; 2] {
        [EgressDefaultPhase::Announced, EgressDefaultPhase::InForce]
    }

    /// A publish where a row holds the address, of ports the row admits:
    /// applied by the row, under either phase.
    fn a_held_address_publishes_what_its_row_admits() {
        let t = table(vec![node_row(), box_row()]);
        for phase in both_phases() {
            assert_eq!(
                applied(
                    &publish(NODE_ADDR, &[Record::Port(7654), Record::Port(7654)]),
                    &t,
                    phase
                ),
                Ok(Applied::Row),
                "the node's own publish is applied by its row under {phase:?}"
            );
            assert_eq!(
                applied(
                    &publish(ROW_LEASE, &[Record::Port(8080), Record::Port(8080)]),
                    &t,
                    phase
                ),
                Ok(Applied::Row),
                "a declared mapping's publish is applied by its row under {phase:?}"
            );
            assert_eq!(
                applied(
                    &publish_name(ROW_LEASE, &[Record::Name(0), Record::Name(0)]),
                    &t,
                    phase
                ),
                Ok(Applied::Row),
                "a declared name's publish is applied by its row under {phase:?}"
            );
        }
    }

    /// A publish of a port the row does not admit: refused, naming the first
    /// offending record — the host's ports stop at what the host published.
    fn a_held_address_refuses_what_its_row_omits() {
        let t = table(vec![node_row(), box_row()]);
        for phase in both_phases() {
            assert_eq!(
                applied(
                    &publish(NODE_ADDR, &[Record::Port(8080), Record::Port(8080)]),
                    &t,
                    phase,
                ),
                Err(Refusal::Undeclared {
                    addr: NODE_ADDR,
                    record: Record::Port(8080),
                }),
                "a port the node's row never declared is refused under {phase:?}"
            );
            assert_eq!(
                applied(
                    &publish(ROW_LEASE, &[Record::Port(8080), Record::Port(22)]),
                    &t,
                    phase
                ),
                Err(Refusal::Undeclared {
                    addr: ROW_LEASE,
                    record: Record::Port(22),
                }),
                "a dial port the row never declared is refused under {phase:?}"
            );
            assert_eq!(
                applied(&publish_name(ROW_LEASE, &[Record::Name(1)]), &t, phase),
                Err(Refusal::Undeclared {
                    addr: ROW_LEASE,
                    record: Record::Name(1),
                }),
                "a name the row never declared is refused under {phase:?}"
            );
            // A publish cannot borrow the node's ports onto another
            // namespace's address either: the row that holds the address is
            // the only one consulted.
            assert_eq!(
                applied(
                    &publish(ROW_LEASE, &[Record::Port(7654), Record::Port(7654)]),
                    &t,
                    phase
                ),
                Err(Refusal::Undeclared {
                    addr: ROW_LEASE,
                    record: Record::Port(7654),
                }),
                "the node's ports are not another namespace's to publish under {phase:?}"
            );
        }
    }

    /// A publish at an address no row holds: the phase decides. Inside the
    /// lease run the announced interim applies it; the per-box default
    /// refuses it. Outside the run — the node's own address unregistered,
    /// the gateway, anything past the plan — both phases refuse.
    fn an_unheld_address_publishes_as_its_phase_decides() {
        let t = table(vec![node_row()]);
        assert_eq!(
            applied(
                &publish(FREE_LEASE, &[Record::Port(8080), Record::Port(8080)]),
                &t,
                EgressDefaultPhase::Announced
            ),
            Ok(Applied::Interim),
            "an in-plan publish no row holds is applied under the announced interim"
        );
        assert_eq!(
            applied(
                &publish(FREE_LEASE, &[Record::Port(8080), Record::Port(8080)]),
                &t,
                EgressDefaultPhase::InForce
            ),
            Err(Refusal::UnknownAddress { addr: FREE_LEASE }),
            "an in-plan publish no row holds is refused once the default binds"
        );
        for phase in both_phases() {
            assert_eq!(
                applied(
                    &publish([100, 64, 0, 2], &[Record::Port(8080), Record::Port(8080)]),
                    &t,
                    phase
                ),
                Err(Refusal::UnknownAddress {
                    addr: [100, 64, 0, 2]
                }),
                "the gateway is not a publishable address under {phase:?}"
            );
            assert_eq!(
                applied(
                    &publish([192, 0, 2, 9], &[Record::Port(8080), Record::Port(8080)]),
                    &t,
                    phase
                ),
                Err(Refusal::UnknownAddress {
                    addr: [192, 0, 2, 9]
                }),
                "an address outside the plan is not a publishable one under {phase:?}"
            );
            assert_eq!(
                applied(
                    &publish_name(FREE_LEASE, &[Record::Name(0)]),
                    &t,
                    EgressDefaultPhase::Announced
                ),
                Ok(Applied::Interim),
                "an in-plan name publish no row holds is applied under the interim"
            );
        }
    }

    /// A retraction is routed to the row at the address it carries — the
    /// publication's own — and applied by what that row's runtime
    /// published: a port the box's own listen published is the guest's to
    /// withdraw, under either phase.
    fn a_retraction_is_applied_by_what_the_row_at_its_address_published() {
        let t = table(vec![node_row(), listening_box_row()]);
        for phase in both_phases() {
            assert_eq!(
                applied(&retract(ROW_LEASE, Record::Port(LISTEN_PORT)), &t, phase),
                Ok(Applied::Row),
                "a listen-published port's retraction is applied by its row under {phase:?}"
            );
        }
    }

    /// A declared port is never the guest's to withdraw: its forward is a
    /// bind the host holds for the session's lifetime, unbound only by
    /// host-side ingress revocation (design §7.1, NET-121). A retraction of
    /// it at the row's own address — the shape a guest's unexpose of a
    /// declared forward takes once the gate attributes it — is refused under
    /// either phase, with the refusal an unpublished record carries, whether
    /// the row's runtime published other ports or none; and the node's own
    /// assigned ports are declared ones too.
    fn retract_of_declared_port_refused() {
        for rows in [
            vec![node_row(), box_row()],
            vec![node_row(), listening_box_row()],
        ] {
            let t = table(rows);
            for phase in both_phases() {
                assert_eq!(
                    applied(&retract(ROW_LEASE, Record::Port(8080)), &t, phase),
                    Err(Refusal::Unheld {
                        addr: ROW_LEASE,
                        record: Some(Record::Port(8080)),
                    }),
                    "a declared port's retraction is refused at its own row under {phase:?}"
                );
                assert_eq!(
                    applied(&retract(NODE_ADDR, Record::Port(7654)), &t, phase),
                    Err(Refusal::Unheld {
                        addr: NODE_ADDR,
                        record: Some(Record::Port(7654)),
                    }),
                    "the node's assigned port's retraction is refused at its row under {phase:?}"
                );
            }
        }
    }

    /// A retraction at an address whose row never published the record it
    /// names is refused, under either phase — even when some *other* row
    /// published or declares the record: a retraction is the owner's
    /// teardown, not a withdrawal justified by a namespace the publication
    /// does not belong to.
    fn a_retraction_of_a_record_its_row_never_published_is_refused() {
        let t = table(vec![node_row(), listening_box_row()]);
        for phase in both_phases() {
            assert_eq!(
                applied(&retract(ROW_LEASE, Record::Port(7654)), &t, phase),
                Err(Refusal::Unheld {
                    addr: ROW_LEASE,
                    record: Some(Record::Port(7654)),
                }),
                "a retraction justified only by the node's row is refused under {phase:?}"
            );
            assert_eq!(
                applied(&retract(NODE_ADDR, Record::Port(LISTEN_PORT)), &t, phase),
                Err(Refusal::Unheld {
                    addr: NODE_ADDR,
                    record: Some(Record::Port(LISTEN_PORT)),
                }),
                "a retraction justified only by the box's row is refused under {phase:?}"
            );
            // The scan is over the retraction's own records: the first one
            // its row did not publish is the one the refusal names.
            let two = SwitchRequest::of(
                SwitchVerb::Retract,
                ROW_LEASE,
                &[Record::Port(LISTEN_PORT), Record::Port(22)],
            )
            .expect("two port records fit the summary");
            assert_eq!(
                applied(&two, &t, phase),
                Err(Refusal::Unheld {
                    addr: ROW_LEASE,
                    record: Some(Record::Port(22)),
                }),
                "the refusal names the first record the row did not publish under {phase:?}"
            );
        }
    }

    /// A retraction at an address no row holds: the phase decides, as for a
    /// publish. Inside the lease run the announced interim applies it — the
    /// teardowns of publications whose rows are still to come, and of
    /// publications whose rows a withdrawal has just retired, must work —
    /// and the per-box default refuses it. Outside the run — the gateway,
    /// anything past the plan, and the unspecified address a retraction the
    /// gate could not attribute carries — both phases refuse: a retraction
    /// at the unspecified address is applied by nothing, however many rows
    /// hold what it names.
    fn an_unheld_address_retracts_as_its_phase_decides() {
        let t = table(vec![node_row()]);
        assert_eq!(
            applied(
                &retract(FREE_LEASE, Record::Port(8080)),
                &t,
                EgressDefaultPhase::Announced
            ),
            Ok(Applied::Interim),
            "an in-plan retraction no row holds is applied under the announced interim"
        );
        assert_eq!(
            applied(
                &retract(FREE_LEASE, Record::Port(8080)),
                &t,
                EgressDefaultPhase::InForce
            ),
            Err(Refusal::Unheld {
                addr: FREE_LEASE,
                record: Some(Record::Port(8080)),
            }),
            "an in-plan retraction no row holds is refused once the default binds"
        );
        for (addr, what) in [
            ([100, 64, 0, 2], "the gateway"),
            ([192, 0, 2, 9], "an address outside the plan"),
            ([0, 0, 0, 0], "the unspecified address"),
        ] {
            for phase in both_phases() {
                assert_eq!(
                    applied(&retract(addr, Record::Port(7654)), &t, phase),
                    Err(Refusal::Unheld {
                        addr,
                        record: Some(Record::Port(7654)),
                    }),
                    "{what} is not an address a retraction is applied at under {phase:?}, even \
                     for a port a published row holds"
                );
            }
        }
    }

    /// The summary holds at most [`MAX_REQUEST_RECORDS`] records; a wider
    /// request has no summary — the gate refuses it rather than truncating
    /// it into a different request.
    fn a_wider_request_has_no_summary() {
        let wide: Vec<Record> = (0..=MAX_REQUEST_RECORDS)
            .map(|i| Record::Port(u16::try_from(i).expect("the summary is u16-wide at most")))
            .collect();
        assert!(
            SwitchRequest::of(SwitchVerb::Publish, NODE_ADDR, &wide).is_none(),
            "a request wider than the summary holds is not summarized"
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{
        EgressDefaultPhase, MAX_REQUEST_RECORDS, Record, SwitchRequest, SwitchRow, SwitchTable,
        SwitchVerb, applied,
    };

    /// A row's declared ports: none, or two symbolic ports — two being what
    /// catches a scan that reads only one element or stops one short of the
    /// end, the same shape the frame verdict's harness pins its lists at.
    /// The publish dimension has no absent-and-allow-all arm: a row admits
    /// exactly the ports its enumeration holds, so `None`-shaped lists have
    /// no meaning to model.
    fn two_ports() -> Vec<u16> {
        if kani::any() {
            Vec::new()
        } else {
            vec![kani::any(), kani::any()]
        }
    }

    /// [`two_ports`](two_ports) for a row's declared names.
    fn two_names() -> Vec<u8> {
        if kani::any() {
            Vec::new()
        } else {
            vec![kani::any(), kani::any()]
        }
    }

    /// A request is applied exactly when the table admits it: stated as an
    /// iff so neither arm can silently become unreachable (the rcache
    /// harness pattern). The admitting half is restated over the same
    /// request and table, per address and for every verb alike — the row at
    /// the request's own address first, then the records it admits — so a
    /// decision that keys a retraction by some other row's address, or
    /// table-wide by *any* row that happens to hold its records, or that
    /// checks in a different order, or that reads an empty row dimension as
    /// allow-all, fails here. What "admits" means is the verb's: a publish
    /// is admitted by the row's declaration, a retraction by the row's
    /// runtime-published set and never by its declaration — so a decision
    /// that lets a guest withdraw a declared port's forward (design §7.1,
    /// NET-121), or one that refuses a listen-published port's teardown,
    /// fails here. The interim's arm carries the nothing-holds bound: a
    /// request at a held address whose row refuses a record must not be
    /// read as the interim's to apply.
    ///
    /// The table is one fully symbolic row beside symbolic plan bounds. One
    /// row is what the per-address decision needs — a retraction keyed by
    /// the row's address is admitted, one keyed by any other address is the
    /// phase's or refused — and a second adds no failure shape while it
    /// multiplies CBMC's search; the multi-row shapes are the unit test's.
    /// The row's declared and runtime-published ports are independent
    /// symbolic lists, so the two dimensions can agree, disagree, or be
    /// empty in any combination.
    ///
    /// The unwind bound is 6: the record scan walks at most four slots, the
    /// row's port, name and published scans at most two each, and comparing
    /// `[u8; 4]` addresses lowers to CBMC's builtin `memcmp`, a 4-trip loop
    /// — so a bound of 4 fails an unwinding assertion even though every
    /// loop the harness itself writes has exited by its fourth check. The
    /// bound has to clear every trip the compiler generates, not only the
    /// ones the source shows.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_switch_request_applied_iff_table_admits() {
        let verb: SwitchVerb = kani::any();
        let addr: [u8; 4] = kani::any();
        let records: [Option<Record>; MAX_REQUEST_RECORDS] = kani::any();
        let row_addr: [u8; 4] = kani::any();
        let row = SwitchRow::of(row_addr, two_ports(), two_names()).with_published(two_ports());
        let first_ptask: [u8; 4] = kani::any();
        let last_ptask: [u8; 4] = kani::any();
        let table = SwitchTable::of(vec![row], first_ptask, last_ptask);
        // The phase the build ships is a constant, but the decision reads
        // both its arms — the harness pins the cutover over both, derived
        // from one symbolic bit.
        let phase = if kani::any() {
            EgressDefaultPhase::Announced
        } else {
            EgressDefaultPhase::InForce
        };
        let request = SwitchRequest {
            verb,
            switch_addr: addr,
            records,
        };

        let outcome = applied(&request, &table, phase);
        let applied_ok = outcome.is_ok();

        // The same row, at the request's own address, for every verb: a
        // publish and a retraction are admitted by the row that holds the
        // address they carry, and by no other — a publish by what the row
        // declares, a retraction by what its runtime published.
        let admits = |row: &SwitchRow, record: Record| match verb {
            SwitchVerb::Publish | SwitchVerb::PublishName => row.holds(record),
            SwitchVerb::Retract => row.publishes(record),
        };
        let declared = table
            .row_at(addr)
            .is_some_and(|row| request.records().all(|record| admits(row, record)));
        // The interim is the phase's decision over an address no row holds,
        // never a second chance past the row that does: a held address whose
        // declaration refuses a record is refused under either phase.
        let interim = phase == EgressDefaultPhase::Announced
            && table.row_at(addr).is_none()
            && table.in_plan(addr);
        assert_eq!(applied_ok, declared || interim);
    }
}
