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
//!   outside the block is refused under either phase. Once the per-box
//!   default is in force (T66, #1711, the creator-side registration that
//!   supplies the rows), only row-held addresses publish at all.
//! * **A retract is decided by what the rows hold, not where the guest
//!   sits** — the wire carries the listener a retraction names, and no
//!   address at all, so the decision is table-wide: a retraction is applied
//!   when some published row holds the record it names — the owner's own
//!   teardown — and refused, once the default binds, when no row does.
//!   Under the announced interim a retraction matching no row is applied:
//!   the publications whose rows are still to come are the ones whose
//!   teardowns must work, and retracting what does not exist is a no-op on
//!   the switch.
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
    /// the listener it bound — the wire carries no address.
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
    /// for an expose, the zone records' address for a name publish. A
    /// retraction carries no address on the wire, and the field is then the
    /// unspecified address — the one value [`applied`] never reads for a
    /// retract.
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
}

impl SwitchRow {
    /// A row published for `switch_addr`, admitting `ports` and declaring
    /// `names`.
    #[must_use]
    pub fn of(switch_addr: [u8; 4], ports: Vec<u16>, names: Vec<u8>) -> Self {
        Self {
            switch_addr,
            ports,
            names,
        }
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
    /// at is one the plan could lease but no row holds (or, for a
    /// retraction, the record it names is declared by no row), so no row's
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
    /// A retraction names records no published row holds, and the per-box
    /// default is in force: there is no publication left to retract.
    /// `record` is the first record the retraction carries, `None` when it
    /// carries none — a shape the wire parse never builds, refused closed.
    Unheld {
        /// The first record no row holds, when the retraction named one.
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
            Self::Unheld { .. } => f.write_str("no published namespace holds what it retracts"),
        }
    }
}

/// The gate's apply-or-refuse decision for one control request against the
/// host-side table (NET-081's publish half): pure — a function of the
/// request, the table, and the phase, nothing else — and deliberately
/// separate from the relay loop that applies it, the same discipline the
/// frame verdict keeps.
///
/// The address is the whole of the routing for a publish: the row that
/// holds it supplies the records its publishes are decided by, and an
/// address no row holds is the phase's to decide
/// ([`EgressDefaultPhase`] carries what that means and why). A retraction
/// carries no address, so its decision is table-wide: some row must hold
/// the record it names, or the phase's interim applies it.
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
                // the announced interim applies the publish — an
                // own-address box's lease is minted inside the VM, and the
                // creator-side registration that will publish its row (T66,
                // #1711) is the only thing that ever will. Outside that
                // block, or once the default binds, the failure case: an
                // address no namespace holds never gains a publication.
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
            if table
                .rows
                .iter()
                .any(|row| request.records().all(|record| row.holds(record)))
            {
                return Ok(Applied::Row);
            }
            if phase == EgressDefaultPhase::Announced {
                return Ok(Applied::Interim);
            }
            Err(Refusal::Unheld {
                record: request.records().next(),
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

    /// A box's row at [`ROW_LEASE`]: one declared mapping's both ends
    /// (`8080`–`8080`), one declared name.
    fn box_row() -> SwitchRow {
        SwitchRow::of(ROW_LEASE, vec![8080], vec![0])
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

    fn retract(record: Record) -> SwitchRequest {
        SwitchRequest::of(SwitchVerb::Retract, [0, 0, 0, 0], &[record])
            .expect("one port record fits the summary")
    }

    #[test]
    fn switch_request_applied_only_when_table_admits() {
        let both_phases = [EgressDefaultPhase::Announced, EgressDefaultPhase::InForce];

        // A publish where a row holds the address, of ports the row admits:
        // applied by the row, under either phase.
        let t = table(vec![node_row(), box_row()]);
        for phase in both_phases {
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

        // A publish of a port the row does not admit: refused, naming the
        // first offending record — the host's ports stop at what the host
        // published.
        for phase in both_phases {
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

        // A publish at an address no row holds: the phase decides. Inside
        // the lease run the announced interim applies it; the per-box
        // default refuses it. Outside the run — the node's own address
        // unregistered, the gateway, anything past the plan — both phases
        // refuse.
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
        for phase in both_phases {
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

        // A retraction is decided table-wide: a row that holds the record
        // applies it under either phase — the owner's own teardown — and a
        // record no row holds is the interim's to apply, refused once the
        // default binds.
        let t = table(vec![node_row(), box_row()]);
        for phase in both_phases {
            assert_eq!(
                applied(&retract(Record::Port(8080)), &t, phase),
                Ok(Applied::Row),
                "a declared port's retraction is applied by its row under {phase:?}"
            );
            assert_eq!(
                applied(&retract(Record::Port(7654)), &t, phase),
                Ok(Applied::Row),
                "the node's own port's retraction is applied by its row under {phase:?}"
            );
        }
        assert_eq!(
            applied(
                &retract(Record::Port(9999)),
                &t,
                EgressDefaultPhase::Announced
            ),
            Ok(Applied::Interim),
            "a retraction no row holds is applied under the announced interim"
        );
        assert_eq!(
            applied(
                &retract(Record::Port(9999)),
                &t,
                EgressDefaultPhase::InForce
            ),
            Err(Refusal::Unheld {
                record: Some(Record::Port(9999)),
            }),
            "a retraction no row holds is refused once the default binds"
        );

        // The unspecified address a retraction carries is never read: the
        // decision is what the rows hold, not where the request claims to
        // sit.
        let t = table(vec![node_row()]);
        let request = SwitchRequest::of(SwitchVerb::Retract, [9, 9, 9, 9], &[Record::Port(7654)])
            .expect("one port record fits the summary");
        assert_eq!(
            applied(&request, &t, EgressDefaultPhase::InForce),
            Ok(Applied::Row),
            "a retraction is decided by what the rows hold, not by the address it carries"
        );

        // The summary holds at most [`MAX_REQUEST_RECORDS`] records; a
        // wider request has no summary — the gate refuses it rather than
        // truncating it into a different request.
        let wide: Vec<Record> = (0..MAX_REQUEST_RECORDS + 1)
            .map(|i| Record::Port(i as u16))
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
    /// request and table — the row at the address first, then the records
    /// it holds, then the phase's interim for an address (or, for a
    /// retraction, a record) nothing holds — so a decision that checks in a
    /// different order, or that reads an empty row dimension as allow-all,
    /// fails here.
    ///
    /// The table is one fully symbolic row beside symbolic plan bounds.
    /// One row is what the retraction's table-wide *some row* needs — a
    /// scan that skipped it, or stopped short of its records, fails the iff
    /// — and a second adds no failure shape while it multiplies CBMC's
    /// search; the multi-row shapes are the unit test's.
    ///
    /// The unwind bound is 6: the record scan walks at most four slots, the
    /// row's port and name scans at most two each, and comparing `[u8; 4]`
    /// addresses lowers to CBMC's builtin `memcmp`, a 4-trip loop — so a
    /// bound of 4 fails an unwinding assertion even though every loop the
    /// harness itself writes has exited by its fourth check. The bound has
    /// to clear every trip the compiler generates, not only the ones the
    /// source shows.
    #[kani::proof]
    #[kani::unwind(6)]
    fn kani_switch_request_applied_iff_table_admits() {
        let verb: SwitchVerb = kani::any();
        let addr: [u8; 4] = kani::any();
        let records: [Option<Record>; MAX_REQUEST_RECORDS] = kani::any();
        let row_addr: [u8; 4] = kani::any();
        let row = SwitchRow::of(row_addr, two_ports(), two_names());
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

        let declared = match verb {
            SwitchVerb::Publish | SwitchVerb::PublishName => {
                let row = table.row_at(addr);
                row.is_some_and(|row| request.records().all(|record| row.holds(record)))
            }
            SwitchVerb::Retract => table
                .rows
                .iter()
                .any(|row| request.records().all(|record| row.holds(record))),
        };
        let interim = phase == EgressDefaultPhase::Announced
            && match verb {
                SwitchVerb::Publish | SwitchVerb::PublishName => table.in_plan(addr),
                SwitchVerb::Retract => true,
            };
        assert_eq!(applied_ok, declared || interim);
    }
}
