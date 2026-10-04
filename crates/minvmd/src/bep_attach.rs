//! The proxy's attachment table (NET-133) — one attachment per box, held on
//! the host, outside the VM.
//!
//! A host running a node-local Box Egress Proxy must tell it, from the
//! host-side creator outside the VM and **before the box's first
//! connection**, which boxes it may attribute delivered connections to: an
//! attachment per box, naming the box by its box id, with its addressing and
//! the source address its connections arrive from. This module is that
//! table. On a VM-backed host the attachment *is* the box's row in the
//! host-side table of published namespaces ([`crate::box_registry`]):
//! issued by the registration that publishes the row, ahead of it, and
//! withdrawn by the retirement that removes the row, before it — the
//! registry is this table's one writer.
//!
//! The trust boundary is the row table's own (NET-138): nothing inside the
//! VM can reach this table. The facts an attachment holds are the host's
//! own — the namespace's name and the two addresses the host's plan
//! assigned — beside the box's own id, minted here once per creation from
//! the host's OS CSPRNG and never from anything the guest could arrange
//! (BEP-070), so an address-to-box claim from inside the VM changes
//! nothing: the guest has no path that writes this table or reaches a
//! mint, and the claim it could make is not a write. The acceptor that
//! reads delivered connections holds a clone it
//! looks up through and never writes — the same shape as the read-only row
//! view the egress gate is handed — so a delivered connection is attributed
//! only to a live box this table holds an attachment for.
//!
//! Every issue and withdrawal is said aloud, one info line each, naming the
//! box id and the address — the lines a diagnostic bundle's daemon log tail
//! reads the attachment state by ([`Attachments::issue`],
//! [`Attachments::withdraw`]).

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// A box's identity in a delivered connection: 16 opaque bytes — the shape
/// [`switch::bep_host::DeliveryHeader`] carries and this table names its
/// boxes by.
pub use switch::bep_host::BoxId;

/// Mints the box id one attachment names its box by (BEP-070): one
/// UUIDv7 — a millisecond timestamp and 74 random bits — minted fresh at
/// each creation, with its random bytes from the host's OS CSPRNG and from
/// nothing the guest could observe, predict or arrange: never a counter,
/// never a digest of the box's facts, never anything a process inside the
/// VM could reach. The mint needs no shared table between minters, because
/// two creations cannot collide.
///
/// Unique per creation is the point: a box recreated with the same name
/// and the same addresses is a new box, and its id says so — the id the
/// proxy's attachment carries and the id the registration reply hands back
/// agree without deriving anything, because both are the one the mint made
/// for this creation. The id never returns to use — nothing is ever
/// allocated from it — so a revocation scoped to it stays scoped forever.
///
/// A minted id never lands on the all-zero value the delivery header
/// carried before ids were the box's own: UUIDv7's version and variant
/// bits make the all-zero id impossible by construction, and the acceptor
/// that reads a delivered header refuses it like any other id the source's
/// attachment does not hold.
pub fn mint_box_id() -> BoxId {
    uuid::Uuid::now_v7().into_bytes()
}

/// One box's attachment: the facts the proxy attributes a delivered
/// connection by. The box's identity is its [`BoxId`] — minted once, by
/// the host-side creator that issues the attachment, unique per creation
/// — and beside it the addressing the host
/// assigned: the switch address, which is the source address the box's
/// delivered connections arrive from, and the loopback address the box is
/// published at. Carried with them, whether the box declared a credentialed
/// upstream (NET-134): the lane that lets the box reach the proxy at all,
/// held where the VM cannot reach it. Nothing in it is sourced from the VM.
#[derive(Debug, PartialEq, Eq)]
pub struct Attachment {
    name: String,
    box_id: BoxId,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
    credentialed_upstream: bool,
}

impl Attachment {
    /// The namespace's name — what a diagnostic names an attachment by.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The box's identity: what the delivery header names the box by, and
    /// what the acceptor cross-checks a claimed id against.
    #[must_use]
    pub fn box_id(&self) -> BoxId {
        self.box_id
    }

    /// The box's address on the switch: the source address its delivered
    /// connections arrive from, and the key this table is keyed by.
    #[must_use]
    pub fn switch_addr(&self) -> Ipv4Addr {
        self.switch_addr
    }

    /// The box's published loopback address: the host-side addressing the
    /// box's services are reached by, carried beside the arrival address
    /// because the attachment holds the box's whole host-assigned
    /// addressing.
    #[must_use]
    pub fn loopback_addr(&self) -> Ipv4Addr {
        self.loopback_addr
    }

    /// Whether this box declared a credentialed upstream (NET-134): the lane
    /// whose infrastructure the proxy's listener is, so a connection this
    /// box delivers is one its session paid for the reach of. The
    /// attachment is the row's own copy of the row's facts, so the lane
    /// travels with it — withdrawn and re-issued with the row, never
    /// editable by anything the guest says.
    #[must_use]
    pub fn declares_credentialed_upstream(&self) -> bool {
        self.credentialed_upstream
    }
}

/// A box id rendered for a log line: 32 lowercase hex digits, one fixed
/// form every diagnostic that names a box id uses — the same spelling the
/// wire's own [`minimald_rpc::BoxId`] renders — so a tail can compare two
/// lines for the same box.
pub(crate) struct BoxIdText<'a>(pub(crate) &'a BoxId);

impl fmt::Display for BoxIdText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The table of live attachments, keyed by the switch address a delivered
/// header names as its source.
///
/// Cheap to clone; every clone shares the rows. [`BoxRegistry`] is the one
/// writer — [`Attachments::issue`] and [`Attachments::withdraw`] are its
/// verbs, called from the registration and withdrawal paths that own the
/// row table — and the acceptor that reads delivered connections holds a
/// clone it looks up through and never writes, the same shape as the
/// read-only row view the egress gate is handed.
#[derive(Debug, Clone, Default)]
pub struct Attachments {
    rows: Arc<RwLock<BTreeMap<[u8; 4], Arc<Attachment>>>>,
}

impl Attachments {
    /// An empty table: no box attached, nothing attributed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issues one box's attachment and returns it: the box is named by
    /// `box_id` — the box's own id, minted once for this creation by the
    /// host-side creator that hands it over ([`mint_box_id`], or the id a
    /// re-registration presented) — and attributed by the address its
    /// delivered connections arrive from. The registration that publishes
    /// the box's row calls this **before** the row is visible, so the
    /// proxy holds the attachment ahead of the box's first connection:
    /// the pool's listeners are partitioned by rows, and a delivered
    /// connection can only exist once the row made the box a share — one
    /// pool turn after the registration, an attachment behind it.
    ///
    /// Issuing for an address that already holds one replaces it, exactly
    /// as the row's re-registration replaces the row: the attachment's
    /// reach is the newest registration's.
    ///
    /// The lane travels with the addressing: `credentialed_upstream` is the
    /// box's own NET-134 declaration, reduced to the fact the proxy and a
    /// diagnostic both read — whether this box may reach the proxy at all.
    ///
    /// One info line names the issue — the box id, the address, and the
    /// lane — so a diagnostic bundle's daemon log tail carries each
    /// attachment the host gave.
    ///
    /// # Panics
    ///
    /// Never: the lock is only ever held across this map update, never
    /// across a panic.
    pub fn issue(
        &self,
        name: &str,
        box_id: BoxId,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
        credentialed_upstream: bool,
    ) -> Arc<Attachment> {
        let attachment = Arc::new(Attachment {
            name: name.to_string(),
            box_id,
            switch_addr,
            loopback_addr,
            credentialed_upstream,
        });
        self.rows
            .write()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .insert(switch_addr.octets(), Arc::clone(&attachment));
        tracing::info!(
            box_id = %BoxIdText(&attachment.box_id),
            switch_addr = %attachment.switch_addr,
            credentialed_upstream = attachment.credentialed_upstream,
            "issued a box egress proxy attachment, ahead of the box's first connection"
        );
        attachment
    }

    /// Withdraws the attachment held for `switch_addr`, returning it when
    /// one was. From here on the proxy attributes nothing to the address:
    /// an ended box's values are refused even when its revocation was
    /// never recorded anywhere, because the attachment that would have
    /// named the address's box is gone. The row's retirement path calls
    /// this **before** it removes the row, so a delivery racing the box's
    /// end finds no attachment and is refused rather than attributed to a
    /// box the table no longer holds.
    ///
    /// `box_ended` is the instant the host observed the box's end — the
    /// moment the retirement path learned of it — and the one info line
    /// this logs measures itself against, so a tail can see a withdrawal
    /// that did not keep the requirement's bound. On a healthy host the
    /// line reads immediately: the bound NET-133 names is 60 seconds and
    /// this runs inside the same event that ended the row.
    ///
    /// # Panics
    ///
    /// Never: the lock is only ever held across this map update, never
    /// across a panic.
    pub fn withdraw(&self, switch_addr: Ipv4Addr, box_ended: Instant) -> Option<Arc<Attachment>> {
        let withdrawn = self
            .rows
            .write()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .remove(&switch_addr.octets());
        if let Some(attachment) = &withdrawn {
            tracing::info!(
                box_id = %BoxIdText(&attachment.box_id),
                switch_addr = %attachment.switch_addr,
                since_box_end = ?box_ended.elapsed(),
                "withdrew a box egress proxy attachment; an ended box's values are \
                 refused from here on"
            );
        }
        withdrawn
    }

    /// The live attachment for the switch address `src`, when one is held:
    /// the whole of the proxy's attribution. An address this table holds
    /// an attachment for is a live box whose delivered connections may be
    /// attributed to it; an address it does not is nothing's, whatever
    /// else a delivery claims.
    #[must_use]
    pub fn by_source(&self, src: [u8; 4]) -> Option<Arc<Attachment>> {
        self.rows
            .read()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .get(&src)
            .cloned()
    }

    /// Every live attachment, in switch-address order — the order the row
    /// table's diagnostics read, so the two tables can be compared in a
    /// bundle without a second sort.
    #[must_use]
    pub fn rows(&self) -> Vec<Arc<Attachment>> {
        self.rows
            .read()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Whether some live attachment already holds `id`: one half of the
    /// collision check every registration runs on the id it minted (the
    /// rows the registry holds are the other, BEP-070), so a registration
    /// can never share an identity with a live box. Ids are never freed: a
    /// withdrawn attachment leaves this set, but its id stays spent for
    /// good — no registration can present it, and the mint never makes it
    /// again.
    #[must_use]
    pub fn holds_id(&self, id: BoxId) -> bool {
        self.rows
            .read()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .values()
            .any(|attachment| attachment.box_id == id)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use crate::net::egress_gate::test_support::capture_log;

    use super::*;

    /// A minted box id is unique per creation and unique to the box it
    /// names: one UUIDv7 — a millisecond timestamp and 74 random bits from
    /// the host's OS CSPRNG — never a counter over the host's facts,
    /// never a digest of them, so the same facts on a second mint name a
    /// second box, and no mint lands on the all-zero "no box named" value
    /// the delivery header carried before ids were the box's own.
    #[test]
    fn box_id_is_unique_per_creation() {
        let name = "web";
        let switch = Ipv4Addr::new(100, 64, 0, 9);
        let loopback = Ipv4Addr::LOCALHOST;

        // The id's shape is a UUIDv7: the version nibble at byte 6, the
        // RFC 4122 variant at byte 8. A digest of the box's facts would
        // carry neither, and this shape is what puts the all-zero id
        // outside the mint's reach by construction.
        let id = mint_box_id();
        assert_eq!(id[6] & 0xf0, 0x70, "a minted id is a version-7 UUID");
        assert_eq!(
            id[8] & 0xc0,
            0x80,
            "a minted id carries the RFC 4122 variant"
        );
        assert_ne!(
            id, [0u8; 16],
            "the mint names the box, never the no-claim value"
        );

        // Unique per creation: two mints name two boxes, because each is a
        // fresh creation — the only way two minted ids could agree is two
        // mints, which is two boxes.
        assert_ne!(mint_box_id(), mint_box_id(), "two creations name two boxes");

        // The attachments agree: a box recreated on its own facts — the same
        // name, the same addresses, its first creation ended and a second
        // begun, the shape a recreate takes — carries a second mint's id,
        // so the id names the creation, never the facts. The first
        // creation's id goes with the first creation: the table holds the
        // second id alone.
        let attachments = Attachments::new();
        let first = attachments.issue(name, mint_box_id(), switch, loopback, false);
        assert!(
            attachments.holds_id(first.box_id()),
            "the table holds the id its own attachment carries"
        );
        attachments.withdraw(switch, Instant::now());
        assert!(
            !attachments.holds_id(first.box_id()),
            "the ended box's id went with it: the table no longer holds it"
        );
        let second = attachments.issue(name, mint_box_id(), switch, loopback, false);
        assert_ne!(
            first.box_id(),
            second.box_id(),
            "a box recreated on its own facts carries a new id"
        );
        assert!(
            !attachments.holds_id(first.box_id()) && attachments.holds_id(second.box_id()),
            "the table holds the recreated box's id, and it alone"
        );
        assert!(
            !attachments.holds_id([0u8; 16]),
            "no attachment holds the all-zero non-id"
        );
    }

    /// The table holds what the host issued and nothing else: an issued
    /// attachment is resolved by the address the box's connections arrive
    /// from — never by its loopback, which is its publishing address — and
    /// a withdrawal retires it, so the proxy attributes nothing to the
    /// address from the moment the box ends.
    #[test]
    fn the_table_holds_the_hosts_own_boxes_only() {
        let attachments = Attachments::new();
        assert!(
            attachments.by_source([100, 64, 0, 9]).is_none(),
            "a fresh table holds nothing"
        );

        let web = attachments.issue(
            "web",
            mint_box_id(),
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
            false,
        );
        assert_eq!(web.name(), "web");
        assert_eq!(web.switch_addr(), Ipv4Addr::new(100, 64, 0, 9));
        assert_eq!(web.loopback_addr(), Ipv4Addr::LOCALHOST);
        assert!(
            !web.declares_credentialed_upstream(),
            "a box that declared nothing carries no lane"
        );
        assert_eq!(
            attachments.by_source([100, 64, 0, 9]).as_deref(),
            Some(web.as_ref()),
            "the attachment is resolved by the address the box arrives from"
        );
        assert_eq!(attachments.rows().len(), 1, "one attachment per box");
        assert!(
            attachments
                .by_source(Ipv4Addr::LOCALHOST.octets())
                .is_none(),
            "the box's loopback address is its publishing address, not the one \
             its deliveries arrive from"
        );

        // A second box beside the first: one attachment each, and each box
        // is named by its own id. The second declares a credentialed
        // upstream, so its attachment carries the lane the first lacks.
        attachments.issue(
            "db",
            mint_box_id(),
            Ipv4Addr::new(100, 64, 0, 10),
            Ipv4Addr::LOCALHOST,
            true,
        );
        assert_eq!(attachments.rows().len(), 2);
        let db = attachments
            .by_source([100, 64, 0, 10])
            .expect("the second box's attachment is held");
        assert_ne!(web.box_id(), db.box_id(), "each box is named by its own id");
        assert!(
            db.declares_credentialed_upstream(),
            "the lane is the row's own fact, held per box"
        );

        // Withdrawal retires the one it names and nothing else, and is
        // idempotent: an address with no attachment withdraws nothing.
        assert_eq!(
            attachments
                .withdraw(Ipv4Addr::new(100, 64, 0, 9), Instant::now())
                .as_deref(),
            Some(web.as_ref()),
            "the withdrawn attachment is the one that was issued"
        );
        assert!(
            attachments.by_source([100, 64, 0, 9]).is_none(),
            "a withdrawn attachment attributes nothing"
        );
        assert!(
            attachments.by_source([100, 64, 0, 10]).is_some(),
            "a sibling's attachment stands"
        );
        assert!(
            attachments
                .withdraw(Ipv4Addr::new(100, 64, 0, 9), Instant::now())
                .is_none(),
            "withdrawal is idempotent"
        );
        assert_eq!(attachments.rows().len(), 1);
    }

    /// One info line per attachment issued and withdrawn — NET-133's
    /// observability — each naming the box id and the address, and the
    /// withdrawal's naming the time since the box ended: the lines a
    /// diagnostic bundle's daemon log tail reads the attachment state by.
    /// An address with no attachment withdraws nothing and says nothing,
    /// so the count is one per attachment, never one per call.
    #[test]
    fn one_line_per_attachment_issued_and_withdrawn() {
        let (log, _guard) = capture_log();
        let attachments = Attachments::new();
        let web = attachments.issue(
            "web",
            mint_box_id(),
            Ipv4Addr::new(100, 64, 0, 9),
            Ipv4Addr::LOCALHOST,
            true,
        );

        let issued = "issued a box egress proxy attachment";
        let logged = log.contents();
        assert_eq!(
            logged.matches(issued).count(),
            1,
            "one line per issue, got: {logged}"
        );
        assert!(
            logged.contains(&format!("box_id={}", BoxIdText(&web.box_id()))),
            "the issue line names the box id, got: {logged}"
        );
        assert!(
            logged.contains("switch_addr=100.64.0.9"),
            "the issue line names the address, got: {logged}"
        );
        assert!(
            logged.contains("credentialed_upstream=true"),
            "the issue line names the lane, got: {logged}"
        );
        assert!(
            !logged.contains("since_box_end"),
            "an issue is not an end, got: {logged}"
        );

        attachments.withdraw(Ipv4Addr::new(100, 64, 0, 9), Instant::now());
        let withdrawn = "withdrew a box egress proxy attachment";
        let logged = log.contents();
        assert_eq!(
            logged.matches(withdrawn).count(),
            1,
            "one line per withdrawal, got: {logged}"
        );
        assert!(
            logged.contains(&format!("box_id={}", BoxIdText(&web.box_id()))),
            "the withdrawal line names the box id, got: {logged}"
        );
        assert!(
            logged.contains("switch_addr=100.64.0.9"),
            "the withdrawal line names the address, got: {logged}"
        );
        assert!(
            logged.contains("since_box_end="),
            "the withdrawal line names the time since the box ended, got: {logged}"
        );

        attachments.withdraw(Ipv4Addr::new(100, 64, 0, 10), Instant::now());
        let logged = log.contents();
        assert_eq!(
            logged.matches(issued).count(),
            1,
            "an address with no attachment issues no line, got: {logged}"
        );
        assert_eq!(
            logged.matches(withdrawn).count(),
            1,
            "an address with no attachment withdraws no line, got: {logged}"
        );
    }
}
