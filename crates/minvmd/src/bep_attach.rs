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
//! assigned — and the id is minted from them here, so an
//! address-to-box claim from inside the VM changes nothing: the guest has
//! no path that writes this table, and the claim it could make is not a
//! write. The acceptor that reads delivered connections holds a clone it
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

/// The box id a delivery carries when nobody named a box: all zero, the
/// value the delivery path writes until it fills the id from the box's
/// attachment. The acceptor reads it as **no claim** — an id to skip the
/// cross-check for, never a mismatch to refuse.
pub const NO_BOX_ID: BoxId = [0; 16];

/// The FNV-1a offset basis and prime this mint's lanes run on.
const FNV_OFFSET_BASIS: u32 = 0x811c_9dc5;
const FNV_PRIME: u32 = 0x0100_0193;

/// Folds `bytes` into `hash`, one FNV-1a round per byte.
fn fnv1a(mut hash: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Mints the box id one attachment names its box by: 16 bytes derived from
/// exactly the facts the host itself assigned — the namespace's name and
/// its two addresses — and from nothing the guest says.
///
/// The derivation is deterministic on purpose: the same box facts mint the
/// same id on every path that derives one, so the id the proxy's attachment
/// carries and any id a later task hands the in-VM daemon over the
/// registration agree without a shared table between them. It is a stable
/// derivation, not a secret: the id identifies the box, and a box learns its
/// own through the host's own registration path, never by guessing one.
///
/// Sixteen lanes, each the whole facts' hash salted by its own index, so
/// the id's bytes do not repeat one hash's worth across lanes. The first
/// lane's byte is forced odd, which puts the all-zero [`NO_BOX_ID`] — the
/// delivery's "no box named" sentinel — outside the mint's reach by
/// construction, at the cost of one bit of the id's space.
fn mint_box_id(name: &str, switch_addr: Ipv4Addr, loopback_addr: Ipv4Addr) -> BoxId {
    let facts = [
        name.as_bytes(),
        &switch_addr.octets(),
        &loopback_addr.octets(),
    ];
    let mut id = NO_BOX_ID;
    for (index, lane) in id.iter_mut().enumerate() {
        let mut hash = fnv1a(FNV_OFFSET_BASIS, &[index as u8]);
        for fact in facts {
            hash = fnv1a(hash, fact);
        }
        *lane = if index == 0 {
            (hash as u8) | 1
        } else {
            hash as u8
        };
    }
    id
}

/// One box's attachment: the facts the proxy attributes a delivered
/// connection by. The box's identity is its [`BoxId`] — minted from the
/// host's own facts about it — and beside it the addressing the host
/// assigned: the switch address, which is the source address the box's
/// delivered connections arrive from, and the loopback address the box is
/// published at. Nothing in it is sourced from the VM.
#[derive(Debug, PartialEq, Eq)]
pub struct Attachment {
    name: String,
    box_id: BoxId,
    switch_addr: Ipv4Addr,
    loopback_addr: Ipv4Addr,
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
}

/// A box id rendered for a log line: 32 lowercase hex digits, one fixed
/// form every diagnostic that names a box id uses, so a tail can compare
/// two lines for the same box.
struct BoxIdText<'a>(&'a BoxId);

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

    /// Issues one box's attachment and returns it: the box is named by the
    /// id minted from the host's own facts about it, and attributed by the
    /// address its delivered connections arrive from. The registration
    /// that publishes the box's row calls this **before** the row is
    /// visible, so the proxy holds the attachment ahead of the box's first
    /// connection: the pool's listeners are partitioned by rows, and a
    /// delivered connection can only exist once the row made the box a
    /// share — one pool turn after the registration, an attachment behind
    /// it.
    ///
    /// Issuing for an address that already holds one replaces it, exactly
    /// as the row's re-registration replaces the row: the attachment's
    /// reach is the newest registration's.
    ///
    /// One info line names the issue — the box id and the address — so a
    /// diagnostic bundle's daemon log tail carries each attachment the host
    /// gave.
    ///
    /// # Panics
    ///
    /// Never: the lock is only ever held across this map update, never
    /// across a panic.
    pub fn issue(
        &self,
        name: &str,
        switch_addr: Ipv4Addr,
        loopback_addr: Ipv4Addr,
    ) -> Arc<Attachment> {
        let attachment = Arc::new(Attachment {
            name: name.to_string(),
            box_id: mint_box_id(name, switch_addr, loopback_addr),
            switch_addr,
            loopback_addr,
        });
        self.rows
            .write()
            .expect("the attachment lock is never held across a panic, so it cannot be poisoned")
            .insert(switch_addr.octets(), Arc::clone(&attachment));
        tracing::info!(
            box_id = %BoxIdText(&attachment.box_id),
            switch_addr = %attachment.switch_addr,
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
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use crate::net::egress_gate::test_support::capture_log;

    use super::*;

    /// The box id is minted from the host's own facts and nothing else: the
    /// same facts mint the same id — the same box, the same identity, on
    /// every path that derives one — while any fact that differs names a
    /// different box, and no mint lands on the all-zero "no box named"
    /// value the acceptor's cross-check skips.
    #[test]
    fn box_ids_mint_from_the_hosts_own_facts() {
        let name = "web";
        let switch = Ipv4Addr::new(100, 64, 0, 9);
        let loopback = Ipv4Addr::LOCALHOST;

        assert_eq!(
            mint_box_id(name, switch, loopback),
            mint_box_id(name, switch, loopback),
            "the same box facts mint the same id"
        );
        assert_ne!(
            mint_box_id(name, switch, loopback),
            mint_box_id("db", switch, loopback),
            "a different name is a different box"
        );
        assert_ne!(
            mint_box_id(name, switch, loopback),
            mint_box_id(name, Ipv4Addr::new(100, 64, 0, 10), loopback),
            "a different switch address is a different box"
        );
        assert_ne!(
            mint_box_id(name, switch, loopback),
            mint_box_id(name, switch, Ipv4Addr::new(127, 0, 0, 2)),
            "a different loopback address is a different box"
        );
        assert_ne!(
            mint_box_id(name, switch, loopback),
            NO_BOX_ID,
            "the mint names the box, never the no-claim value"
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

        let web = attachments.issue("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST);
        assert_eq!(web.name(), "web");
        assert_eq!(web.switch_addr(), Ipv4Addr::new(100, 64, 0, 9));
        assert_eq!(web.loopback_addr(), Ipv4Addr::LOCALHOST);
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
        // is named by its own id.
        attachments.issue("db", Ipv4Addr::new(100, 64, 0, 10), Ipv4Addr::LOCALHOST);
        assert_eq!(attachments.rows().len(), 2);
        let db = attachments
            .by_source([100, 64, 0, 10])
            .expect("the second box's attachment is held");
        assert_ne!(web.box_id(), db.box_id(), "each box is named by its own id");

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
        let web = attachments.issue("web", Ipv4Addr::new(100, 64, 0, 9), Ipv4Addr::LOCALHOST);

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
