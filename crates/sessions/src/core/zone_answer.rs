//! The box-zone answer decision (NET-009, NET-124 – NET-128).
//!
//! The box zone — `*.min.internal` — is answered for the host OS by an
//! always-on loopback answerer, and by the same semantics in every
//! deployment that runs one: a native host's daemon answers from its own
//! registry, and a VM-backed host's host daemon answers from the
//! host-authored table (NET-138). What must not drift between them is the
//! *decision* — which lookup gets which answer class — and this module is
//! that decision, pulled out as one pure function over the two inputs every
//! answerer already has: the lookup ([`Lookup`] — a name, a record type,
//! and where it came from) and the zone view ([`ZoneView`] — the held
//! names, each with the host-answerable address a lookup may be told and
//! whether its namespace is running). Nothing here knows about sockets,
//! DNS wire formats, registries, or clocks, which is what lets both
//! daemons share it and the test below pin it.
//!
//! The decision, in full:
//!
//! | Lookup | Verdict |
//! |---|---|
//! | from off this machine | [`Verdict::Silent`] |
//! | a name outside the box zone | [`Verdict::Refused`] |
//! | the apex `min.internal` | [`Verdict::Nodata`] |
//! | in-zone, held, live, A, with an address | [`Verdict::Address`] |
//! | in-zone, held — any other shape | [`Verdict::Nodata`] |
//! | in-zone, held by no name | [`Verdict::Nxdomain`] |
//!
//! The three NODATA shapes are the ones the requirements name separately
//! and the view answers together: a name held **without an address** — a
//! box's address the host may not be told, or a shared address held by a
//! namespace that stopped — a **non-A record type**, and a name whose
//! namespace is **not live** (NET-124, NET-127, NET-128). All three are
//! *held*: the zone never says NXDOMAIN for a box that exists, and never
//! hands out an address nothing is answering on.
//!
//! Every negative — NODATA and NXDOMAIN — is a negative the answerer is
//! authoritative for, so it carries the zone's SOA in the reply's
//! authority section for the host resolver to cache (NET-124, RFC 2308);
//! REFUSED, a namespace that is not ours, carries nothing. The SOA, and
//! the records the A answers come in, are wire things: the answerer that
//! calls this decision builds them, at a TTL of at most
//! [`ANSWER_TTL_SECS`] (NET-126).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

/// The zone every decision here is authoritative for, and nothing else:
/// `min.internal` (design §7.1). The daemon registries key their zone
/// names under this suffix; the decision matches lookup names against it
/// and treats every other name as out of zone.
pub const ZONE_APEX: &str = "min.internal";

/// The ceiling on the TTL of any record a zone answer carries (NET-126):
/// answers are for boxes that come and go with sessions, so no host
/// resolver may cache one past this. The answerer that builds the reply's
/// records uses this constant for every record it emits, answers and the
/// SOA alike, so no number the zone puts on the wire can exceed it.
pub const ANSWER_TTL_SECS: u32 = 15;

/// The ceiling restated as a compile-time fact, so a value that drifts
/// past NET-126's bound fails the build rather than a test run.
const _: () = assert!(ANSWER_TTL_SECS <= 15);

/// The record type of one lookup, as the decision classifies it: A is the
/// only type the zone answers with data, and every other type — AAAA,
/// TXT, SRV, anything a resolver asks besides A — is NODATA on a held
/// name (NET-124). The answerer maps its wire type onto this; the decision
/// does not know the wire's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    /// An A lookup: the one type a held, live name can answer with an
    /// address.
    A,
    /// Every other record type.
    Other,
}

impl RecordType {
    /// Whether this lookup asks for an A record.
    #[must_use]
    pub fn is_a(self) -> bool {
        matches!(self, Self::A)
    }
}

/// Where a lookup originated: the zone answers only the machine its
/// answerer runs on (NET-006), and a lookup from anywhere else gets
/// *nothing* — not even a refusal, which would tell a scanner a DNS
/// server is here. The answerer classifies the datagram's source into
/// this; the decision turns it into [`Verdict::Silent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// The lookup originated on this machine.
    OnMachine,
    /// The lookup originated somewhere else.
    OffMachine,
}

impl Origin {
    /// Whether the lookup is one this machine answers.
    #[must_use]
    pub fn on_machine(self) -> bool {
        matches!(self, Self::OnMachine)
    }
}

/// One box-zone lookup: the name as asked, the record type it asks for,
/// and where it came from. The name is the full zone name — `web.min.internal`,
/// the apex `min.internal`, or a name outside the zone entirely — and the
/// decision normalizes it, so the caller may pass it exactly as the wire
/// rendered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The name the lookup asks for, in any letter case, root dot or not.
    pub name: String,
    /// The record type the lookup asks for.
    pub record: RecordType,
    /// Where the lookup originated.
    pub origin: Origin,
}

/// One held name in the zone view: the address a lookup may be told, and
/// whether the name's namespace is running.
///
/// `address` is the **host-answerable** address (NET-127): the address the
/// name publishes at, or `None` when there is none the host may be told —
/// an address outside the local ones, or a shared address held by a
/// namespace that stopped (NET-128). The view's builder applies that gate;
/// the decision never sees an address it should refuse, it sees the
/// absence of one.
///
/// `live` is whether the namespace the name names is running: a name
/// stays held while its namespace is stopped — a stopped box is never
/// mistaken for one that never existed — and answers NODATA until it runs
/// again (NET-128).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneRow {
    /// The host-answerable address an A lookup gets, if there is one.
    pub address: Option<Ipv4Addr>,
    /// Whether the name's namespace is running.
    pub live: bool,
}

/// The held names of one zone, as one owned view: what the answering
/// daemon's registry holds, resolved into the shape the decision needs.
/// The view is a snapshot, never a live handle — the answerer builds one
/// per lookup (its registry may resolve a name against state the view
/// cannot express, such as a deprecated name form), or once per datagram
/// from a table it owns outright.
///
/// Names are held in the decision's canonical form — lower-case, no root
/// dot — and [`ZoneView::hold`] puts them there, so a builder passes
/// whatever form it has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneView {
    rows: BTreeMap<String, ZoneRow>,
}

impl ZoneView {
    /// An empty view: a zone holding no names, where every in-zone lookup
    /// is NXDOMAIN and the apex is NODATA.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Holds one name with the row the registry resolved it to, replacing
    /// any row already held under that name. The name is normalized here,
    /// so the builder passes it in whatever form it holds.
    pub fn hold(&mut self, name: impl Into<String>, row: ZoneRow) {
        self.rows.insert(normalize(&name.into()), row);
    }

    /// Every held name with its row, in name order — the zone table a
    /// daemon's state dump writes (one row per held name, its address and
    /// its liveness), which is the same rows the answers come from.
    pub fn rows(&self) -> impl Iterator<Item = (&str, &ZoneRow)> {
        self.rows.iter().map(|(name, row)| (name.as_str(), row))
    }

    /// Whether the view holds no names at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The row held under `name`, in the decision's canonical form.
    fn held(&self, name: &str) -> Option<&ZoneRow> {
        self.rows.get(name)
    }
}

/// What the answerer replies for one lookup. The verdict carries the
/// reply's *class* — which rcode, which section, which record — and the
/// answerer builds the wire reply from it; the SOA every negative cites
/// and the TTL every record carries are the answerer's to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No reply at all: the lookup did not originate on this machine
    /// (NET-006). The zone leaves the machine with *nothing*, not even a
    /// refusal.
    Silent,
    /// REFUSED: the name is outside the box zone, and this answerer is
    /// authoritative for the zone and nothing else. No authority section —
    /// the zone's SOA certifies its own negatives, never someone else's
    /// namespace.
    Refused,
    /// NODATA: the name is held — or is the apex, which carries the SOA —
    /// and there is no record to give. The reply is authoritative and
    /// carries the zone's SOA (NET-124).
    Nodata,
    /// NXDOMAIN: an in-zone name nothing holds. The reply is authoritative
    /// and carries the zone's SOA (NET-125).
    Nxdomain,
    /// An A record for the address, at a TTL of at most
    /// [`ANSWER_TTL_SECS`] (NET-126, NET-127).
    Address(Ipv4Addr),
}

/// The answer one zone gives one lookup: the whole of the answerer's
/// decision, over the lookup and the zone's held names.
///
/// Off-machine lookups come first — the zone says nothing to them whatever
/// they ask — then the zone's own boundary: the apex is held (it carries
/// the SOA every negative cites, so it is NODATA, never NXDOMAIN —
/// answering that the zone does not exist while citing its SOA in the same
/// reply would contradict itself), a name outside the zone is REFUSED, and
/// a name inside is decided by the view: held, and held live with an
/// address for an A lookup, answers the address; held in any other shape —
/// non-A, no address, or a namespace that is stopped — is NODATA; held by
/// no name is NXDOMAIN (NET-124, NET-125, NET-128).
#[must_use]
pub fn decide(lookup: &Lookup, view: &ZoneView) -> Verdict {
    // Off this machine: nothing at all, whatever the name asks (NET-006).
    if !lookup.origin.on_machine() {
        return Verdict::Silent;
    }
    let name = normalize(&lookup.name);
    // The apex is held by the answerer itself: it is the record every
    // negative cites, so it answers, never "does not exist".
    if name == ZONE_APEX {
        return Verdict::Nodata;
    }
    if !in_zone(&name) {
        // Authoritative for the box zone and nothing else: a name that
        // strayed in is REFUSED, visibly, with no SOA of ours attached.
        return Verdict::Refused;
    }
    match view.held(&name) {
        // Held, and the shape the row carries decides: live with an
        // address answers an A lookup; a stopped namespace, a name with no
        // address to tell, or a non-A type all answer NODATA — held, so
        // never NXDOMAIN for a box that exists (NET-124, NET-128).
        None => Verdict::Nxdomain,
        Some(row) => match (row.address, lookup.record) {
            (Some(address), RecordType::A) if row.live => Verdict::Address(address),
            _ => Verdict::Nodata,
        },
    }
}

/// The canonical form of a zone name: lower-case, no root dot — the form
/// the view holds names in and the decision compares. DNS names are
/// case-insensitive, and the wire renders them as FQDNs with the root dot
/// (`Web.Min.Internal.`); both normalizations are total, so a caller may
/// pass the name exactly as the wire rendered it.
fn normalize(name: &str) -> String {
    let lowered = name.to_ascii_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_string()
}

/// Whether `name` is inside the box zone: `web.min.internal` is, the apex
/// and `example.com` are not. The decision looks the name up as given —
/// the view holds full zone names — so this is only the boundary. An empty
/// label — the bare suffix `.min.internal` — is not a name and is not in
/// zone.
fn in_zone(name: &str) -> bool {
    let suffix = format!(".{ZONE_APEX}");
    name.strip_suffix(&suffix)
        .is_some_and(|label| !label.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        Lookup, Origin, RecordType, Verdict, ZONE_APEX, ZoneRow, ZoneView, decide, in_zone,
        normalize,
    };

    /// An A lookup for `name` from this machine.
    fn a_lookup(name: &str) -> Lookup {
        Lookup {
            name: name.to_string(),
            record: RecordType::A,
            origin: Origin::OnMachine,
        }
    }

    /// A view holding one live name at `address`, the shape every
    /// answerer's common case takes.
    fn held(name: &str, address: Option<std::net::Ipv4Addr>) -> ZoneView {
        let mut view = ZoneView::new();
        view.hold(
            name,
            ZoneRow {
                address,
                live: true,
            },
        );
        view
    }

    /// The decision matches the answer contract the two answerers share:
    /// every arm of the answer table, over both zones of it — the classes
    /// a lookup gets, and the held shapes that all fall to NODATA. The
    /// contract is the requirement set this decision exists to serve
    /// (NET-006, NET-124 – NET-128), so a regression here is a regression
    /// in both daemons at once.
    #[test]
    fn zone_answer_decision_matches_contract() {
        let address = std::net::Ipv4Addr::new(127, 0, 64, 7);
        let view = held("web.min.internal", Some(address));

        // Off this machine: nothing at all, whatever the name and type
        // (NET-006) — held or not, in zone or not.
        for name in ["web.min.internal", ZONE_APEX, "example.com"] {
            assert_eq!(
                decide(
                    &Lookup {
                        name: name.to_string(),
                        record: RecordType::A,
                        origin: Origin::OffMachine,
                    },
                    &view
                ),
                Verdict::Silent,
                "an off-machine lookup for {name} gets nothing"
            );
        }

        // A held, live name answers an A lookup with its address.
        assert_eq!(
            decide(&a_lookup("web.min.internal"), &view),
            Verdict::Address(address),
            "a held live name answers A with its address"
        );

        // A non-A type is NODATA on a held name, never NXDOMAIN and never
        // an address (NET-124) — the answer is for the name's shape, not
        // the address's.
        assert_eq!(
            decide(
                &Lookup {
                    name: "web.min.internal".to_string(),
                    record: RecordType::Other,
                    origin: Origin::OnMachine,
                },
                &view
            ),
            Verdict::Nodata,
            "a non-A type on a held name is NODATA"
        );

        // A held name without an address — a box's switch lease the host
        // may not be told — is NODATA (NET-124, NET-127).
        assert_eq!(
            decide(
                &a_lookup("shared.min.internal"),
                &held("shared.min.internal", None)
            ),
            Verdict::Nodata,
            "a held name with no address to tell is NODATA"
        );

        // A stopped namespace keeps its name held and answers NODATA, not
        // the address it would answer with were it live (NET-128): the
        // shared-address shape the requirement names, and the own-address
        // one beside it.
        let mut stopped = ZoneView::new();
        stopped.hold(
            "web.min.internal",
            ZoneRow {
                address: Some(address),
                live: false,
            },
        );
        assert_eq!(
            decide(&a_lookup("web.min.internal"), &stopped),
            Verdict::Nodata,
            "a stopped namespace answers NODATA, held"
        );

        // An in-zone name nothing holds is NXDOMAIN (NET-125).
        assert_eq!(
            decide(&a_lookup("gone.min.internal"), &view),
            Verdict::Nxdomain,
            "an unknown in-zone name is NXDOMAIN"
        );
        assert_eq!(
            decide(&a_lookup("gone.min.internal"), &ZoneView::new()),
            Verdict::Nxdomain,
            "an empty zone holds nothing: every in-zone name is NXDOMAIN"
        );

        // A name outside the box zone is REFUSED, whatever it asks —
        // authoritative for the zone and nothing else.
        assert_eq!(
            decide(&a_lookup("example.com"), &view),
            Verdict::Refused,
            "an out-of-zone name is REFUSED"
        );

        // The apex is held: it carries the SOA every negative cites, so it
        // answers NODATA, never NXDOMAIN — whatever the type.
        for record in [RecordType::A, RecordType::Other] {
            assert_eq!(
                decide(
                    &Lookup {
                        name: ZONE_APEX.to_string(),
                        record,
                        origin: Origin::OnMachine,
                    },
                    &view
                ),
                Verdict::Nodata,
                "the apex answers NODATA for a {record:?} lookup"
            );
        }

        // The decision normalizes what the wire renders: case and the root
        // dot never change an answer.
        assert_eq!(
            decide(&a_lookup("Web.Min.Internal."), &view),
            Verdict::Address(address),
            "letter case and the root dot do not change the answer"
        );

        // The TTL ceiling the answerers emit every record at is a
        // compile-time fact of this module (the `const` assertion beside
        // [`ANSWER_TTL_SECS`]), and the wire TTL each answerer puts on the
        // records it builds is what its own tests pin (NET-126).
    }

    /// The zone's name grammar: the suffix is the boundary, and neither the
    /// apex itself, nor the bare suffix, nor a name that stops before the
    /// boundary is in zone. Names arrive here already normalized —
    /// [`decide`] normalizes before it asks.
    #[test]
    fn zone_name_grammar_matches_the_suffix_only() {
        assert!(in_zone("web.min.internal"));
        assert!(!in_zone("web.other.example"));
        assert!(!in_zone("min.internal"), "the apex is its own held arm");
        assert!(!in_zone(".min.internal"), "an empty label is no name");
        assert_eq!(normalize("Web.Min.Internal."), "web.min.internal");
        assert_eq!(normalize("min.internal"), ZONE_APEX);
    }

    /// The view holds names in the decision's canonical form whatever the
    /// builder passes, and iterates them in name order — the order the
    /// state dump's zone table writes.
    #[test]
    fn zone_view_holds_and_orders_its_rows() {
        let mut view = ZoneView::new();
        assert!(view.is_empty(), "a fresh view holds nothing");
        view.hold(
            "Web.Min.Internal.",
            ZoneRow {
                address: None,
                live: true,
            },
        );
        view.hold(
            "alpha.min.internal",
            ZoneRow {
                address: Some(std::net::Ipv4Addr::LOCALHOST),
                live: false,
            },
        );
        let names: Vec<&str> = view.rows().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            ["alpha.min.internal", "web.min.internal"],
            "names are held canonical and iterated in name order"
        );
        assert_eq!(
            decide(&a_lookup("WEB.min.internal"), &view),
            Verdict::Nodata,
            "the held name answers under any case the lookup arrives in"
        );
    }
}
