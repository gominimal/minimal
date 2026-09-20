//! What an established attribution says about the sending box's addressing,
//! and the audit marker a cohort admit carries (BEP-020, BEP-028).
//!
//! A box with an address of its own answers to it alone, so a value is
//! redeemed only from the box it names. A `host_ip` box shares the host's
//! address with its cohort, so the source address names the cohort and not one
//! box inside it: a value naming a live `host_ip` box of this host is
//! redeemable from any of them, and the admit records [`COHORT_ATTRIBUTED`] to
//! say that the cohort, not one box, is what the connection was attributed to
//! (BEP-028). The marker is the whole difference a box's audit trail shows
//! between an admit attributed to the box itself and one attributed to its
//! cohort.
//!
//! [`Attribution`] is the fact the shell establishes and the redemption
//! decision reads; [`Kind`] is what that fact says about the addressing, which
//! the audit record's marker and the redemption span's `attribution` field
//! name.

use crate::redeem::Attribution;

/// The audit marker an admit carries when the connection was attributed to a
/// cohort sharing the host's address rather than to a box addressed on its own
/// (BEP-028).
pub const COHORT_ATTRIBUTED: &str = "cohort_attributed";

/// How an attributed box is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The box has an address of its own, so the attribution names that box.
    Own,
    /// The box shares the host's address with its cohort, so the attribution
    /// names the cohort (BEP-028).
    Cohort,
}

impl Kind {
    /// How the box `attribution` names is addressed, or `None` for a source
    /// address that resolved to no live box.
    #[must_use]
    pub fn of(attribution: Attribution) -> Option<Self> {
        match attribution {
            Attribution::NoBox => None,
            Attribution::OwnIp(_) => Some(Self::Own),
            Attribution::HostIp(_) => Some(Self::Cohort),
        }
    }

    /// The name the redemption span carries.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Cohort => "cohort",
        }
    }

    /// The marker an admit under this attribution records, or `None` when it
    /// names none: only a cohort attribution is marked (BEP-028).
    #[must_use]
    pub fn marker(self) -> Option<&'static str> {
        match self {
            Self::Own => None,
            Self::Cohort => Some(COHORT_ATTRIBUTED),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redeem::BoxId;

    /// BEP-028: a cohort attribution is the one an admit marks; a box
    /// addressed on its own is marked as nothing, and a source address that
    /// is no box's has no addressing at all.
    #[test]
    fn only_a_cohort_attribution_is_marked() {
        let cohort = Kind::of(Attribution::HostIp(BoxId(0))).expect("a live box");
        assert_eq!(cohort, Kind::Cohort);
        assert_eq!(cohort.marker(), Some(COHORT_ATTRIBUTED));
        assert_eq!(cohort.name(), "cohort");

        let own = Kind::of(Attribution::OwnIp(BoxId(0))).expect("a live box");
        assert_eq!(own, Kind::Own);
        assert_eq!(own.marker(), None);
        assert_eq!(own.name(), "own");

        assert_eq!(Kind::of(Attribution::NoBox), None);
    }
}
