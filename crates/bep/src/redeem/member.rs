//! The checks over the sealed member itself: BEP-019, BEP-020, BEP-021,
//! BEP-024 and BEP-058, in the order the decision runs them.
//!
//! Every check is a predicate over the owned facts in a [`Redemption`]; none
//! reads a clock, a socket or a key store. The shell interns the member's
//! context before deciding: the box and the module as small ids, the host set
//! the value was minted under (its `host_set_version`) as the bound set, and
//! the `mode` and `breadth` strings through [`Mode::recognise`] and
//! [`Breadth::recognise`].

use super::{BoxId, Check, HostSet, ModuleId, Redemption};

/// A sealed member as the decision sees it: the authenticated context of
/// BEP-006, interned by the shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMember {
    /// The box the member is minted for.
    pub box_id: BoxId,
    /// The module the member belongs to.
    pub module: ModuleId,
    /// The module's host set at the version the member was minted under.
    pub bound_set: HostSet,
    /// The member's mode, or `None` when the context carries none the proxy
    /// knows.
    pub mode: Option<Mode>,
    /// The member's breadth, or `None` when the context carries none the
    /// proxy recognises.
    pub breadth: Option<Breadth>,
    /// The expiry, as seconds since the Unix epoch.
    pub expires_at: u64,
}

/// A member's mode: how it was minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Mode {
    /// Minted from the held sign-in (BEP-005).
    User,
    /// Minted from an installation, which an un-enrolled host refuses at
    /// expansion (BEP-056).
    Installation,
}

impl Mode {
    /// The mode a sealed context's `mode` names, or `None` for one the proxy
    /// does not know.
    #[must_use]
    pub fn recognise(mode: &str) -> Option<Self> {
        match mode {
            "user" => Some(Self::User),
            "installation" => Some(Self::Installation),
            _ => None,
        }
    }
}

/// A member's breadth: how much of the signed-in account's reach it carries.
/// Only `full` is minted at v1 (BEP-005, BEP-057); a narrower breadth is
/// recognised when repository narrowing lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Breadth {
    /// The signed-in account's whole reach.
    Full,
}

impl Breadth {
    /// The breadth a sealed context's `breadth` names, or `None` for one the
    /// proxy does not recognise (BEP-058).
    #[must_use]
    pub fn recognise(breadth: &str) -> Option<Self> {
        match breadth {
            "full" => Some(Self::Full),
            _ => None,
        }
    }
}

/// What a connection's source address resolved to (BEP-020).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Attribution {
    /// No live box.
    NoBox,
    /// A live `own_ip` box: the value must name it.
    OwnIp(BoxId),
    /// A live `host_ip` box of this host: the cohort shares an address, so
    /// the value's box is not told apart from it (BEP-028).
    HostIp(BoxId),
}

/// One revocation in force (BEP-024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Revocation {
    /// Every value naming the box: `min box stop` or `min box rm` completed
    /// (BEP-043).
    Box(BoxId),
    /// Every member of the module on this host: `min auth logout` completed
    /// (BEP-044).
    Module(ModuleId),
}

/// One check as a predicate over the facts.
type Predicate = fn(&SealedMember, &Redemption) -> bool;

/// The member checks, in the order they run; the first to fail names the
/// refusal.
const CHECKS: [(Check, Predicate); 7] = [
    (Check::Attributed, attributed),
    (Check::InBoundSet, in_bound_set),
    (Check::InCurrentSet, in_current_set),
    (Check::Unexpired, unexpired),
    (Check::Unrevoked, unrevoked),
    (Check::HasMode, has_mode),
    (Check::HasBreadth, has_breadth),
];

/// The first member check `redemption` fails, or `None` when it passes them
/// all. A value that did not decrypt fails [`Check::Decrypts`] before any
/// other check is read.
pub(super) fn first_failure(redemption: &Redemption) -> Option<Check> {
    let Some(member) = &redemption.member else {
        return Some(Check::Decrypts);
    };
    CHECKS
        .iter()
        .find(|(_, passes)| !passes(member, redemption))
        .map(|(check, _)| *check)
}

/// BEP-020: the connection is attributed to a live box the value may be
/// redeemed from.
pub(super) fn attributed(member: &SealedMember, redemption: &Redemption) -> bool {
    match redemption.attribution {
        Attribution::NoBox => false,
        Attribution::OwnIp(box_id) => box_id == member.box_id,
        Attribution::HostIp(_) => true,
    }
}

/// BEP-021: the connection authority is in the value's bound host set.
pub(super) fn in_bound_set(member: &SealedMember, redemption: &Redemption) -> bool {
    member.bound_set.contains(redemption.authority)
}

/// BEP-021: the connection authority is in the module's current host set.
fn in_current_set(_: &SealedMember, redemption: &Redemption) -> bool {
    redemption.current_set.contains(redemption.authority)
}

/// BEP-024: the clock is before the value's expiry.
pub(super) fn unexpired(member: &SealedMember, redemption: &Redemption) -> bool {
    redemption.now < member.expires_at
}

/// BEP-024: no revocation in force covers the value.
pub(super) fn unrevoked(member: &SealedMember, redemption: &Redemption) -> bool {
    !redemption
        .revocations
        .iter()
        .any(|revocation| match *revocation {
            Revocation::Box(box_id) => box_id == member.box_id,
            Revocation::Module(module) => module == member.module,
        })
}

/// BEP-058: the member carries a mode.
fn has_mode(member: &SealedMember, _: &Redemption) -> bool {
    member.mode.is_some()
}

/// BEP-058: the member carries a recognised breadth.
fn has_breadth(member: &SealedMember, _: &Redemption) -> bool {
    member.breadth.is_some()
}
