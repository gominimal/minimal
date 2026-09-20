//! The checks over the connection and the request itself: BEP-031, BEP-022
//! and BEP-023, which the decision runs before it reads the sealed value at
//! all.
//!
//! These are the facts the listener and the request line establish: the
//! `host:port` the connection was opened for, the egress the sending box
//! declared, and the authority the request claims to be going to. None of them
//! depends on a sealed value, so they run first: a connection on a port the
//! module does not declare, a request to an authority the box's egress denies,
//! and a request whose `Host` disagrees with its connection are each refused
//! whether or not the request carries a sealed value, and so before any
//! substitution.
//!
//! Every check is a predicate over the owned facts in a [`Redemption`], as in
//! [`super::member`]: none reads a clock, a socket or a key store. The shell
//! establishes them and interns each authority it knows as an [`AuthorityId`];
//! an authority it does not know has no id, which is why a `Host` header or a
//! request target naming one is `None` here.

use super::{AuthorityId, Check, Redemption};

/// A credentialed hostname, interned by the shell as a small id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct HostId(pub u8);

/// A `host:port` pair as the listener sees it, carrying the port that interning
/// an authority hides. A module declares its authorities as these pairs and the
/// shell interns each as an [`AuthorityId`], so port discipline is the one
/// check that reads the port itself (BEP-031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct Endpoint {
    /// The credentialed hostname.
    pub host: HostId,
    /// The port.
    pub port: u16,
}

/// The sending box's declared egress, interned: the authorities its
/// `egress.allow_dns_hosts` admits (BEP-022). A box that declares no host
/// allow-list admits every authority this host knows, which the shell interns
/// as that whole union.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Egress(pub Vec<AuthorityId>);

impl Egress {
    /// Whether the declaration admits `authority`.
    #[must_use]
    pub fn admits(&self, authority: AuthorityId) -> bool {
        self.0.contains(&authority)
    }
}

/// The request and the connection it arrived on, as the decision reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The `host:port` the connection was opened for (BEP-031).
    pub endpoint: Endpoint,
    /// The `host:port` pairs the module declares as its authorities: the same
    /// authorities as the `current_set` of [`Redemption`], before the shell
    /// interned them (BEP-031).
    pub declared: Vec<Endpoint>,
    /// The sending box's declared egress (BEP-022).
    pub egress: Egress,
    /// The authority the request's `Host` header named, or `None` when the
    /// header is absent or names an authority this host does not know — which
    /// no connection authority is, so a `None` differs from it (BEP-023).
    pub host_header: Option<AuthorityId>,
    /// The authority the request target named: the connection authority itself
    /// for an origin-form target, which the shell fills in, and `None` when an
    /// absolute-form target or a CONNECT names an authority this host does not
    /// know (BEP-023).
    pub target: Option<AuthorityId>,
}

/// One check as a predicate over the facts.
type Predicate = fn(&Request, &Redemption) -> bool;

/// The connection and request checks, in the order they run; the first to fail
/// names the refusal.
const CHECKS: [(Check, Predicate); 3] = [
    (Check::OnDeclaredPort, on_declared_port),
    (Check::EgressAdmitted, egress_admitted),
    (Check::AuthorityPinned, authority_pinned),
];

/// The first connection or request check `redemption` fails, or `None` when it
/// passes them all. These run before the member checks, so a refusal names the
/// off port, the undeclared authority or the unpinned authority even for a
/// request that carries no sealed value.
pub(super) fn first_failure(redemption: &Redemption) -> Option<Check> {
    CHECKS
        .iter()
        .find(|(_, passes)| !passes(&redemption.request, redemption))
        .map(|(check, _)| *check)
}

/// BEP-031: the connection arrived on a `host:port` the module declares, so the
/// same credentialed hostname on any other port is refused.
fn on_declared_port(request: &Request, _: &Redemption) -> bool {
    request.declared.contains(&request.endpoint)
}

/// BEP-022: the sending box's declared egress admits the connection authority.
fn egress_admitted(request: &Request, redemption: &Redemption) -> bool {
    request.egress.admits(redemption.authority)
}

/// BEP-023: the `Host` header and the request target both name the connection
/// authority itself.
fn authority_pinned(request: &Request, redemption: &Redemption) -> bool {
    request.host_header == Some(redemption.authority)
        && request.target == Some(redemption.authority)
}
