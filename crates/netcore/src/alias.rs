//! Whether the host alias is open to a source for a frame.
//!
//! Layer 3 of the crate, from policy to rules. It uses modules of its own
//! layer and of the layers below, and no other ([`crate`] lists them).
//!
//! The host alias is the one address in the block that stands for the host
//! itself. It is default-deny. A frame reaches it only at a configured host
//! exposure, only from a source that names the host, and never at a port one
//! of the product's own listeners holds. The node alone also reaches it at
//! the ports its baseline fetches from, over TCP.
//!
//! THEOREM AO1: `alias_open` returns `alias_spec`.
//!
//! THEOREMS about the specification, for every state, source and frame:
//!   AO2  a frame with no transport port (not TCP or UDP, a later fragment,
//!        a short header) is never admitted;
//!   AO3  a box that does not name the host is never admitted;
//!   AO4  a port one of the product's own listeners holds, in that protocol,
//!        is never open, except to the node at a baseline port over TCP;
//!   AO5  any admit other than the node's baseline fetch is at a configured
//!        exposure, for that exposure's own protocol and port.
//!
//! What the state holds is the shell's to keep current: the listener list
//! and the exposure table change while a gate runs.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The protocol the node's baseline fetches over.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const FETCH_PROTO: u8 = 6;

/// An inclusive range of ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

/// A port one of the product's own listeners holds at the alias. `proto` is
/// `None` for a listener that holds the port in every protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Holder {
    pub proto: Option<u8>,
    pub port: u16,
}

/// One configured host exposure: a protocol and a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Exposure {
    pub proto: u8,
    pub port: u16,
}

/// What decides the alias, as of one frame.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct AliasState {
    /// The ports the node's baseline fetches from at the alias.
    pub node_ports: Vec<PortRange>,
    /// The product's own listeners at the alias.
    pub held: Vec<Holder>,
    /// The configured host exposures.
    pub exposures: Vec<Exposure>,
}

/// Who is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum AliasSource {
    Node,
    Cohort,
    /// A box, which reaches an exposure only if it names the host: by name in
    /// its DNS hosts, or by an allowed-subnet list that covers the alias. A
    /// box with no subnet list covers it.
    Box {
        names_host: bool,
    },
}

#[cfg(verus_keep_ghost)]
verus! {

pub open spec fn in_ranges(ranges: Seq<PortRange>, port: u16) -> bool {
    exists|i: int| 0 <= i < ranges.len() && (#[trigger] ranges[i]).lo <= port && port <= ranges[i].hi
}

pub open spec fn holder_holds(h: Holder, proto: u8, port: u16) -> bool {
    h.port == port && match h.proto {
        None => true,
        Some(p) => p == proto,
    }
}

pub open spec fn is_held(held: Seq<Holder>, proto: u8, port: u16) -> bool {
    exists|i: int| 0 <= i < held.len() && holder_holds(#[trigger] held[i], proto, port)
}

pub open spec fn is_exposed(exposures: Seq<Exposure>, proto: u8, port: u16) -> bool {
    exists|i: int| 0 <= i < exposures.len() && (#[trigger] exposures[i]).proto == proto && exposures[i].port == port
}

pub open spec fn names_host(who: AliasSource) -> bool {
    match who {
        AliasSource::Node => true,
        AliasSource::Cohort => true,
        AliasSource::Box { names_host } => names_host,
    }
}

/// The node's baseline fetch: TCP at one of its ports.
pub open spec fn node_fetch(s: AliasState, who: AliasSource, proto: u8, port: u16) -> bool {
    who == AliasSource::Node && proto == FETCH_PROTO && in_ranges(s.node_ports@, port)
}

/// The specification.
pub open spec fn alias_spec(s: AliasState, who: AliasSource, transport: Option<(u8, u16)>) -> bool {
    match transport {
        None => false,
        Some((proto, port)) => node_fetch(s, who, proto, port) || (!is_held(s.held@, proto, port)
            && names_host(who) && is_exposed(s.exposures@, proto, port)),
    }
}

/// AO2.
pub proof fn theorem_ao2(s: AliasState, who: AliasSource)
    ensures
        !alias_spec(s, who, None),
{
}

/// AO3.
pub proof fn theorem_ao3(s: AliasState, transport: Option<(u8, u16)>)
    ensures
        !alias_spec(s, AliasSource::Box { names_host: false }, transport),
{
}

/// AO4.
pub proof fn theorem_ao4(s: AliasState, who: AliasSource, proto: u8, port: u16)
    requires
        is_held(s.held@, proto, port),
        alias_spec(s, who, Some((proto, port))),
    ensures
        node_fetch(s, who, proto, port),
{
}

/// AO5.
pub proof fn theorem_ao5(s: AliasState, who: AliasSource, proto: u8, port: u16)
    requires
        alias_spec(s, who, Some((proto, port))),
        !node_fetch(s, who, proto, port),
    ensures
        is_exposed(s.exposures@, proto, port),
        names_host(who),
        !is_held(s.held@, proto, port),
{
}

} // verus!

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == in_ranges(ranges@, port),
))]
fn within(ranges: &[PortRange], port: u16) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= ranges.len(),
            forall|j: int| 0 <= j < i ==> !((#[trigger] ranges@[j]).lo <= port && port <= ranges@[j].hi),
        decreases ranges.len() - i,
    ))]
    while i < ranges.len() {
        if ranges[i].lo <= port && port <= ranges[i].hi {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == is_held(held@, proto, port),
))]
fn any_holder(held: &[Holder], proto: u8, port: u16) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= held.len(),
            forall|j: int| 0 <= j < i ==> !holder_holds(#[trigger] held@[j], proto, port),
        decreases held.len() - i,
    ))]
    while i < held.len() {
        let holds = held[i].port == port
            && match held[i].proto {
                None => true,
                Some(p) => p == proto,
            };
        if holds {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == is_exposed(exposures@, proto, port),
))]
fn any_exposure(exposures: &[Exposure], proto: u8, port: u16) -> bool {
    let mut i: usize = 0;
    #[cfg_attr(verus_keep_ghost, verus_spec(
        invariant
            i <= exposures.len(),
            forall|j: int| 0 <= j < i ==> !((#[trigger] exposures@[j]).proto == proto && exposures@[j].port == port),
        decreases exposures.len() - i,
    ))]
    while i < exposures.len() {
        if exposures[i].proto == proto && exposures[i].port == port {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether the alias is open to `who` for a frame with this transport: its
/// protocol and destination port when it is a TCP or UDP first fragment with
/// a whole header, `None` otherwise. AO1.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures r == alias_spec(*s, who, transport),
))]
pub fn alias_open(s: &AliasState, who: AliasSource, transport: Option<(u8, u16)>) -> bool {
    let (proto, port) = match transport {
        Some(t) => t,
        None => return false,
    };
    let node = match who {
        AliasSource::Node => true,
        AliasSource::Cohort => false,
        AliasSource::Box { .. } => false,
    };
    if node && proto == FETCH_PROTO && within(s.node_ports.as_slice(), port) {
        return true;
    }
    if any_holder(s.held.as_slice(), proto, port) {
        return false;
    }
    let names = match who {
        AliasSource::Node => true,
        AliasSource::Cohort => true,
        AliasSource::Box { names_host } => names_host,
    };
    names && any_exposure(s.exposures.as_slice(), proto, port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AliasState {
        AliasState {
            node_ports: vec![PortRange { lo: 443, hi: 443 }],
            held: vec![
                Holder {
                    proto: Some(6),
                    port: 8118,
                },
                Holder {
                    proto: None,
                    port: 7656,
                },
                Holder {
                    proto: Some(6),
                    port: 443,
                },
            ],
            exposures: vec![
                Exposure {
                    proto: 6,
                    port: 5432,
                },
                Exposure {
                    proto: 17,
                    port: 7656,
                },
                Exposure {
                    proto: 6,
                    port: 8118,
                },
            ],
        }
    }

    const NAMES: AliasSource = AliasSource::Box { names_host: true };
    const SILENT: AliasSource = AliasSource::Box { names_host: false };

    #[test]
    fn an_exposure_opens_its_own_protocol_and_port_to_a_box_that_names_the_host() {
        let s = state();
        assert!(alias_open(&s, NAMES, Some((6, 5432))));
        assert!(!alias_open(&s, NAMES, Some((17, 5432))));
        assert!(!alias_open(&s, NAMES, Some((6, 5433))));
        assert!(!alias_open(&s, SILENT, Some((6, 5432))));
        assert!(alias_open(&s, AliasSource::Cohort, Some((6, 5432))));
    }

    #[test]
    fn a_listener_of_our_own_shadows_an_exposure_at_its_port() {
        let s = state();
        assert!(!alias_open(&s, NAMES, Some((6, 8118))));
        assert!(!alias_open(&s, NAMES, Some((17, 7656))));
        assert!(!alias_open(&s, AliasSource::Cohort, Some((6, 8118))));
    }

    #[test]
    fn the_node_alone_reaches_its_baseline_port_over_tcp() {
        let s = state();
        assert!(alias_open(&s, AliasSource::Node, Some((6, 443))));
        assert!(!alias_open(&s, AliasSource::Node, Some((17, 443))));
        assert!(!alias_open(&s, NAMES, Some((6, 443))));
        assert!(!alias_open(&s, AliasSource::Cohort, Some((6, 443))));
    }

    #[test]
    fn a_frame_with_no_port_is_never_admitted() {
        let s = state();
        assert!(!alias_open(&s, AliasSource::Node, None));
        assert!(!alias_open(&s, NAMES, None));
    }
}
