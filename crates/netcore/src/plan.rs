//! The address plan of one switch block: which addresses are the switch's
//! own, and which may be leased to a box.
//!
//! Layer 0 of the crate, a leaf: a value with one meaning. It uses no other
//! module ([`crate`] lists the layers).
//!
//! THEOREM A1, for every block [`Plan::new`] accepts:
//!   (a) the seven reserved addresses (network, gateway, cohort, proxy peer,
//!       node, host alias, broadcast) are pairwise distinct and inside the
//!       block;
//!   (b) the lease run is not empty;
//!   (c) every leasable address is inside the block and is not reserved.
//!
//! Layout: the first host address
//! is the gateway; below broadcast, descending, the host alias, the node
//! address, the proxy peer and the host-address cohort.
//!
//! The cohort's address is reserved here, and `is_leasable` says no for it.
//! Whether a box may nevertheless hold it is not this module's to say: where
//! the cohort sends from the node's address, its own address is free and is
//! the last lease. The module that registers rows decides that, by how the
//! cohort is spelled.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// The smallest block: seven reserved addresses and one lease.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MIN_BLOCK: u32 = 8;
/// The largest block, a /8.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub const MAX_BLOCK: u32 = 16_777_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub enum PlanError {
    /// A prefix shorter than /8 or longer than /29.
    PrefixOutOfRange,
    /// The address is not the first of a block of that size.
    Unaligned,
}

/// One switch block. Built only by [`Plan::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct Plan {
    network: u32,
    size: u32,
}

#[cfg(verus_keep_ghost)]
verus! {

/// What [`Plan::new`] establishes.
pub closed spec fn wf(p: Plan) -> bool {
    &&& 8 <= p.size
    &&& p.size <= 16777216
    &&& p.network as int + p.size as int <= 4294967296
    &&& p.network as int % p.size as int == 0
}

pub closed spec fn spec_network(p: Plan) -> int { p.network as int }
pub closed spec fn spec_broadcast(p: Plan) -> int { p.network as int + p.size as int - 1 }
pub open spec fn spec_gateway(p: Plan) -> int { spec_network(p) + 1 }
pub open spec fn spec_host_alias(p: Plan) -> int { spec_broadcast(p) - 1 }
pub open spec fn spec_node(p: Plan) -> int { spec_broadcast(p) - 2 }
pub open spec fn spec_proxy_peer(p: Plan) -> int { spec_broadcast(p) - 3 }
pub open spec fn spec_cohort(p: Plan) -> int { spec_broadcast(p) - 4 }
pub open spec fn spec_first_lease(p: Plan) -> int { spec_network(p) + 2 }
pub open spec fn spec_last_lease(p: Plan) -> int { spec_broadcast(p) - 5 }

pub open spec fn spec_contains(p: Plan, a: int) -> bool {
    spec_network(p) <= a && a <= spec_broadcast(p)
}

pub open spec fn spec_reserved(p: Plan, a: int) -> bool {
    ||| a == spec_network(p)
    ||| a == spec_gateway(p)
    ||| a == spec_cohort(p)
    ||| a == spec_proxy_peer(p)
    ||| a == spec_node(p)
    ||| a == spec_host_alias(p)
    ||| a == spec_broadcast(p)
}

pub open spec fn spec_leasable(p: Plan, a: int) -> bool {
    spec_first_lease(p) <= a && a <= spec_last_lease(p)
}

/// The whole block is inside 100.64.0.0/10, the range node blocks are carved
/// from.
pub open spec fn spec_shared(p: Plan) -> bool {
    0x6440_0000 <= spec_network(p) && spec_broadcast(p) <= 0x647f_ffff
}

/// THEOREM A1.
pub proof fn theorem_a1(p: Plan)
    requires
        wf(p),
    ensures
        // (a) pairwise distinct, in address order, and inside the block
        spec_network(p) < spec_gateway(p),
        spec_gateway(p) < spec_cohort(p),
        spec_cohort(p) < spec_proxy_peer(p),
        spec_proxy_peer(p) < spec_node(p),
        spec_node(p) < spec_host_alias(p),
        spec_host_alias(p) < spec_broadcast(p),
        spec_broadcast(p) <= 4294967295,
        // (b) the lease run is not empty
        spec_first_lease(p) <= spec_last_lease(p),
        // (c) a leasable address is inside the block and not reserved
        forall|a: int| spec_leasable(p, a) ==> spec_contains(p, a) && !spec_reserved(p, a),
{
}

/// The gateway and the four top reserved addresses of a well-formed plan
/// lie inside its block.
pub proof fn lemma_reserved_inside(p: Plan)
    requires
        wf(p),
    ensures
        spec_contains(p, spec_gateway(p)),
        spec_contains(p, spec_host_alias(p)),
        spec_contains(p, spec_node(p)),
        spec_contains(p, spec_proxy_peer(p)),
        spec_contains(p, spec_cohort(p)),
{
}

} // verus!

/// The number of addresses in a block of prefix length `prefix`, for /8 to /29.
#[cfg_attr(verus_keep_ghost, verus_spec(r =>
    ensures
        match r {
            Some(size) => 8 <= size && size <= 16777216,
            None => true,
        },
))]
fn block_size(prefix: u8) -> Option<u32> {
    match prefix {
        8 => Some(16_777_216),
        9 => Some(8_388_608),
        10 => Some(4_194_304),
        11 => Some(2_097_152),
        12 => Some(1_048_576),
        13 => Some(524_288),
        14 => Some(262_144),
        15 => Some(131_072),
        16 => Some(65_536),
        17 => Some(32_768),
        18 => Some(16_384),
        19 => Some(8_192),
        20 => Some(4_096),
        21 => Some(2_048),
        22 => Some(1_024),
        23 => Some(512),
        24 => Some(256),
        25 => Some(128),
        26 => Some(64),
        27 => Some(32),
        28 => Some(16),
        29 => Some(8),
        _ => None,
    }
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
impl Plan {
    /// The block that starts at `network` with prefix length `prefix`.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        ensures
            match r {
                Ok(p) => wf(p),
                Err(_) => true,
            },
    ))]
    pub fn new(network: u32, prefix: u8) -> Result<Plan, PlanError> {
        let size = match block_size(prefix) {
            Some(size) => size,
            None => return Err(PlanError::PrefixOutOfRange),
        };
        if !network.is_multiple_of(size) {
            return Err(PlanError::Unaligned);
        }
        if network as u64 + size as u64 > 4_294_967_296 {
            return Err(PlanError::Unaligned);
        }
        Ok(Plan { network, size })
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_network(*self),
    ))]
    pub fn network(&self) -> u32 {
        self.network
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_broadcast(*self),
    ))]
    pub fn broadcast(&self) -> u32 {
        self.network + (self.size - 1)
    }

    /// Where the resolver answers.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_gateway(*self),
    ))]
    pub fn gateway(&self) -> u32 {
        self.network + 1
    }

    /// `host.min.internal` inside boxes.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_host_alias(*self),
    ))]
    pub fn host_alias(&self) -> u32 {
        self.broadcast() - 1
    }

    /// The node-plane address.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_node(*self),
    ))]
    pub fn node(&self) -> u32 {
        self.broadcast() - 2
    }

    /// The Box Egress Proxy's own switch address.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_proxy_peer(*self),
    ))]
    pub fn proxy_peer(&self) -> u32 {
        self.broadcast() - 3
    }

    /// The address every host-address box sends from.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_cohort(*self),
    ))]
    pub fn cohort(&self) -> u32 {
        self.broadcast() - 4
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_first_lease(*self),
    ))]
    pub fn first_lease(&self) -> u32 {
        self.network + 2
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r as int == spec_last_lease(*self),
    ))]
    pub fn last_lease(&self) -> u32 {
        self.broadcast() - 5
    }

    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r == spec_contains(*self, addr as int),
    ))]
    pub fn contains(&self, addr: u32) -> bool {
        self.network <= addr && addr <= self.broadcast()
    }

    /// Whether the whole block is inside 100.64.0.0/10. `Plan::new` does not
    /// require it.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r == spec_shared(*self),
    ))]
    pub fn in_shared_range(&self) -> bool {
        self.network >= 0x6440_0000 && self.broadcast() <= 0x647f_ffff
    }

    /// Whether `addr` is one of the switch's own seven addresses.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r == spec_reserved(*self, addr as int),
    ))]
    pub fn is_reserved(&self, addr: u32) -> bool {
        addr == self.network()
            || addr == self.gateway()
            || addr == self.cohort()
            || addr == self.proxy_peer()
            || addr == self.node()
            || addr == self.host_alias()
            || addr == self.broadcast()
    }

    /// Whether `addr` may be leased to a box or a task.
    #[cfg_attr(verus_keep_ghost, verus_spec(r =>
        requires wf(*self),
        ensures r == spec_leasable(*self, addr as int),
    ))]
    pub fn is_leasable(&self, addr: u32) -> bool {
        self.first_lease() <= addr && addr <= self.last_lease()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn the_local_block_has_the_documented_addresses() {
        let p = Plan::new(ip(100, 64, 0, 0), 16).unwrap();
        assert_eq!(p.gateway(), ip(100, 64, 0, 1));
        assert_eq!(p.host_alias(), ip(100, 64, 255, 254));
        assert_eq!(p.node(), ip(100, 64, 255, 253));
        assert_eq!(p.proxy_peer(), ip(100, 64, 255, 252));
        assert_eq!(p.cohort(), ip(100, 64, 255, 251));
        assert_eq!(p.first_lease(), ip(100, 64, 0, 2));
        assert_eq!(p.last_lease(), ip(100, 64, 255, 250));
    }

    // The plan reserves the cohort address. Whether a row may hold it is
    // decided where rows are registered, by the cohort's spelling.
    #[test]
    fn the_cohort_address_is_not_leasable() {
        let p = Plan::new(ip(100, 64, 0, 0), 16).unwrap();
        assert!(p.is_reserved(p.cohort()));
        assert!(!p.is_leasable(p.cohort()));
    }

    #[test]
    fn the_smallest_block_leases_exactly_one_address() {
        let p = Plan::new(ip(100, 64, 0, 8), 29).unwrap();
        assert_eq!(p.first_lease(), p.last_lease());
        assert_eq!(p.first_lease(), ip(100, 64, 0, 10));
    }

    #[test]
    fn a_block_too_small_for_the_reserved_addresses_is_refused() {
        assert_eq!(
            Plan::new(ip(100, 64, 0, 0), 30),
            Err(PlanError::PrefixOutOfRange)
        );
    }

    #[test]
    fn a_block_is_in_the_shared_range_only_if_all_of_it_is() {
        assert!(Plan::new(0x6440_0000, 24).unwrap().in_shared_range());
        assert!(Plan::new(0x647f_ff00, 24).unwrap().in_shared_range());
        assert!(Plan::new(0x6440_0000, 10).unwrap().in_shared_range());
        assert!(!Plan::new(0x6400_0000, 8).unwrap().in_shared_range());
        assert!(!Plan::new(0x6480_0000, 24).unwrap().in_shared_range());
        assert!(!Plan::new(0x0a00_0000, 29).unwrap().in_shared_range());
    }

    #[test]
    fn an_address_inside_a_block_is_not_its_network() {
        assert_eq!(Plan::new(ip(100, 64, 0, 4), 29), Err(PlanError::Unaligned));
    }
}

/// Bit-level check of A1 for every network and prefix, against definitions
/// that share nothing with the accessors: a shift for the block size, and an
/// array for the reserved set.
#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(8)]
    fn kani_plan_a1() {
        let network: u32 = kani::any();
        let prefix: u8 = kani::any();
        let Ok(p) = Plan::new(network, prefix) else {
            return;
        };
        // The table in `block_size` is the shift it stands for.
        assert!((8..=29).contains(&prefix));
        let size = 1u64 << (32 - u32::from(prefix));
        let first = u64::from(network);
        let last = first + size - 1;
        assert!(last <= u64::from(u32::MAX));
        assert!(u64::from(p.network()) == first);
        assert!(u64::from(p.broadcast()) == last);

        let reserved = [
            p.network(),
            p.gateway(),
            p.cohort(),
            p.proxy_peer(),
            p.node(),
            p.host_alias(),
            p.broadcast(),
        ];
        // (a) pairwise distinct and inside the block
        let i: usize = kani::any();
        let j: usize = kani::any();
        kani::assume(i < 7 && j < 7 && i != j);
        assert!(reserved[i] != reserved[j]);
        assert!(first <= u64::from(reserved[i]) && u64::from(reserved[i]) <= last);
        // (b) the lease run is not empty
        assert!(p.first_lease() <= p.last_lease());
        // (c) leasable implies inside and not one of the seven
        let a: u32 = kani::any();
        if p.is_leasable(a) {
            assert!(first <= u64::from(a) && u64::from(a) <= last);
            assert!(a != reserved[i]);
        }
        // `is_reserved` is membership in that array
        let mut member = false;
        let mut k = 0;
        while k < 7 {
            if reserved[k] == a {
                member = true;
            }
            k += 1;
        }
        assert!(p.is_reserved(a) == member);
    }
}
