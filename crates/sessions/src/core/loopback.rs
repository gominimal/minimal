//! The host-loopback address allocator behind a published box (NET-010).
//!
//! An own-address or `none` box publishes its ports on a host loopback
//! address of its own, leased from the reserved local range —
//! `127.64.0.0/24`, a loopback block no stock host service claims (design
//! §7.1). The range is carved at [`SLICE_PREFIX`] into [`SLICE_COUNT`]
//! disjoint slices, one per gvproxy daemon on the host: a daemon's slice is a
//! function of its slice octet (`octet % SLICE_COUNT`, the
//! `minimald::sessions::LoopbackAllocator` wrapper), so every daemon leases
//! inside its own addresses without asking another, and the union of the
//! slices' owned sets is the host-global allocation NET-010 ranges over.
//!
//! This module is the pure half of that decision, deliberately separate from
//! the publish call and from any daemon's own state (spec NET, Tiers: NET-010
//! is T2): a [`LoopbackAllocator`] owns its slice's leased set and nothing
//! else — no sockets, no clock, no randomness — which is what lets the Kani
//! harness below exhaust publish and withdraw over the whole live-box budget.
//!
//! The carve restates `switch::DEFAULT_ADDRESS_PLAN` address for address —
//! the same range, the same `/27`, the same index-to-slice step — because
//! this crate does not depend on the switch; `minimald`'s
//! `loopback_slice_carve_matches_the_switch_plan` pins the two together over
//! every index so the restatement cannot drift.

use std::net::Ipv4Addr;

/// The reserved local range a published box's address is leased from:
/// `127.64.0.0/24` (design §7.1).
///
/// Restated from `switch::DEFAULT_ADDRESS_PLAN`, which owns the definition;
/// pinned to it by `minimald`'s carve cross-check test.
pub const RESERVED_LOCAL_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(127, 64, 0, 0), 24);

/// The prefix each daemon's slice of the range is carved at: a `/27`, so a
/// slice holds [`SLICE_ADDRESSES`] addresses.
pub const SLICE_PREFIX: u8 = 27;

/// How many slices the range carves into: `2^(27-24)` = 8, one per gvproxy
/// daemon on the host.
pub const SLICE_COUNT: u32 = 1 << (SLICE_PREFIX - RESERVED_LOCAL_RANGE.1);

/// How many addresses one slice holds: `2^(32-27)` = 32, the slice's
/// live-box budget.
pub const SLICE_ADDRESSES: u32 = 1 << (32 - SLICE_PREFIX);

/// One daemon's run of the reserved local range: a `/27` inside
/// [`RESERVED_LOCAL_RANGE`], disjoint from every other slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackSlice {
    first: u32,
    last: u32,
}

impl LoopbackSlice {
    /// The `index`-th slice of the reserved local range.
    ///
    /// Returns `None` outside `0..SLICE_COUNT`. Within it the slices are
    /// pairwise disjoint and their union is exactly the range, which is what
    /// lets the allocator stay per-slice while the allocation it implements
    /// is host-global.
    #[must_use]
    pub fn for_index(index: u32) -> Option<Self> {
        if index >= SLICE_COUNT {
            return None;
        }
        let first = u32::from(RESERVED_LOCAL_RANGE.0) + index * SLICE_ADDRESSES;
        Some(Self {
            first,
            last: first + SLICE_ADDRESSES - 1,
        })
    }

    /// The slice's first address.
    #[must_use]
    pub fn first(self) -> Ipv4Addr {
        Ipv4Addr::from(self.first)
    }

    /// The slice's last address.
    #[must_use]
    pub fn last(self) -> Ipv4Addr {
        Ipv4Addr::from(self.last)
    }

    /// The slice's bounds, as the daemon's start line logs them.
    #[must_use]
    pub fn range(self) -> (Ipv4Addr, Ipv4Addr) {
        (self.first(), self.last())
    }

    /// Whether `addr` falls inside this slice.
    #[must_use]
    pub fn contains(self, addr: Ipv4Addr) -> bool {
        let value = u32::from(addr);
        value >= self.first && value <= self.last
    }

    /// Whether `other` shares any address with this slice.
    #[must_use]
    pub fn overlaps(self, other: Self) -> bool {
        self.first <= other.last && other.first <= self.last
    }
}

/// The leased set of one slice of the reserved local range: which of the
/// slice's [`SLICE_ADDRESSES`] addresses a live published box holds.
///
/// Pure by construction (NET-010 is T2): the whole state is the slice and a
/// `u32` bitmask, one bit per address, so lease and release are branch-free
/// arithmetic over it. The daemon-side wrapper in `minimald::sessions` holds
/// one of these per gvproxy slice beside the hostname registry — never inside
/// the publish call, never per-session — and no daemon leases from a slice
/// but its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackAllocator {
    slice: LoopbackSlice,
    leased: u32,
}

impl LoopbackAllocator {
    /// An allocator over `slice` with nothing leased.
    #[must_use]
    pub fn new(slice: LoopbackSlice) -> Self {
        Self { slice, leased: 0 }
    }

    /// The slice this allocator leases from.
    #[must_use]
    pub fn slice(self) -> LoopbackSlice {
        self.slice
    }

    /// Leases the lowest free address in the slice, which stays owned until
    /// [`release`](Self::release) returns it.
    ///
    /// Returns `None` when every address in the slice is leased — the
    /// slice's live-box budget is spent.
    pub fn lease(&mut self) -> Option<Ipv4Addr> {
        // The complement of the leased mask is the free set: both masks are
        // SLICE_ADDRESSES bits wide, so there is no capacity to check beyond
        // an empty free set.
        let free = !self.leased;
        if free == 0 {
            return None;
        }
        // The lowest set bit of the free set is the lowest free address's
        // offset — branch-free, so the Kani harness has no 32-trip scan to
        // unwind.
        let offset = free.trailing_zeros();
        self.leased |= 1 << offset;
        Some(Ipv4Addr::from(self.slice.first + offset))
    }

    /// Returns `addr` to the slice, making it leasable again.
    ///
    /// Returns `true` only when `addr` was this slice's and was leased;
    /// releasing a foreign or already-free address reports `false` and
    /// changes nothing, so a double-release cannot clear a live box's bit.
    pub fn release(&mut self, addr: Ipv4Addr) -> bool {
        let Some(offset) = self.offset_of(addr) else {
            return false;
        };
        let bit = 1 << offset;
        if self.leased & bit == 0 {
            return false;
        }
        self.leased &= !bit;
        true
    }

    /// Whether `addr` is currently leased from this slice.
    #[must_use]
    pub fn is_leased(self, addr: Ipv4Addr) -> bool {
        match self.offset_of(addr) {
            Some(offset) => self.leased & (1 << offset) != 0,
            None => false,
        }
    }

    /// `addr`'s offset in the slice, or `None` when `addr` is outside it.
    fn offset_of(self, addr: Ipv4Addr) -> Option<u32> {
        let value = u32::from(addr);
        if value < self.slice.first || value > self.slice.last {
            return None;
        }
        Some(value - self.slice.first)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use super::{
        LoopbackAllocator, LoopbackSlice, RESERVED_LOCAL_RANGE, SLICE_ADDRESSES, SLICE_COUNT,
    };

    #[test]
    fn slices_partition_the_reserved_range() {
        let mut covered = BTreeSet::new();
        for index in 0..SLICE_COUNT {
            let slice = LoopbackSlice::for_index(index).expect("index inside the carve");
            assert!(slice.first() >= RESERVED_LOCAL_RANGE.0);
            for value in u32::from(slice.first())..=u32::from(slice.last()) {
                assert!(
                    covered.insert(Ipv4Addr::from(value)),
                    "{} is covered twice",
                    Ipv4Addr::from(value)
                );
            }
            for other in 0..SLICE_COUNT {
                let mate = LoopbackSlice::for_index(other).expect("index inside the carve");
                assert_eq!(slice.overlaps(mate), other == index);
            }
        }
        let carved = usize::try_from(SLICE_ADDRESSES * SLICE_COUNT).expect("carve size");
        assert_eq!(covered.len(), carved);
    }

    #[test]
    fn for_index_refuses_indices_outside_the_carve() {
        assert_eq!(LoopbackSlice::for_index(SLICE_COUNT), None);
        assert_eq!(LoopbackSlice::for_index(u32::MAX), None);
    }

    #[test]
    fn lease_hands_out_distinct_addresses_until_the_slice_is_spent() {
        let slice = LoopbackSlice::for_index(1).expect("index inside the carve");
        let mut allocator = LoopbackAllocator::new(slice);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..SLICE_ADDRESSES {
            let address = allocator.lease().expect("a fresh slice has room");
            assert!(slice.contains(address));
            assert!(seen.insert(address), "{address} leased twice");
        }
        assert_eq!(allocator.lease(), None);
    }

    #[test]
    fn release_returns_the_address_to_the_slice() {
        let slice = LoopbackSlice::for_index(2).expect("index inside the carve");
        let mut allocator = LoopbackAllocator::new(slice);
        let first = allocator.lease().expect("a fresh slice has room");
        let second = allocator.lease().expect("a fresh slice has room");
        assert!(allocator.is_leased(first));
        assert!(allocator.release(first));
        assert!(!allocator.is_leased(first));
        assert_eq!(
            allocator.lease(),
            Some(first),
            "the lowest free address comes back"
        );
        assert!(allocator.is_leased(first));
        assert!(allocator.is_leased(second));
    }

    #[test]
    fn release_refuses_foreign_and_unleased_addresses() {
        let slice = LoopbackSlice::for_index(0).expect("index inside the carve");
        let mut allocator = LoopbackAllocator::new(slice);
        let leased = allocator.lease().expect("a fresh slice has room");
        // An address from another slice: outside this allocator entirely.
        let other_slice = LoopbackSlice::for_index(3).expect("index inside the carve");
        assert!(!allocator.release(other_slice.first()));
        // A slice address that was never leased.
        assert!(!allocator.release(Ipv4Addr::from(u32::from(leased) + 1)));
        // And the double release reports the second one.
        assert!(allocator.release(leased));
        assert!(!allocator.release(leased));
    }
}

/// The Kani proof of NET-010: no two live published boxes hold the same
/// loopback address, for every publish and withdraw sequence, up to eight
/// live boxes, across daemons.
///
/// # Why two daemons carry the whole property
///
/// NET-010 ranges over "every daemon on the host", but the property is
/// about PAIRS of live boxes, and a pair has only two shapes: both boxes
/// were leased through the same slice, or through two different slices.
/// The harness proves both halves over slices drawn symbolically from the
/// whole carve, so every slice a host's daemon can hold is in each half,
/// and any number of daemons follows. Two daemons that drew the same
/// slice share that slice's ONE owned set (the fold in `set_for`) — the
/// case a daemon-private copy of the leased set would get wrong.
///
/// # Schedule
///
/// The publish/withdraw sequence is pinned at the requirement's bound:
/// eight live boxes, a symbolic subset withdrawn, every freed slot
/// re-published by a freshly drawn daemon. Every subset and every
/// box-to-daemon assignment is in the proof; only the LENGTH is pinned,
/// the same concrete-length discipline the egress harnesses use, because
/// a schedule of symbolic length is what makes a solve unaffordable
/// (gominimal/minimal#1700).
///
/// # Bounds
///
/// The unwind bound is 10, two trips over the longest loop the proof
/// writes: the per-box phases and the pairwise scan each take at most
/// eight trips per activation, and the pairwise scan's inner pass at most
/// seven. [`LoopbackAllocator::lease`] and
/// [`release`](LoopbackAllocator::release) are branch-free bit arithmetic —
/// there is no 32-trip scan for a bound to clear — and the harness
/// unwraps nothing, so no `expect`'s panic path is encoded either; the
/// two spare trips are for the loops rustc lowers around the asserts'
/// failure paths (the `memcmp` lesson in the egress harness's bound doc).
///
/// Run: `cargo kani -p sessions` (or `./scripts/kani.sh`). Kani pinned at
/// 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use std::net::Ipv4Addr;

    use super::{LoopbackAllocator, LoopbackSlice, SLICE_COUNT};

    /// The live-box budget the property ranges over (NET-010: "up to 8 live
    /// boxes"), and the size of the schedule below, so every assertion is
    /// made at the requirement's stated bound.
    const LIVE: usize = 8;

    /// Asserts the property over the live set: two live boxes never hold one
    /// address. Compared as `u32`s so a pair costs one SAT operation, not
    /// the four-trip `memcmp` an `Ipv4Addr` compare lowers to.
    fn assert_live_addresses_distinct(live: &[Option<Ipv4Addr>; LIVE]) {
        for first in 0..LIVE {
            for second in (first + 1)..LIVE {
                if let (Some(a), Some(b)) = (live[first], live[second]) {
                    assert!(
                        u32::from(a) != u32::from(b),
                        "two live boxes hold one address"
                    );
                }
            }
        }
    }

    /// Which owned set a box's daemon leases through: the left slice's, or
    /// the right's — and when the two daemons drew the same slice, the one
    /// set that slice owns. That fold is the whole difference between a
    /// host-global allocation and a daemon-private copy of it.
    fn set_for(left: u32, right: u32, daemon: bool) -> usize {
        if left == right {
            0
        } else {
            usize::from(daemon)
        }
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_loopback_alloc_injective() {
        // Two daemons, their slices drawn from the whole carve: each octet a
        // host can hand a daemon, folded by the same modulo the daemon-side
        // wrapper applies (`octet % SLICE_COUNT`), so every pair of slices —
        // the equal pair included — is in the proof.
        let left = u32::from(kani::any::<u8>()) % SLICE_COUNT;
        let right = u32::from(kani::any::<u8>()) % SLICE_COUNT;

        // Unreachable for a folded index: `for_index` is total inside the
        // carve, pinned by `slices_partition_the_reserved_range`, which walks
        // every index. Returned from rather than unwrapped so the proof
        // carries no panic machinery.
        let (Some(left_slice), Some(right_slice)) = (
            LoopbackSlice::for_index(left),
            LoopbackSlice::for_index(right),
        ) else {
            return;
        };

        // The carve's half of the property: distinct slices are disjoint, so
        // an address one daemon can lease is an address no other daemon's
        // slice owns.
        if left != right {
            assert!(
                !left_slice.overlaps(right_slice),
                "distinct slices share an address"
            );
        }

        // The host's owned sets for the two drawn slices: one set when both
        // daemons drew the same slice, two when they did not. The second
        // element keeps a copy of the first slice's allocator when the
        // indices are equal, and `set_for` never selects it — the shared
        // slice is served by the one set.
        let mut sets = [
            LoopbackAllocator::new(left_slice),
            LoopbackAllocator::new(left_slice),
        ];
        if left != right {
            sets[1] = LoopbackAllocator::new(right_slice);
        }

        // Eight live boxes, each published by a symbolic daemon and leased
        // through that daemon's slice's owned set: every assignment of the
        // live boxes to the two daemons — all eight on one slice included —
        // is in the proof.
        let mut owned_by = [0usize; LIVE];
        let mut live: [Option<Ipv4Addr>; LIVE] = [None; LIVE];
        for slot in 0..LIVE {
            let daemon = kani::any::<bool>();
            owned_by[slot] = set_for(left, right, daemon);
            live[slot] = sets[owned_by[slot]].lease();
            // Eight live boxes never spend a slice: `LIVE` is below a slice's
            // budget, so every lease lands.
            assert!(live[slot].is_some(), "the live-box budget spent a slice");
            // No daemon self-assigns outside its own slice.
            if let Some(address) = live[slot] {
                assert!(
                    sets[owned_by[slot]].slice().contains(address),
                    "a lease fell outside its slice"
                );
            }
        }
        assert_live_addresses_distinct(&live);

        // A symbolic subset of the live boxes is withdrawn — destroyed —
        // each address returned through the set that leased it, so the bit
        // it reopens is the bit the next phase can re-lease.
        let mut withdrawn = [false; LIVE];
        for slot in 0..LIVE {
            withdrawn[slot] = kani::any::<bool>();
            if withdrawn[slot] {
                if let Some(address) = live[slot] {
                    assert!(
                        sets[owned_by[slot]].release(address),
                        "a live box's address was not leased"
                    );
                }
                live[slot] = None;
            }
        }

        // Every freed slot is re-published by a freshly drawn daemon, so a
        // freed address can come back through the other slice in the same
        // run.
        for slot in 0..LIVE {
            if withdrawn[slot] {
                let daemon = kani::any::<bool>();
                owned_by[slot] = set_for(left, right, daemon);
                live[slot] = sets[owned_by[slot]].lease();
                assert!(live[slot].is_some(), "the live-box budget spent a slice");
            }
        }
        assert_live_addresses_distinct(&live);
    }
}
