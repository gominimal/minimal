//! The host-loopback address allocator behind a published box (NET-010).
//!
//! An own-address or `none` box publishes its ports on a host loopback
//! address of its own, granted from the reserved local range —
//! `127.0.64.0/24`, a loopback block no stock host service claims (design
//! §7.1). Allocation in that range is **host-global**: one owned set per
//! host, held by the zone answerer — the host service whose map the node
//! daemons write over its authenticated local channel — and every daemon
//! on the host asks it for a lease rather than carving the range for
//! itself. No daemon self-assigns (§7.1), so no two daemons can meet on
//! one address, and it is the answerer's record, not any daemon's memory,
//! that a restart re-derives its live grants from.
//!
//! This module is the pure core of that answerer: one owned set over the
//! answerer's whole leasable pool, deliberately separate from the publish
//! call and from any daemon's own state (spec NET, NET-010 is T2). A
//! [`LoopbackAllocator`] is the leased-set bitmask and nothing else — no
//! sockets, no clock, no randomness, no file — which is what lets the
//! Kani harness below exhaust publish and withdraw over the whole
//! live-box budget. The durable half, the record that says which
//! namespace holds which address and survives a daemon restart in it,
//! is the daemon side (`minimald::net::dns`'s lease book), which restores
//! one of these from that record before it grants.
//!
//! The range itself restates `switch::DEFAULT_ADDRESS_PLAN`, which owns
//! the definition, because this crate does not depend on the switch;
//! `minimald`'s `net` tests pin the restatement to the plan so it cannot
//! drift.

use std::net::Ipv4Addr;

/// The reserved local range a published box's address is granted from:
/// `127.0.64.0/24` (design §7.1).
///
/// Restated from `switch::DEFAULT_ADDRESS_PLAN`, which owns the definition;
/// pinned to it by `minimald`'s plan cross-check test.
pub const RESERVED_LOCAL_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(127, 0, 64, 0), 24);

/// The answerer's own address in the reserved local range (design §7.1: its
/// Linux listener sits here), and therefore the one address in the range no
/// lease may ever include: a published box must not take the address its own
/// zone answers on.
pub const ANSWERER_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 1);

/// The first address the answerer grants: the range's own `.0` (its network
/// address) and `.1` ([`ANSWERER_ADDRESS`]) are both held back ahead of it.
pub const POOL_FIRST: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 2);

/// The last address the answerer grants: the range's `.255` (its broadcast
/// address) is held back behind it.
pub const POOL_LAST: Ipv4Addr = Ipv4Addr::new(127, 0, 64, 254);

/// How many addresses the answerer may grant: `253`, the range's 254 usable
/// addresses minus its own `.1`. This is the **host's** published-namespace
/// budget — one address per published namespace, a box or a node — never a
/// per-daemon one, which is why a second daemon on the host spends no part
/// of it that the first is not already holding.
pub const POOL_LEN: u32 = 253;

/// How many `u32` words the leased-set mask needs to cover the pool:
/// `8 × 32 = 256` bits, three more than [`POOL_LEN`] has addresses. A
/// `u32`, because every offset and word index the allocator works with is
/// one — only the array subscript casts to `usize`, which is always the
/// lossless direction.
const MASK_WORDS: u32 = 8;

/// How many bits of the mask's last word name real addresses: the pool
/// ends three bits short of the mask.
const LAST_WORD_BITS: u32 = POOL_LEN - (POOL_LEN / 32) * 32;

/// The bits of the mask's last word that name real addresses: those three
/// spare bits must never read as free, or a lease could hand out an
/// address past [`POOL_LAST`] — outside the reserved range entirely.
const LAST_WORD_USABLE: u32 = (1 << LAST_WORD_BITS) - 1;

/// An address as a plain `u32`, the one conversion the const assertions
/// below can make: neither `Ipv4Addr`'s nor the integer widening `From`
/// impls are const-callable yet (rust#143874), so `u32::from` inside a
/// const does not compile. `Ipv4Addr::octets` is const, and the widening
/// `u8 as u32` casts are lossless.
const fn bits(address: Ipv4Addr) -> u32 {
    let octets = address.octets();
    ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32)
}

const _: () = assert!(POOL_LEN <= MASK_WORDS * 32);
const _: () = assert!(bits(POOL_LAST) - bits(POOL_FIRST) + 1 == POOL_LEN);
const _: () = assert!(bits(ANSWERER_ADDRESS) < bits(POOL_FIRST));
const _: () = assert!(
    bits(POOL_FIRST) > bits(RESERVED_LOCAL_RANGE.0)
        && bits(POOL_LAST)
            < bits(RESERVED_LOCAL_RANGE.0) + (1 << (32 - (RESERVED_LOCAL_RANGE.1 as u32)))
);

/// The answerer's owned set over the whole reserved local range: which of
/// the addresses it may grant — [`POOL_FIRST`] through [`POOL_LAST`] — a
/// live published namespace, a box or a node, holds.
///
/// Pure by construction (NET-010 is T2): the whole state is one fixed-width
/// bitmask, a bit per grantable address, so lease and release are bit
/// arithmetic over it. The daemon-side lease book
/// (`minimald::net::dns::LoopbackLeaseBook`) is the durable half of the
/// same answerer: it restores one of these from the answerer's record
/// under that record's own lock, grants through it, and writes each grant
/// back — so the set a lease spends is the host's, one per host, never a
/// daemon's private copy of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopbackAllocator {
    leased: [u32; MASK_WORDS as usize],
}

impl LoopbackAllocator {
    /// The answerer's owned set with nothing leased: the whole pool free.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leased: [0; MASK_WORDS as usize],
        }
    }

    /// The owned set exactly as the answerer's record holds it: every
    /// address in `owned` that falls inside the pool is marked leased.
    ///
    /// A foreign address — one the answerer cannot grant, whether a stale
    /// record's range moved or a hand-edited line wandered — is ignored
    /// rather than widening the pool, so restoring can only ever narrow
    /// what a new lease may take.
    #[must_use]
    pub fn restore(owned: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        let mut allocator = Self::new();
        for address in owned {
            allocator.mark(address);
        }
        allocator
    }

    /// Grants the lowest free address in the pool, which stays owned until
    /// [`release`](Self::release) returns it.
    ///
    /// Returns `None` when every address the answerer may grant is held —
    /// the host's published-namespace budget is spent.
    pub fn lease(&mut self) -> Option<Ipv4Addr> {
        for word in 0..MASK_WORDS {
            let free = Self::free_in(self.leased[word as usize], word);
            if free != 0 {
                // The lowest set bit of the free set is the lowest free
                // address's offset — no scan to unwind, so the Kani harness
                // pays one SAT step per word of the mask, not per address.
                let bit = free.trailing_zeros();
                self.leased[word as usize] |= 1 << bit;
                let offset = word * 32 + bit;
                return Some(Ipv4Addr::from(u32::from(POOL_FIRST) + offset));
            }
        }
        None
    }

    /// Returns `addr` to the owned set, making it grantable again.
    ///
    /// Returns `true` only when `addr` was inside the pool and was leased;
    /// releasing a foreign or already-free address reports `false` and
    /// changes nothing, so a double-release cannot clear a live box's bit.
    pub fn release(&mut self, addr: Ipv4Addr) -> bool {
        let Some(offset) = Self::offset_of(addr) else {
            return false;
        };
        let slot = &mut self.leased[(offset / 32) as usize];
        let bit = 1 << (offset % 32);
        if *slot & bit == 0 {
            return false;
        }
        *slot &= !bit;
        true
    }

    /// Whether `addr` is currently held in this owned set.
    #[must_use]
    pub fn is_leased(self, addr: Ipv4Addr) -> bool {
        match Self::offset_of(addr) {
            Some(offset) => self.leased[(offset / 32) as usize] & (1 << (offset % 32)) != 0,
            None => false,
        }
    }

    /// The free bits of mask word `word`, with the bits past the pool's end
    /// never free — see [`LAST_WORD_USABLE`].
    fn free_in(leased: u32, word: u32) -> u32 {
        let free = !leased;
        if word + 1 == MASK_WORDS {
            free & LAST_WORD_USABLE
        } else {
            free
        }
    }

    /// Marks `addr` leased without checking it was free: the
    /// [`Self::restore`] fold over the answerer's record, where every
    /// address is by construction the one grant its namespace holds.
    fn mark(&mut self, addr: Ipv4Addr) {
        if let Some(offset) = Self::offset_of(addr) {
            self.leased[(offset / 32) as usize] |= 1 << (offset % 32);
        }
    }

    /// `addr`'s offset in the pool, or `None` when `addr` is outside it.
    fn offset_of(addr: Ipv4Addr) -> Option<u32> {
        let value = u32::from(addr);
        if !(u32::from(POOL_FIRST)..=u32::from(POOL_LAST)).contains(&value) {
            return None;
        }
        Some(value - u32::from(POOL_FIRST))
    }
}

impl Default for LoopbackAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use super::{
        ANSWERER_ADDRESS, LoopbackAllocator, POOL_FIRST, POOL_LAST, POOL_LEN, RESERVED_LOCAL_RANGE,
    };

    /// Whether `addr` falls inside the reserved local range.
    fn in_range(addr: Ipv4Addr) -> bool {
        let (network, prefix) = RESERVED_LOCAL_RANGE;
        let mask = u32::MAX << (32 - u32::from(prefix));
        u32::from(network) & mask == u32::from(addr) & mask
    }

    #[test]
    fn the_pool_holds_back_the_answerer_s_own_address() {
        assert_eq!(ANSWERER_ADDRESS, Ipv4Addr::new(127, 0, 64, 1));
        assert_eq!(POOL_FIRST, Ipv4Addr::new(127, 0, 64, 2));
        assert_eq!(POOL_LAST, Ipv4Addr::new(127, 0, 64, 254));
        assert_eq!(POOL_LEN, 253);
        for addr in [ANSWERER_ADDRESS, POOL_FIRST, POOL_LAST] {
            assert!(
                in_range(addr),
                "{addr} must sit inside the reserved local range"
            );
        }
        // The pool's ends exclude, in order: the range's network address,
        // the answerer's own `.1`, and its broadcast.
        assert_eq!(u32::from(POOL_FIRST), u32::from(ANSWERER_ADDRESS) + 1);
    }

    #[test]
    fn lease_hands_out_distinct_addresses_until_the_pool_is_spent() {
        let mut allocator = LoopbackAllocator::new();
        let mut seen = BTreeSet::new();
        for _ in 0..POOL_LEN {
            let address = allocator
                .lease()
                .expect("the answerer's fresh pool has room for every namespace");
            assert!(
                (POOL_FIRST..=POOL_LAST).contains(&address),
                "{address} is outside the answerer's pool"
            );
            assert_ne!(
                address, ANSWERER_ADDRESS,
                "no lease may include the answerer's own address"
            );
            assert!(seen.insert(address), "{address} granted twice");
        }
        assert_eq!(
            allocator.lease(),
            None,
            "a spent pool yields no more addresses"
        );
    }

    #[test]
    fn release_returns_the_address_to_the_pool() {
        let mut allocator = LoopbackAllocator::new();
        let first = allocator.lease().expect("a fresh pool has room");
        let second = allocator.lease().expect("a fresh pool has room");
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
        let mut allocator = LoopbackAllocator::new();
        let leased = allocator.lease().expect("a fresh pool has room");
        // Outside the pool entirely: the answerer's own address, the range's
        // network and broadcast addresses, and the host loopback.
        for foreign in [
            ANSWERER_ADDRESS,
            Ipv4Addr::new(127, 0, 64, 0),
            Ipv4Addr::new(127, 0, 64, 255),
            Ipv4Addr::LOCALHOST,
        ] {
            assert!(!allocator.release(foreign), "{foreign} is not grantable");
            assert!(!allocator.is_leased(foreign));
        }
        // A pool address that was never leased.
        assert!(!allocator.release(Ipv4Addr::from(u32::from(leased) + 1)));
        // And the double release reports the second one.
        assert!(allocator.release(leased));
        assert!(!allocator.release(leased));
    }

    #[test]
    fn restore_marks_exactly_the_record_s_addresses() {
        let held = [POOL_FIRST, Ipv4Addr::new(127, 0, 64, 9)];
        let mut allocator = LoopbackAllocator::restore(
            held.into_iter()
                .chain([ANSWERER_ADDRESS, Ipv4Addr::LOCALHOST]),
        );
        for address in held {
            assert!(allocator.is_leased(address), "{address} must stay held");
        }
        // A grant through the restored set cannot take either held address
        // — a restarted daemon re-derives the same owned set its record
        // holds, so a namespace that is still live keeps its address.
        let next = allocator.lease().expect("a restored pool has room");
        assert_ne!(next, held[0]);
        assert_ne!(next, held[1]);
        assert!(allocator.is_leased(next));
        // Releasing the lowest held address hands it straight back on the
        // next lease; releasing a higher one leaves the lower gaps first.
        assert!(allocator.release(held[0]));
        assert_eq!(allocator.lease(), Some(held[0]));
        assert!(allocator.release(held[1]));
        assert_eq!(
            allocator.lease(),
            Some(Ipv4Addr::new(127, 0, 64, 4)),
            "the gap below the released address wins over the released one"
        );
    }
}

/// The Kani proof of NET-010: no two live published boxes hold the same
/// loopback address, for every publish and withdraw sequence, up to eight
/// live boxes, over the one host-wide owned set.
///
/// # Why the daemon dimension collapsed
///
/// NET-010 ranges over "every daemon on the host", and the round that
/// moved allocation into the answerer's one owned set is what made that
/// dimension disappear: a lease is now a function of the host's owned set
/// alone, because the daemon that asks contributes no state the allocator
/// reads (design §7.1: co-resident nodes MUST NOT self-assign, so a daemon
/// has no slice, octet, or grant of its own to fold into the address).
/// "Every sequence of publish and withdraw operations from every daemon"
/// is therefore the same set as "every sequence of publish and withdraw
/// operations", which is the schedule below exhausts at the requirement's
/// stated bound. A harness before this round needed a symbolic per-box
/// daemon because the owned set was per-daemon state — that is precisely
/// the design NET-010 rejected.
///
/// # Schedule
///
/// The publish/withdraw sequence is pinned at the requirement's bound:
/// eight live boxes, a symbolic subset withdrawn, every freed slot
/// re-published. In the middle, the owned set is closed and re-derived
/// through [`LoopbackAllocator::restore`] — the answerer's record read
/// back the way a restarted daemon reads it — so the proof also carries
/// the record's half of the property: the addresses live boxes hold are
/// exactly the ones the re-opened set keeps, and a grant through it
/// cannot take one. Every subset and every re-publish is in the proof;
/// only the LENGTH is pinned, the same concrete-length discipline the
/// egress harnesses use, because a schedule of symbolic length is what
/// makes a solve unaffordable (gominimal/minimal#1700).
///
/// # Bounds
///
/// The unwind bound is 10, two trips over the longest loop the proof
/// writes: the per-box phases take at most eight trips, the pairwise
/// scan's inner pass at most seven, and the mask scan inside
/// [`LoopbackAllocator::lease`] at most its eight words —
/// `lease` picks a word by one comparison and an address within it by
/// `trailing_zeros`, so there is no per-address scan for a bound to
/// clear. The harness unwraps nothing, so no `expect`'s panic path is
/// encoded either; the two spare trips are for the loops rustc lowers
/// around the asserts' failure paths (the `memcmp` lesson in the egress
/// harness's bound doc).
///
/// Run: `cargo kani -p sessions` (or `./scripts/kani.sh`). Kani pinned at
/// 0.68.0 in CI.
#[cfg(kani)]
mod kani_proofs {
    use std::net::Ipv4Addr;

    use super::{ANSWERER_ADDRESS, LoopbackAllocator, POOL_FIRST, POOL_LAST};

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

    /// Asserts the bounds of every grant: inside the answerer's pool, and
    /// never the answerer's own address — the two exclusions design §7.1
    /// draws inside the reserved local range.
    fn assert_grantable(address: Ipv4Addr) {
        assert!(
            u32::from(address) >= u32::from(POOL_FIRST),
            "a lease fell below the answerer's pool"
        );
        assert!(
            u32::from(address) <= u32::from(POOL_LAST),
            "a lease fell past the answerer's pool"
        );
        assert!(
            u32::from(address) != u32::from(ANSWERER_ADDRESS),
            "a lease took the answerer's own address"
        );
    }

    #[kani::proof]
    #[kani::unwind(10)]
    fn kani_loopback_alloc_injective() {
        // The host's one owned set: the answerer's whole pool, nothing yet
        // held. Every grant the schedule makes comes through this one set —
        // there is no per-daemon state left to fold in, which is the
        // property's premise (see "Why the daemon dimension collapsed").
        let mut owned = LoopbackAllocator::new();

        // Eight live boxes, each published by leasing through the one
        // owned set: every sequence of eight grants is in the proof, and
        // eight live boxes never spend the pool (its budget is 253), so
        // every lease lands.
        let mut live: [Option<Ipv4Addr>; LIVE] = [None; LIVE];
        for slot in 0..LIVE {
            live[slot] = owned.lease();
            assert!(live[slot].is_some(), "the live-box budget spent the pool");
            if let Some(address) = live[slot] {
                assert_grantable(address);
            }
        }
        assert_live_addresses_distinct(&live);

        // A symbolic subset of the live boxes is withdrawn — destroyed —
        // each address returned through the set that granted it, so the bit
        // it reopens is the bit the next phase can re-grant.
        let mut withdrawn = [false; LIVE];
        for slot in 0..LIVE {
            withdrawn[slot] = kani::any::<bool>();
            if withdrawn[slot] {
                if let Some(address) = live[slot] {
                    assert!(owned.release(address), "a live box's address was not held");
                }
                live[slot] = None;
            }
        }

        // The answerer's record, closed and re-opened: the set a restarted
        // daemon re-derives is exactly the set of live grants, so a live box
        // keeps its address across the restart and a freed one does not come
        // back as held.
        let reopened = LoopbackAllocator::restore(live.iter().flatten().copied());
        let mut owned = reopened;
        for slot in 0..LIVE {
            if let Some(address) = live[slot] {
                assert!(
                    owned.is_leased(address),
                    "the re-derived record lost a live box's address"
                );
            }
        }

        // Every freed slot is re-published — the next box on the host, which
        // may be another daemon's — so a freed address can come back in the
        // same run, but never to two live boxes at once.
        for slot in 0..LIVE {
            if withdrawn[slot] {
                live[slot] = owned.lease();
                assert!(live[slot].is_some(), "the live-box budget spent the pool");
                if let Some(address) = live[slot] {
                    assert_grantable(address);
                }
            }
        }
        assert_live_addresses_distinct(&live);
    }
}
