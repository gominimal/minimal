//! Host-global allocation of per-box loopback addresses (NET-010).
//!
//! An own-address or `none` box is published at a host loopback address of
//! its own, drawn from the reserved local range [`RESERVED_RANGE`]
//! (`127.0.64.0/24`, design §7.1), so two boxes listening on the same port
//! answer at two different addresses by name. A host-address box mirrors its
//! node's address instead (NET-129) and never draws from here.
//!
//! One pure value, [`LoopbackAllocator`], owns the host-wide set of leased
//! addresses: it is separate from the publish call that asks for an address
//! and from any daemon's own state, which is what lets the Kani harness below
//! exhaust every sequence of leases and releases and prove that no two live
//! boxes ever hold the same address. A released address is handed out again
//! (the range has 254 addresses and a host outlives many boxes); a live one
//! never is.

use std::fmt;
use std::net::Ipv4Addr;

/// The reserved local range published addresses are drawn from
/// (`127.0.64.0/24`): the network address and its prefix length.
pub const RESERVED_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(127, 0, 64, 0), 24);

/// The lowest host offset handed out: `.0` is left as the range's network
/// address so the range reads as a conventional `/24`.
const FIRST_HOST: u32 = 1;
/// The highest host offset handed out: `.255` is left as the range's
/// broadcast address, for the same reason.
const LAST_HOST: u32 = 254;

/// The number of addresses the range can hold live at once.
pub const CAPACITY: usize = (LAST_HOST - FIRST_HOST + 1) as usize;

/// Every address of the reserved range is leased to a live box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangeExhausted;

impl fmt::Display for RangeExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the reserved local range {}/{} has no free address: {CAPACITY} boxes hold one",
            RESERVED_RANGE.0, RESERVED_RANGE.1
        )
    }
}

impl std::error::Error for RangeExhausted {}

/// The host-wide set of leased loopback addresses, one bit per host offset
/// of the reserved range. Pure: every operation is a function of this value
/// alone, with no I/O and no daemon identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackAllocator {
    /// Bit `i` of the concatenated words is set while `127.0.64.i` is leased.
    /// Bits `0` and `255` are set for good, so the network and broadcast
    /// offsets are never handed out.
    leased: [u64; 4],
}

impl Default for LoopbackAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopbackAllocator {
    /// An allocator with every address of the range free.
    #[must_use]
    pub fn new() -> Self {
        let mut leased = [0u64; 4];
        leased[0] |= 1;
        leased[3] |= 1 << 63;
        Self { leased }
    }

    /// Whether `addr` lies in the reserved range and could be leased at all.
    #[must_use]
    pub fn in_range(addr: Ipv4Addr) -> bool {
        Self::offset(addr).is_some()
    }

    /// The host offset of `addr` within the range, if it is one the
    /// allocator hands out.
    fn offset(addr: Ipv4Addr) -> Option<u32> {
        let offset = u32::from(addr).checked_sub(u32::from(RESERVED_RANGE.0))?;
        (FIRST_HOST..=LAST_HOST).contains(&offset).then_some(offset)
    }

    fn address(offset: u32) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(RESERVED_RANGE.0) + offset)
    }

    /// Leases the lowest free address of the range.
    ///
    /// # Errors
    ///
    /// [`RangeExhausted`] when every address is leased to a live box.
    pub fn allocate(&mut self) -> Result<Ipv4Addr, RangeExhausted> {
        for word in 0..4u32 {
            let bits = &mut self.leased[word as usize];
            let free = !*bits;
            if free != 0 {
                let bit = free.trailing_zeros();
                *bits |= 1 << bit;
                return Ok(Self::address(word * 64 + bit));
            }
        }
        Err(RangeExhausted)
    }

    /// Releases `addr` for a later lease. Returns whether it was leased; an
    /// address outside the range, or one not leased, releases nothing.
    pub fn release(&mut self, addr: Ipv4Addr) -> bool {
        let Some(offset) = Self::offset(addr) else {
            return false;
        };
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        let was = self.leased[word] & (1 << bit) != 0;
        self.leased[word] &= !(1 << bit);
        was
    }

    /// Whether `addr` is leased to a live box right now.
    #[must_use]
    pub fn is_leased(&self, addr: Ipv4Addr) -> bool {
        Self::offset(addr)
            .is_some_and(|offset| self.leased[(offset / 64) as usize] & (1 << (offset % 64)) != 0)
    }

    /// How many addresses are leased to live boxes.
    #[must_use]
    pub fn live(&self) -> usize {
        let set: u32 = self.leased.iter().map(|w| w.count_ones()).sum();
        // The two offsets held for good are not leases.
        set as usize - 2
    }

    /// Every leased address, lowest first.
    pub fn leased(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        (FIRST_HOST..=LAST_HOST)
            .filter(move |offset| self.leased[(offset / 64) as usize] & (1 << (offset % 64)) != 0)
            .map(Self::address)
    }
}

/// Bounded verification of [`LoopbackAllocator`] (NET-010): exhaustive over
/// every sequence of up to eight publish and withdraw operations, from any
/// daemon on the host, and so over every state with up to eight live boxes.
/// The harness keeps its own record of which addresses are live, restated
/// independently of the allocator, and checks that a fresh lease is in the
/// range and equals none of them.
///
/// Run: `cargo kani -p sessions` (or `just kani`). The count of harnesses in
/// this crate is asserted by `scripts/kani.sh`.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// At most this many operations, and so at most this many live boxes.
    /// The unwind bound below is one more, for the loop's exit check.
    const OPS: usize = 8;

    #[kani::proof]
    #[kani::unwind(9)]
    fn kani_loopback_alloc_injective() {
        let mut alloc = LoopbackAllocator::new();
        // The live boxes' addresses, kept by the harness rather than read
        // back from the allocator.
        let mut live: [Option<Ipv4Addr>; OPS] = [None; OPS];
        let mut next = 0;
        for _ in 0..OPS {
            if kani::any() {
                // A publish, from whichever daemon: never exhausted with at
                // most eight boxes live.
                let addr = alloc.allocate().unwrap();
                assert!(LoopbackAllocator::in_range(addr));
                for held in live.iter().flatten() {
                    assert!(*held != addr);
                }
                live[next] = Some(addr);
                next += 1;
            } else {
                // A withdraw of any box, live or already withdrawn.
                let i: usize = kani::any();
                kani::assume(i < OPS);
                if let Some(addr) = live[i].take() {
                    assert!(alloc.release(addr));
                }
            }
        }
        let held = live.iter().flatten().count();
        assert!(alloc.live() == held);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_are_sequential_from_the_first_host() {
        let mut alloc = LoopbackAllocator::new();
        assert_eq!(alloc.allocate(), Ok(Ipv4Addr::new(127, 0, 64, 1)));
        assert_eq!(alloc.allocate(), Ok(Ipv4Addr::new(127, 0, 64, 2)));
        assert_eq!(alloc.live(), 2);
        assert_eq!(
            alloc.leased().collect::<Vec<_>>(),
            vec![Ipv4Addr::new(127, 0, 64, 1), Ipv4Addr::new(127, 0, 64, 2)]
        );
    }

    #[test]
    fn released_address_is_leased_again_but_a_live_one_never_is() {
        let mut alloc = LoopbackAllocator::new();
        let one = alloc.allocate().unwrap();
        let two = alloc.allocate().unwrap();
        assert!(alloc.release(one));
        assert!(!alloc.release(one), "a second release finds nothing leased");
        assert_eq!(alloc.allocate(), Ok(one), "the released address is reused");
        assert_ne!(alloc.allocate().unwrap(), two, "the live one is not");
    }

    #[test]
    fn network_and_broadcast_offsets_are_never_handed_out() {
        let mut alloc = LoopbackAllocator::new();
        let all: Vec<_> = std::iter::from_fn(|| alloc.allocate().ok()).collect();
        assert_eq!(all.len(), CAPACITY);
        assert_eq!(all.first(), Some(&Ipv4Addr::new(127, 0, 64, 1)));
        assert_eq!(all.last(), Some(&Ipv4Addr::new(127, 0, 64, 254)));
        assert_eq!(alloc.allocate(), Err(RangeExhausted));
        assert!(!alloc.release(Ipv4Addr::new(127, 0, 64, 0)));
        assert!(!alloc.release(Ipv4Addr::new(127, 0, 64, 255)));
        assert!(!alloc.release(Ipv4Addr::LOCALHOST));
        assert!(!LoopbackAllocator::in_range(Ipv4Addr::new(127, 0, 65, 1)));
    }

    mod property {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone, Copy)]
        enum Op {
            Publish,
            Withdraw(usize),
        }

        fn arb_ops() -> impl Strategy<Value = Vec<Op>> {
            proptest::collection::vec(
                prop_oneof![Just(Op::Publish), (0usize..64).prop_map(Op::Withdraw)],
                0..=64,
            )
        }

        proptest! {
            /// The proptest twin of `kani_loopback_alloc_injective`, under the
            /// ordinary test run and over longer sequences: across any
            /// sequence of publishes and withdraws, a fresh lease lies in the
            /// reserved range and equals no address a live box holds.
            #[test]
            fn loopback_alloc_never_reuses_a_live_address(ops in arb_ops()) {
                let mut alloc = LoopbackAllocator::new();
                let mut live: Vec<Option<Ipv4Addr>> = Vec::new();
                for op in ops {
                    match op {
                        Op::Publish => {
                            let addr = alloc.allocate().unwrap();
                            prop_assert!(LoopbackAllocator::in_range(addr));
                            prop_assert!(!live.iter().flatten().any(|held| *held == addr));
                            live.push(Some(addr));
                        }
                        Op::Withdraw(i) => {
                            if let Some(addr) = live.get_mut(i).and_then(Option::take) {
                                prop_assert!(alloc.release(addr));
                            }
                        }
                    }
                    prop_assert_eq!(alloc.live(), live.iter().flatten().count());
                }
            }
        }
    }
}
