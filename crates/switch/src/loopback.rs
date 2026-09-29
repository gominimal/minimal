//! The bind probe over the reserved local range: one TCP `bind` with port 0
//! per address of [`RESERVED_LOCAL_RANGE`], answering whether the host this
//! runs on carries the range on its loopback (NET-123).
//!
//! One definition, next to the range it probes, for both sides that need
//! the verdict: the daemon's session-start probe (`minimald::net::loopback`)
//! and the CLI's naming-surface record for `min bug`. Two copies of the walk
//! could disagree on which addresses count, and then the daemon's interim
//! verdict and the bundle's could differ for one host.
//!
//! A bind with port 0 cannot collide with a live listener, and it answers in
//! microseconds either way: where the address exists it succeeds, where it
//! does not it fails with `EADDRNOTAVAIL` — the "range absent" verdict. A
//! /24 takes a few milliseconds (2.53 ms over 256 addresses, measured in the
//! macOS loopback-alias spike, `docs/spikes/2026-09-22-macos-loopback-alias.md`).
//! A *connect* to an absent address would instead hang to timeout, never
//! refuse, which is why the interim exists: until the aliases are installed,
//! a box must not be handed out at an address its fetches would time out on
//! rather than fail.
//!
//! The probe is deliberately whole-range: a partial alias set — some
//! addresses aliased on `lo0`, some not — must read as absent, since the
//! allocator could otherwise hand out exactly the address that hangs.
//!
//! The probe measures the loopback of the host it runs on, and only that
//! host. On Linux the whole `127/8` is local to `lo`, so it always reads the
//! range present there; the absent verdict is a fact about a macOS `lo0`
//! before the aliases are installed.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use crate::RESERVED_LOCAL_RANGE;

/// What the probe found, over the whole reserved local range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProbe {
    /// How many addresses bound — the loopback aliases present on this host.
    pub bound: usize,
    /// How many addresses the probe covered. Equal to [`Self::bound`] when
    /// the range is present; the difference is the alias count a host
    /// (or its diagnostics reader) compares against the range size.
    pub probed: usize,
    /// The first address that refused the bind, and the refusal. `None` when
    /// every address bound. The first is what a diagnostics reader wants: on
    /// a partially-aliased host it names where the range stops.
    pub first_failure: Option<(Ipv4Addr, io::ErrorKind)>,
}

impl RangeProbe {
    /// The verdict for a probe that never ran (a panicking or lost blocking
    /// task): conservative on purpose. A probe without an answer must not
    /// let a host report the range present, so it reads as absent — the
    /// interim.
    pub fn failed_to_run() -> Self {
        RangeProbe {
            bound: 0,
            probed: 0,
            first_failure: None,
        }
    }

    /// Whether the whole reserved range is present: every probed address
    /// bound, and at least one was probed.
    pub fn present(&self) -> bool {
        self.bound == self.probed && self.probed > 0
    }

    /// Whether the reserved range read absent — the interim verdict
    /// (NET-123): a host whose loopback carries none of the range, or not
    /// all of it, the per-host state the step that installs the range
    /// supersedes.
    pub fn interim(&self) -> bool {
        !self.present()
    }

    /// The publish surface the verdict picks, for a log line.
    pub fn surface(&self) -> &'static str {
        if self.interim() {
            "127.0.0.1-interim"
        } else {
            "reserved-range"
        }
    }

    /// What the probe found, one line for a log and the diagnostics bundle:
    /// the range, the bound count out of the probed count, and the first
    /// refusal when there was one.
    pub fn summary(&self) -> String {
        let (base, prefix_bits) = RESERVED_LOCAL_RANGE;
        match self.first_failure {
            None => format!("{base}/{prefix_bits} {}/{} bound", self.bound, self.probed),
            Some((addr, kind)) => format!(
                "{base}/{prefix_bits} {}/{} bound; first refusal {addr} ({kind:?})",
                self.bound, self.probed
            ),
        }
    }
}

/// Every usable address in the reserved local range: host part 1..=254. The
/// `.0` and `.255` spellings of a /24 are the network and broadcast forms,
/// and the step that installs the range installs exactly these 254 aliases —
/// so these are the addresses publication would hand out and the ones the
/// probe has to speak for.
pub fn range_hosts() -> impl Iterator<Item = Ipv4Addr> {
    let (base, prefix_bits) = RESERVED_LOCAL_RANGE;
    let hosts = 1u32 << (32 - u32::from(prefix_bits));
    let base = u32::from(base);
    (1..hosts - 1).map(move |host| Ipv4Addr::from(base + host))
}

/// The real probe: one `bind((addr, 0))` per address in the reserved local
/// range. Cheap enough to run at every session start — microseconds per
/// address — and side-effect-free: port 0 binds nothing that stays bound.
/// Blocking, so an async caller runs it on a blocking thread.
pub fn probe() -> RangeProbe {
    probe_over(range_hosts(), |addr| {
        TcpListener::bind(SocketAddrV4::new(addr, 0)).map(|_| ())
    })
}

/// The probe over an injected bind, so a test can stand in for a host whose
/// loopback lacks the range. Linux carries the whole `127/8` on `lo`, so no
/// real bind on a Linux host can produce the absent arm — the injection is
/// the only way to exercise it there.
pub fn probe_over(
    hosts: impl Iterator<Item = Ipv4Addr>,
    bind: impl Fn(Ipv4Addr) -> io::Result<()>,
) -> RangeProbe {
    let mut probe = RangeProbe::failed_to_run();
    for addr in hosts {
        probe.probed += 1;
        match bind(addr) {
            Ok(()) => probe.bound += 1,
            Err(e) => {
                probe.first_failure.get_or_insert((addr, e.kind()));
            }
        }
    }
    probe
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A binder that always refuses, the shape of a host whose `lo0` carries
    /// no range alias at all (the stock macOS measured in the spike).
    fn absent(_: Ipv4Addr) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
    }

    /// A binder that always succeeds: the whole range binds.
    fn present(_: Ipv4Addr) -> io::Result<()> {
        Ok(())
    }

    #[test]
    fn a_whole_range_of_refusals_reads_absent_and_interim() {
        let probe = probe_over(range_hosts(), absent);
        assert_eq!(probe.probed, 254, "the probe covers every usable host");
        assert_eq!(probe.bound, 0);
        assert!(!probe.present());
        assert!(probe.interim(), "an absent range reads as the interim");
        assert_eq!(probe.surface(), "127.0.0.1-interim");
        assert_eq!(
            probe.first_failure,
            Some((
                Ipv4Addr::new(127, 64, 0, 1),
                io::ErrorKind::AddrNotAvailable
            )),
            "the first missing alias is the one the summary names"
        );
        assert!(
            probe.summary().contains("first refusal 127.64.0.1"),
            "{}",
            probe.summary()
        );
    }

    #[test]
    fn a_whole_range_of_binds_reads_present() {
        let probe = probe_over(range_hosts(), present);
        assert!(probe.present());
        assert!(!probe.interim());
        assert_eq!(probe.surface(), "reserved-range");
        assert_eq!(probe.first_failure, None);
    }

    /// A *partial* alias set must read as absent: the addresses the
    /// allocator could still hand out are exactly the missing ones, and a
    /// connect to one of them hangs rather than refusing (NET-123's
    /// rationale — one refused bind is enough to fall back).
    #[test]
    fn a_partial_alias_set_reads_absent() {
        let probe = probe_over(range_hosts(), |addr| {
            if addr.octets()[3] == 100 {
                absent(addr)
            } else {
                Ok(())
            }
        });
        assert_eq!(probe.probed, 254);
        assert_eq!(probe.bound, 253);
        assert!(
            !probe.present(),
            "the one missing alias fails the whole range"
        );
        assert!(probe.interim());
        assert_eq!(
            probe.first_failure.map(|(a, _)| a),
            Some(Ipv4Addr::new(127, 64, 0, 100))
        );
    }

    /// A probe that never ran reads as absent, never as present: without a
    /// verdict a host may not publish at range addresses.
    #[test]
    fn a_probe_that_never_ran_reads_absent() {
        let probe = RangeProbe::failed_to_run();
        assert!(!probe.present());
        assert!(probe.interim());
    }

    /// The real probe on this host covers the whole range. Whether it finds
    /// the range present is a fact about this host — Linux always does, a
    /// macOS host only once its aliases are installed — so only the
    /// coverage and the internal consistency are pinned.
    #[test]
    fn the_real_probe_covers_the_whole_range() {
        let probe = probe();
        assert_eq!(probe.probed, 254, "every usable host in the /24");
        assert!(probe.bound <= probe.probed);
        assert_eq!(probe.interim(), !probe.present());
        assert_eq!(
            probe.first_failure.is_none(),
            probe.present(),
            "a present range records no refusal: {probe:?}"
        );
        #[cfg(target_os = "linux")]
        assert!(
            probe.present(),
            "on Linux 127/8 is local to lo, so the range binds: {}",
            probe.summary()
        );
    }
}
