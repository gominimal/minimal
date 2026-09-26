//! The session-start loopback probe (NET-123): bind-probe the reserved local
//! range before publishing, and report the `127.0.0.1` interim when it is
//! absent — the verdict the `CreateSession` reply carries and the one the
//! client re-surfaces the naming advisory on (NET-122).
//!
//! One TCP `bind` with port 0 per address of the reserved local range — a
//! few milliseconds for the whole /24 (2.53 ms over 256 addresses, measured
//! in the macOS loopback-alias spike, `docs/spikes/2026-09-22-macos-loopback-alias.md`).
//! A bind with port 0 cannot collide with a live listener, and it answers in
//! microseconds either way: where the address exists it succeeds, where it
//! does not it fails with `EADDRNOTAVAIL` — the "range absent" verdict. A
//! *connect* to an absent address would instead hang to timeout, never
//! refuse, which is why the interim exists: until the aliases are installed,
//! a box must not be handed out at an address its fetches would time out on
//! rather than fail — the requirement this verdict is the input for.
//!
//! The probe is deliberately whole-range: a partial alias set — some
//! addresses aliased on `lo0`, some not — must read as absent, since the
//! allocator could otherwise hand out exactly the address that hangs.
//!
//! Whose loopback the probe measures: the daemon's own host, and only that
//! host. This daemon is a Linux process — running natively, or as the guest
//! of a libkrun microVM — and on Linux the whole `127/8` is local to `lo`, so
//! its probe always reads the range present. The absent verdict is a fact
//! about a *macOS* host's `lo0`, the aliases the privileged step installs,
//! and the probe that can see them belongs to the microVM host (`minvmd`);
//! until that lands, a VM-backed daemon's flag stays the guest's verdict.
//! Nothing about a port-0 bind is Linux-specific, so the probe itself is not
//! gated by target OS — on whatever host it runs, it measures that host.
//!
//! What the verdict carries in this change: the reply flag and the one
//! session-start log line, no more. It does not switch the addresses a
//! session's boxes publish — those still follow the node (a native node's
//! boxes already mirror `127.0.0.1`; a VM node's publish their switch
//! leases), so NET-123's "publish the box at `127.0.0.1`" is the change this
//! verdict feeds rather than one the flag makes. `rpc.rs`'s create handler is
//! where the verdict is read.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

use super::dns::RESERVED_LOCAL_RANGE;

/// What the session-start probe found, over the whole reserved local range.
///
/// Carried onto the `CreateSession` reply as the interim flag (the absent
/// verdict), and into the daemon log's one session-start line as the
/// surface it picked.
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
    /// let the daemon report the range present, so it reads as absent — the
    /// reply then carries the interim.
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
    /// (NET-123). This is the flag the `CreateSession` reply carries and the
    /// one that re-surfaces the naming advisory on the client (NET-122): a
    /// host that reports it is a host whose loopback carries none of the
    /// range, the per-host state the privileged step that installs the range
    /// supersedes.
    pub fn interim(&self) -> bool {
        !self.present()
    }

    /// The publish surface the probe picked, for the session-start log line.
    pub fn surface(&self) -> &'static str {
        if self.interim() {
            "127.0.0.1-interim"
        } else {
            "reserved-range"
        }
    }

    /// What the probe found, one line for the log and the diagnostics
    /// bundle: the range, the bound count out of the probed count, and the
    /// first refusal when there was one.
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
/// and the boot step that re-applies the range installs exactly these 254
/// aliases — so these are the addresses publication would hand out and the
/// ones the probe has to speak for.
fn range_hosts() -> impl Iterator<Item = Ipv4Addr> {
    let (base, prefix_bits) = RESERVED_LOCAL_RANGE;
    let hosts = 1u32 << (32 - u32::from(prefix_bits));
    let base = u32::from(base);
    (1..hosts - 1).map(move |host| Ipv4Addr::from(base + host))
}

/// The real probe: one `bind((addr, 0))` per address in the reserved local
/// range. Cheap enough to run at every session start — microseconds per
/// address — and side-effect-free: port 0 binds nothing that stays bound.
pub fn probe() -> RangeProbe {
    probe_over(range_hosts(), |addr| {
        TcpListener::bind(SocketAddrV4::new(addr, 0)).map(|_| ())
    })
}

/// The probe over an injected bind, so a test can stand in for a host whose
/// `lo` lacks the range. Linux carries the whole `127/8` on `lo`, so no real
/// bind on a Linux host can produce the absent arm — the injection is the
/// only way to exercise it.
pub(crate) fn probe_over(
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

/// The test stand-in for the session-start probe, when one is installed: a
/// `fn` so it needs no capture, process-global because the probe has no
/// caller to thread through — the `CreateSession` handler reads it at
/// session start. Production builds never read this (the field is compiled
/// out); a test that installs one serializes against every other test in
/// the binary that drives a create, since the stand-in is process-global.
#[cfg(any(test, feature = "test-support"))]
static PROBE_STANDIN: std::sync::Mutex<Option<fn() -> RangeProbe>> = std::sync::Mutex::new(None);

/// Installs the probe a test wants the session-start path to see.
///
/// The tests that use this take the probe-test mutex in rpc.rs's test module
/// for the whole install→create→assert→clear window: under libtest the tests
/// of one binary share a process, and a concurrent create would read the
/// stand-in too.
#[cfg(any(test, feature = "test-support"))]
pub fn install_probe_standin(probe: fn() -> RangeProbe) {
    *PROBE_STANDIN.lock().unwrap() = Some(probe);
}

/// Clears the test stand-in, restoring the real bind probe.
#[cfg(any(test, feature = "test-support"))]
pub fn clear_probe_standin() {
    *PROBE_STANDIN.lock().unwrap() = None;
}

/// The probe to run at session start: the test stand-in when one is
/// installed, else the real bind probe. Test-support only: the production
/// handler calls [`probe`] directly.
#[cfg(any(test, feature = "test-support"))]
pub fn session_start_probe() -> RangeProbe {
    let standin = *PROBE_STANDIN.lock().unwrap();
    (standin.unwrap_or(probe))()
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
    /// verdict the daemon may not publish at range addresses.
    #[test]
    fn a_probe_that_never_ran_reads_absent() {
        let probe = RangeProbe::failed_to_run();
        assert!(!probe.present());
        assert!(probe.interim());
    }

    /// The real probe on this host covers the whole range, and on Linux —
    /// where the whole `127/8` is local to `lo` — finds it present.
    #[test]
    fn the_real_probe_covers_the_whole_range() {
        let probe = probe();
        assert_eq!(probe.probed, 254, "every usable host in 127.64.0.0/24");
        assert!(
            probe.present(),
            "on Linux 127/8 is local to lo, so the range binds: {}",
            probe.summary()
        );
    }
}
