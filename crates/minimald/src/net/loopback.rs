//! The session-start loopback probe (NET-123): bind-probe the reserved local
//! range before publishing, and report the `127.0.0.1` interim when it is
//! absent — the verdict the `CreateSession` reply carries and the one the
//! client re-surfaces the naming advisory on (NET-122).
//!
//! The probe itself — the walk over the range, the verdict, its summary —
//! is `switch::loopback`, next to the range constant it probes and shared
//! with the CLI's `min bug` record, so the daemon's verdict and the bundle's
//! cannot differ for one host. This module holds what is the daemon's: the
//! test stand-in the `CreateSession` handler reads.
//!
//! Whose loopback the probe measures: the daemon's own host, and only that
//! host. This daemon is a Linux process — running natively, or as the guest
//! of a libkrun microVM — and on Linux the whole `127/8` is local to `lo`, so
//! its probe always reads the range present. The absent verdict is a fact
//! about a *macOS* host's `lo0`, the aliases the privileged step installs,
//! and the probe that can see them belongs to the microVM host (`minvmd`);
//! until that lands, a VM-backed daemon's flag stays the guest's verdict.
//!
//! What the verdict carries in this change: the reply flag and the one
//! session-start log line, no more. It does not switch the addresses a
//! session's boxes publish — those still follow the node (a native node's
//! boxes already mirror `127.0.0.1`; a VM node's publish their switch
//! leases), so NET-123's "publish the box at `127.0.0.1`" is the change this
//! verdict feeds rather than one the flag makes: the per-box allocation over
//! the range is what has a range address to fall back *from*, and it
//! consumes this verdict when it lands. `rpc.rs`'s create handler is where
//! the verdict is read.

pub use ::switch::loopback::{RangeProbe, probe};

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
