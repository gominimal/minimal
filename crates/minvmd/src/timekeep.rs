//! Host→guest wall-clock updates: the host half of `minimald`'s
//! `guest::run_timekeep_listener`.
//!
//! The guest clock only advances while the VM is scheduled, so a host that
//! suspends leaves the guest's `CLOCK_REALTIME` frozen at the moment it went
//! down, and every later guest timestamp is wrong — TLS handshakes fail on
//! not-yet-valid certificates, build systems see sources "from the future".
//! libkrun ships a timesync worker for exactly this, but it sends AF_VSOCK
//! **datagrams**, which exist only under the TSI patchset carried by libkrun's
//! own kernel; we boot the generic upstream kernel, where nothing can receive
//! them. This module is the replacement: the guest *listens* on a vsock
//! **stream** and the host dials in and writes timestamps.
//!
//! ```text
//!  host (sender thread)               libkrun              guest
//!  ┌──────────────────┐  UNIX sock   ┌─────────┐  vsock   ┌───────────────────┐
//!  │ 8-byte LE stamps │─────────────▶│ vsock   │─────────▶│ minimald listener │
//!  │ every 60s + wake │ timekeep.sock│ bridge  │  :7351   │ steps CLOCK_REALTIME
//!  └──────────────────┘              └─────────┘          └───────────────────┘
//! ```
//!
//! **Why a socket file on disk.** libkrun's whole vsock surface is
//! `krun_add_vsock_port{,2}(ctx, port, const char *filepath[, listen])`: a
//! filesystem path, registered before `krun_start_enter`. There is no
//! fd-passing variant and no API to reach a guest vsock port from the host once
//! the VM is up, so a host→guest channel *must* be a UDS on disk. It lands
//! beside the two that already exist for the same reason (`ssh.sock`,
//! `gvproxy-switch.sock`) in the minvmd provider dir.
//!
//! The registration is `listen = true` — libkrun binds the host UDS and bridges
//! each accepted connection to the guest process listening on the vsock port —
//! the same direction as the minimald SSH bridge
//! ([`crate::sock::VSOCK_BRIDGE_PORT`]), and the mirror of the guest-initiated
//! READY marker ([`crate::cmd::VSOCK_MARKER_PORT`]).

use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// vsock port the in-guest listener binds, which libkrun bridges the host UDS
/// to.
///
/// Mirrors `minimald`'s `guest::TIMEKEEP_PORT` — minvmd does not depend on the
/// minimald crate, so the value is duplicated here, exactly as
/// [`crate::cmd::VSOCK_MARKER_PORT`] duplicates the guest's boot-marker port.
/// Keep the two in step. Distinct from every other vsock port minvmd registers
/// (asserted in the tests below).
pub const VSOCK_TIMEKEEP_PORT: u32 = 7351;

/// How often a healthy sender re-states the host time. Matches the cadence of
/// libkrun's own timesync worker; the guest ignores an update it is already
/// within 80 ms of, so this is a cheap keepalive that costs 8 bytes a minute.
const HEARTBEAT: Duration = Duration::from_secs(60);

/// How often the sender wakes to check whether an update is due. Bounds how
/// long a guest can stay frozen after the host wakes from suspend, and doubles
/// as the retry interval while the bridge or the guest listener is not up yet
/// (through boot, when both are still coming up).
const TICK: Duration = Duration::from_secs(5);

/// Wall-vs-monotonic disagreement across one tick that counts as the host
/// having suspended (or had its clock stepped) rather than clock jitter.
const CLOCK_JUMP_THRESHOLD: Duration = Duration::from_secs(1);

/// Resolve the host UDS path libkrun binds for the timekeep bridge.
///
/// Placed beside the minimald bridge socket (same parent dir, already created
/// with mode 0700 by [`crate::sock::prepare_socket_dir`]), like the gvproxy
/// switch socket.
///
/// # Errors
///
/// Propagates [`crate::sock::resolve_uds_path`]'s error.
pub fn resolve_timekeep_sock() -> io::Result<PathBuf> {
    Ok(timekeep_sock_beside(&crate::sock::resolve_uds_path()?))
}

/// The timekeep socket path beside a given minimald bridge UDS (same parent
/// dir). Pure — derived only from `uds`, no env — so it is unit-testable
/// without mutating process-global state.
fn timekeep_sock_beside(uds: &Path) -> PathBuf {
    uds.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("timekeep.sock")
}

/// Whether the wall clock moved further than the monotonic clock did over the
/// same tick — the host suspended, or its clock was stepped, and the guest's
/// frozen clock wants correcting now rather than at the next heartbeat.
///
/// On macOS [`Instant`] is `mach_absolute_time`, which does *not* advance while
/// the machine is asleep, so a suspend shows up here as a large wall delta
/// against a near-zero monotonic one.
fn clock_jumped(monotonic: Duration, wall: Duration) -> bool {
    wall.abs_diff(monotonic) > CLOCK_JUMP_THRESHOLD
}

/// Whether an update should go out on this tick: the heartbeat has come round
/// (or nothing has been delivered yet), or a jump-triggered update is still
/// outstanding.
///
/// `jump_pending` is deliberately not folded into `last_sent`: a clock jump is
/// detected from one tick's deltas, so if the send that follows it fails, the
/// next tick sees no jump at all. Without the flag the correction the guest
/// most needs — the one right after the host wakes, exactly when the bridge is
/// most likely to be broken — would wait for the next heartbeat.
fn update_due(last_sent: Option<Instant>, now: Instant, jump_pending: bool) -> bool {
    jump_pending || last_sent.is_none_or(|sent| now.duration_since(sent) >= HEARTBEAT)
}

/// The update payload: nanoseconds since the Unix epoch, as the guest decodes
/// it (`u64::from_le_bytes`). `None` for a clock before the epoch or beyond
/// what 64 bits of nanoseconds can carry (year 2554) — both unrepresentable in
/// the wire format rather than errors to handle.
fn stamp_nanos(now: SystemTime) -> Option<u64> {
    u64::try_from(now.duration_since(UNIX_EPOCH).ok()?.as_nanos()).ok()
}

/// Start the sender thread for the timekeep bridge at `sock`.
///
/// Spawn this **before** `krun_start_enter`, which never returns: libkrun binds
/// `sock` while starting the VM, and the guest listener only comes up once
/// minimald is running, so the thread expects to find nothing there for the
/// first tens of seconds and retries every [`TICK`] until it connects.
///
/// The thread runs for the life of the process (libkrun `exit()`s it when the
/// guest ends), so the returned handle is safe to drop.
///
/// # Errors
///
/// Propagates the OS error if the thread cannot be spawned.
pub fn spawn(sock: PathBuf) -> io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("timekeep".to_string())
        .spawn(move || run(&sock))
}

/// Send the host wall clock to the guest every [`HEARTBEAT`], and immediately
/// whenever the host looks to have woken from suspend.
///
/// Holds one connection across updates and redials on any failure. A dead
/// connection can cost one update: libkrun accepts on the host UDS before it
/// knows whether the guest port is listening, so an early write can be buffered
/// into a bridge that then closes. The guest is idempotent — every update
/// carries an absolute time, not a delta — so the next one repairs it.
fn run(sock: &Path) {
    let mut conn: Option<std::os::unix::net::UnixStream> = None;
    let mut last_monotonic = Instant::now();
    let mut last_wall = SystemTime::now();
    // `None` until the guest has taken an update: until then every tick is due,
    // which is what walks the sender through boot to the first success.
    let mut last_sent: Option<Instant> = None;
    // A detected jump stays outstanding until an update is actually delivered,
    // so a failed send retries every TICK instead of falling back to the
    // heartbeat (see `update_due`).
    let mut jump_pending = false;
    let mut announced = false;

    loop {
        std::thread::sleep(TICK);
        let (monotonic, wall) = (Instant::now(), SystemTime::now());
        // A wall clock that ran backwards is a step by definition; `Err` here
        // *is* the jump, not a failure to measure one.
        let jumped = match wall.duration_since(last_wall) {
            Ok(elapsed_wall) => {
                clock_jumped(monotonic.duration_since(last_monotonic), elapsed_wall)
            }
            Err(_) => true,
        };
        (last_monotonic, last_wall) = (monotonic, wall);
        jump_pending |= jumped;

        if !update_due(last_sent, monotonic, jump_pending) {
            continue;
        }
        let Some(stamp) = stamp_nanos(wall) else {
            tracing::warn!("host wall clock is not representable; skipping the time update");
            continue;
        };

        if conn.is_none() {
            match std::os::unix::net::UnixStream::connect(sock) {
                // Bound the send: a bridge that accepts but never drains would
                // otherwise park this thread in `write_all` for the life of the
                // VM, ending updates entirely. One tick is ample for 8 bytes,
                // and a timed-out write is handled like any other send failure
                // — redial, retry next tick.
                Ok(stream) => match stream.set_write_timeout(Some(TICK)) {
                    Ok(()) => conn = Some(stream),
                    Err(e) => {
                        tracing::debug!(error = %e, "cannot bound the timekeep send; redialling");
                        continue;
                    }
                },
                // Expected until libkrun binds the socket and the guest
                // listener is up; retried on the next tick.
                Err(e) => {
                    tracing::debug!(sock = %sock.display(), error = %e, "timekeep bridge not up yet");
                    continue;
                }
            }
        }
        let stream = conn.as_mut().expect("connected just above");

        use std::io::Write as _;
        match stream
            .write_all(&stamp.to_le_bytes())
            .and_then(|()| stream.flush())
        {
            Ok(()) => {
                last_sent = Some(monotonic);
                jump_pending = false;
                if !announced {
                    announced = true;
                    tracing::info!(sock = %sock.display(), "sending host time updates to the guest");
                } else {
                    tracing::trace!(stamp, jumped, "sent a host time update");
                }
            }
            // Redial on the next tick — which is also the retry cadence, since
            // a failed send leaves the update due: `jump_pending` is kept, so a
            // post-wake correction retries every TICK until it lands.
            Err(e) => {
                tracing::debug!(error = %e, "timekeep connection failed; redialling");
                conn = None;
                announced = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timekeep_port_is_distinct_from_the_other_vsock_ports() {
        assert_ne!(VSOCK_TIMEKEEP_PORT, crate::cmd::VSOCK_MARKER_PORT);
        assert_ne!(VSOCK_TIMEKEEP_PORT, crate::sock::VSOCK_BRIDGE_PORT);
        assert_ne!(VSOCK_TIMEKEEP_PORT, crate::net::VSOCK_GVPROXY_SHUTTLE_PORT);
    }

    #[test]
    fn timekeep_sock_sits_beside_the_bridge_socket() {
        // Pure helper, asserted directly — no env mutation, so this can't race
        // other tests that read the env (std::env is process-global).
        let uds = std::path::Path::new("/run/user/1000/minimal/ssh.sock");
        assert_eq!(
            timekeep_sock_beside(uds),
            PathBuf::from("/run/user/1000/minimal/timekeep.sock")
        );
    }

    /// Ordinary ticks are not suspends: a monotonic and a wall clock that
    /// advanced together leave the heartbeat to do the work.
    #[test]
    fn a_tick_where_both_clocks_advanced_together_is_not_a_jump() {
        assert!(!clock_jumped(TICK, TICK));
        // Scheduling noise either side of the tick stays below the threshold.
        assert!(!clock_jumped(TICK, TICK + Duration::from_millis(200)));
        assert!(!clock_jumped(TICK + Duration::from_millis(200), TICK));
    }

    /// The case the detector exists for: the host slept for an hour, so the
    /// wall clock advanced while `Instant` (mach_absolute_time on macOS) did
    /// not. A clock stepped backwards counts too.
    #[test]
    fn a_wall_clock_that_outran_the_monotonic_one_is_a_jump() {
        assert!(clock_jumped(
            Duration::from_millis(20),
            Duration::from_secs(3600)
        ));
        // Backwards is symmetric — `abs_diff`, not a signed comparison.
        assert!(clock_jumped(
            Duration::from_secs(3600),
            Duration::from_millis(20)
        ));
    }

    /// The send schedule: nothing delivered yet, or the heartbeat has come
    /// round, or a jump is still outstanding.
    #[test]
    fn an_update_is_due_on_the_heartbeat_and_while_a_jump_is_outstanding() {
        let now = Instant::now();
        let recent = now.checked_sub(TICK).expect("an instant a tick ago");
        let stale = now
            .checked_sub(HEARTBEAT)
            .expect("an instant a heartbeat ago");

        // Nothing delivered yet: due every tick, which walks the sender
        // through boot to its first success.
        assert!(update_due(None, now, false));
        // Delivered a tick ago, no jump: wait for the heartbeat.
        assert!(!update_due(Some(recent), now, false));
        assert!(update_due(Some(stale), now, false));

        // A jump outstanding overrides the heartbeat — this is the retry that
        // gets a post-wake correction through after a failed send, when the
        // tick that detected the jump is long past.
        assert!(update_due(Some(recent), now, true));
    }

    /// The wire format the guest decodes: 8 bytes, little endian, nanoseconds
    /// since the epoch.
    #[test]
    fn the_stamp_is_little_endian_nanoseconds_since_the_epoch() {
        let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let stamp = stamp_nanos(at).expect("a 2023 timestamp is representable");
        assert_eq!(stamp, 1_700_000_000_123_456_789);
        assert_eq!(u64::from_le_bytes(stamp.to_le_bytes()), stamp);

        // The epoch itself is a valid stamp; anything before it is not.
        assert_eq!(stamp_nanos(UNIX_EPOCH), Some(0));
        assert_eq!(stamp_nanos(UNIX_EPOCH - Duration::from_secs(1)), None);
    }
}
