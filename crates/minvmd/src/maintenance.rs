//! Host-side scheduler for guest maintenance: an interval timer that drives
//! the in-VM minimald through a cache sweep and an `fstrim`.
//!
//! **Why the schedule lives on the host.** The obvious alternative — a timer
//! inside the guest — runs on a clock the guest does not fully own: it sets
//! from the RTC at boot and then only advances while the VM is scheduled, so a
//! laptop that sleeps leaves it hours behind (which is what
//! [`crate::timekeep`] exists to repair). A host-side timer needs no such
//! repair, and it keeps working when the guest is wedged enough to miss a timer
//! of its own. It also matches the `Shutdown` precedent: policy on the host,
//! execution in the guest.
//!
//! **The interval counts awake time, the retention counts calendar time.**
//! `recv_timeout` measures its deadline monotonically, and on macOS that clock
//! does not advance across system sleep — so the interval is really "six hours
//! of host uptime", not six hours of wall clock. That is the right unit for
//! this: a cache grows with use, not with the calendar. The sweep's retention
//! is the opposite and is applied guest-side against wall time, because "unused
//! for 14 days" *is* a calendar claim.
//!
//! **Why it declines on battery.** A cycle is unbounded-growth housekeeping
//! with no deadline; spending an ext4 `FITRIM` walk and a package resolution
//! per session on a machine running off its battery buys nothing the next
//! mains-powered tick would not. Detection is best-effort and fails *open* —
//! an unreadable power state runs the cycle, because a maintenance pass that
//! never fires is a worse failure than one that fires on battery.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

/// How long to wait for the SSH handshake with the guest daemon. Short: libkrun
/// accepts on the bridge UDS even when the guest is wedged, so only a completed
/// handshake proves a live daemon, and a wedged guest should not hold the timer
/// thread for the length of the RPC deadline.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the cycle itself. The daemon sweeps before it answers,
/// and a cache with tens of thousands of entries takes real time to walk, so
/// this is generous — it exists to stop a hung guest parking the thread
/// forever, not to bound the work.
const RPC_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A running maintenance timer. Dropping it stops the thread before the next
/// cycle: the send half closes, which wakes the loop's `recv_timeout` with
/// [`RecvTimeoutError::Disconnected`].
///
/// The stop is deliberate rather than relying on process exit: the supervisor
/// tears the VM down as soon as its VMM child exits, and dispatching a *new*
/// cycle into that window would only hang on a socket nobody is serving.
///
/// Drop does not join. A cycle already in flight is left to finish or die with
/// the process, because joining would put the supervisor's teardown behind this
/// thread's RPC deadline — and a leaked `__krun-vmm` holding the bridge socket
/// open is exactly the case where that RPC does not return promptly. Nothing
/// the thread can still do is destructive: the guest it talks to is gone, and
/// the supervisor's remaining work is writing its own state file.
pub struct MaintenanceTimer {
    /// Held only to be dropped; the loop watches the receiving end.
    _stop: Sender<()>,
}

/// Start the maintenance timer for the guest behind `uds_path`.
///
/// The first cycle fires one `interval` after this call, not immediately: a VM
/// that has just booted has nothing to reclaim, and a sweep competing with the
/// first build of a session is exactly the contention the guest-side deferral
/// exists to avoid.
///
/// # Errors
///
/// Propagates the OS error if the thread cannot be spawned.
pub fn spawn(
    uds_path: PathBuf,
    interval: Duration,
    older_than_secs: u64,
) -> std::io::Result<MaintenanceTimer> {
    let (stop, stopped) = channel();
    std::thread::Builder::new()
        .name("maintenance".to_string())
        .spawn(move || run(&uds_path, interval, older_than_secs, &stopped))?;
    tracing::info!(
        interval_secs = interval.as_secs(),
        older_than_secs,
        "guest maintenance timer started"
    );
    Ok(MaintenanceTimer { _stop: stop })
}

/// Whether another cycle is due, from the outcome of waiting out one interval
/// on the stop channel. Only a timeout means "the interval elapsed and nobody
/// stopped us"; a closed channel is the [`MaintenanceTimer`] having been
/// dropped. Split out because getting the `Disconnected` arm backwards would
/// make the timer outlive the VM it maintains, which no other test could see.
fn should_continue(wait: Result<(), RecvTimeoutError>) -> bool {
    matches!(wait, Err(RecvTimeoutError::Timeout))
}

/// Drive one cycle per `interval` until the stop channel closes.
///
/// Every failure is logged and swallowed: a maintenance cycle is best-effort
/// housekeeping, and a guest that refuses one — booting, wedged, mid-build —
/// must not take the supervisor down with it. The next tick simply tries again.
fn run(
    uds_path: &std::path::Path,
    interval: Duration,
    older_than_secs: u64,
    stopped: &Receiver<()>,
) {
    while should_continue(stopped.recv_timeout(interval)) {
        if on_battery() == Some(true) {
            tracing::debug!("host is on battery; skipping this maintenance cycle");
            continue;
        }

        match crate::rpc_client::run_guest_maintenance(
            uds_path,
            older_than_secs,
            CONNECT_TIMEOUT,
            RPC_TIMEOUT,
        ) {
            Ok(minimald_rpc::MaintenanceResponse::Completed(report)) => {
                tracing::info!(
                    cache_entries_deleted = report.cache_entries_deleted,
                    cache_bytes_deleted = report.cache_bytes_deleted,
                    cache_entries_protected = report.cache_entries_protected,
                    cache_sweep_skipped = report.cache_sweep_skipped,
                    stale_dirs_removed = report.stale_dirs_removed,
                    stale_dir_bytes_deleted = report.stale_dir_bytes_deleted,
                    bytes_trimmed = report.bytes_trimmed,
                    duration_ms = report.duration_ms,
                    "guest maintenance reclaimed state"
                );
            }
            Ok(minimald_rpc::MaintenanceResponse::Deferred { reason }) => {
                tracing::debug!(reason, "guest deferred maintenance");
            }
            Err(error) => {
                tracing::warn!(error = %error, "guest maintenance cycle failed");
            }
        }
    }
}

/// Whether the host is running from its battery.
///
/// `None` when the power state could not be determined, which callers treat as
/// mains — see the module note on failing open. A desktop with no battery
/// reports `Some(false)`, not `None`: absence of a battery is a known state.
#[must_use]
pub fn on_battery() -> Option<bool> {
    #[cfg(target_os = "macos")]
    {
        // `pmset -g batt` names the source on its first line, e.g.
        // "Now drawing from 'AC Power'". A subprocess per tick is fine at this
        // cadence, and it avoids binding IOKit for one boolean.
        let out = std::process::Command::new("/usr/bin/pmset")
            .args(["-g", "batt"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        parse_pmset(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(target_os = "linux")]
    {
        on_battery_sysfs(std::path::Path::new("/sys/class/power_supply"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// Read the power state out of a `power_supply` sysfs tree.
///
/// The mains supply's `online` flag is the authority: a laptop on its charger
/// reports `1`, on battery `0`. A tree with no `Mains` supply at all is a
/// machine with no battery either (a server), which is mains by definition.
/// An entry that cannot be read is skipped rather than failing the probe — a
/// single odd supply must not be able to suppress maintenance.
///
/// Takes the root as a parameter so the parse is testable against a fixture
/// instead of the host's actual power state.
#[cfg(any(target_os = "linux", test))]
fn on_battery_sysfs(root: &std::path::Path) -> Option<bool> {
    let mut saw_mains = false;
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let path = entry.path();
        let Ok(kind) = std::fs::read_to_string(path.join("type")) else {
            continue;
        };
        if kind.trim() != "Mains" {
            continue;
        }
        saw_mains = true;
        if std::fs::read_to_string(path.join("online")).is_ok_and(|s| s.trim() == "1") {
            return Some(false);
        }
    }
    Some(saw_mains)
}

/// Read the power source out of `pmset -g batt` output.
///
/// Pure so the parse is testable without a Mac's actual power state. `None`
/// for output that names no recognised source — a `pmset` whose format moved
/// must read as "unknown" and let maintenance proceed, not as "on battery"
/// and silently disable it forever.
#[cfg(any(target_os = "macos", test))]
fn parse_pmset(stdout: &str) -> Option<bool> {
    let line = stdout.lines().find(|l| l.contains("Now drawing from"))?;
    if line.contains("'Battery Power'") {
        Some(true)
    } else if line.contains("'AC Power'") {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmset_battery_and_ac_are_recognised() {
        assert_eq!(
            parse_pmset("Now drawing from 'Battery Power'\n -InternalBattery-0\t62%\n"),
            Some(true)
        );
        assert_eq!(
            parse_pmset("Now drawing from 'AC Power'\n -InternalBattery-0\t100%\n"),
            Some(false)
        );
    }

    /// Unrecognised output must be `None` (→ run the cycle), never `Some(true)`
    /// (→ never run it again). Getting this backwards would disable
    /// maintenance permanently on any host whose `pmset` output shifted.
    #[test]
    fn unrecognised_pmset_output_is_unknown_not_battery() {
        assert_eq!(parse_pmset(""), None);
        assert_eq!(parse_pmset("Now drawing from 'UPS Power'\n"), None);
        assert_eq!(parse_pmset("some unrelated output\n"), None);
    }

    /// Only an elapsed interval means another cycle is due. A closed channel is
    /// the timer having been dropped — reading it as "carry on" would leave the
    /// thread ticking against a VM that is gone.
    #[test]
    fn only_an_elapsed_interval_schedules_another_cycle() {
        assert!(should_continue(Err(RecvTimeoutError::Timeout)));
        assert!(!should_continue(Err(RecvTimeoutError::Disconnected)));
        assert!(!should_continue(Ok(())));
    }

    /// Spawning must not depend on the guest being reachable: the timer starts
    /// right after the VM is marked Running and dials only on its first tick.
    #[test]
    fn spawning_succeeds_without_a_live_guest_socket() {
        let timer = spawn(
            PathBuf::from("/nonexistent/minvmd-maintenance-test.sock"),
            Duration::from_secs(3600),
            60,
        )
        .expect("spawn must not require a reachable guest");
        drop(timer);
    }

    /// Builds a `power_supply` fixture: `(name, type, online)` per supply.
    fn sysfs_fixture(supplies: &[(&str, &str, Option<&str>)]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        for (name, kind, online) in supplies {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
            if let Some(online) = online {
                std::fs::write(dir.join("online"), format!("{online}\n")).unwrap();
            }
        }
        tmp
    }

    #[test]
    fn sysfs_reads_mains_online_as_not_on_battery() {
        let tmp = sysfs_fixture(&[("AC", "Mains", Some("1")), ("BAT0", "Battery", None)]);
        assert_eq!(on_battery_sysfs(tmp.path()), Some(false));
    }

    #[test]
    fn sysfs_reads_mains_offline_as_on_battery() {
        let tmp = sysfs_fixture(&[("AC", "Mains", Some("0")), ("BAT0", "Battery", None)]);
        assert_eq!(on_battery_sysfs(tmp.path()), Some(true));
    }

    /// A machine with no mains supply has no battery either — it is a server,
    /// permanently on mains, and must not have maintenance suppressed.
    #[test]
    fn sysfs_with_no_mains_supply_is_not_on_battery() {
        let tmp = sysfs_fixture(&[]);
        assert_eq!(on_battery_sysfs(tmp.path()), Some(false));
    }

    /// One unreadable supply must not decide the probe. Here the only mains
    /// entry has no `online` file: unknown, so the tree falls through to "a
    /// mains supply exists", not to "on battery".
    #[test]
    fn sysfs_skips_supplies_it_cannot_read() {
        let tmp = sysfs_fixture(&[("AC", "Mains", None), ("weird", "Mains", Some("1"))]);
        assert_eq!(on_battery_sysfs(tmp.path()), Some(false));
        let missing = tmp.path().join("no-such-root");
        assert_eq!(
            on_battery_sysfs(&missing),
            None,
            "unreadable root is unknown"
        );
    }
}
