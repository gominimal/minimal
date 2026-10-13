//! Orphan reaping for the microVM's init.
//!
//! In the microVM the kernel runs this binary as pid 1, and pid 1 inherits
//! every orphan in the guest: a process whose parent exits first is
//! reparented to it, and when that process exits it stays a zombie until
//! pid 1 waits for it. A session shell that outlives its parent, or a
//! `git` that detaches a background job, leaves one zombie each, and nothing
//! else in the guest can clear them. The pid table is finite, so a
//! long-lived VM would slowly run out of pids.
//!
//! The daemon cannot simply wait for "any child" itself. tokio's process
//! driver reaps the `tokio::process::Child`ren it spawned by pid, and the
//! session host blocks in hakoniwa's `Child::wait()` on its container's pid.
//! A `waitpid(-1)` in the same process would take those exit statuses first,
//! turning a normal session exit into a hang or a wrong exit code.
//!
//! So pid 1 splits in two before it does anything else: [`split_init`]
//! forks, the daemon carries on in the child, and pid 1 stays behind as a
//! reaper that only ever waits for any child. Every process the daemon
//! spawns is the daemon's child, so tokio and hakoniwa keep reaping their
//! own exactly as on a native host. The only children pid 1 ever has are
//! the daemon and the orphans reparented to it, and an orphan has no other
//! owner, so nothing it reaps was anyone else's to wait for.
//!
//! pid 1 forwards no signals. The daemon installs no signal handlers, and
//! the kernel drops every signal sent to pid 1 from inside its namespace
//! that pid 1 has no handler for. Forwarding them would turn signals that
//! are dropped today into ones that kill the daemon.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set in the daemon half of [`split_init`]: this process was forked by the
/// microVM's init and is the guest daemon, though it is no longer pid 1.
static FORKED_FROM_MICROVM_INIT: AtomicBool = AtomicBool::new(false);

/// Whether this process is the daemon [`split_init`] forked off the
/// microVM's init.
///
/// Only code that has itself verified it is the microVM's init sets this,
/// before the fork, so it carries pid 1's guarantee into the child: nothing
/// outside the guest can make it true.
pub fn forked_from_microvm_init() -> bool {
    FORKED_FROM_MICROVM_INIT.load(Ordering::Relaxed)
}

/// Splits the microVM's init into the daemon and an orphan reaper.
///
/// Returns in the forked child, which goes on to run the daemon. In pid 1 it
/// never returns: pid 1 reaps every child that exits until the daemon does,
/// then takes the VM down, because there is no daemon left to serve it.
///
/// If the fork fails, this returns in pid 1 itself and the daemon runs
/// unsplit as before, with orphans left unreaped: a daemon that cannot fork
/// at boot is still better than a guest that never comes up.
///
/// Must be called while the process is still single-threaded, before the
/// tokio runtime is built.
pub fn split_init() {
    // SAFETY: `main` calls this before the tokio runtime or any other thread
    // exists, so the child is a complete copy of a single-threaded process
    // and may go on to do anything. The parent only waits, writes to stderr
    // and calls `sync`/`reboot`.
    match unsafe { libc::fork() } {
        0 => FORKED_FROM_MICROVM_INIT.store(true, Ordering::Relaxed),
        -1 => {
            let error = std::io::Error::last_os_error();
            let _ = writeln!(
                std::io::stderr(),
                "minimald: could not fork the daemon off pid 1 ({error}); running as pid 1 \
                 itself, so orphaned processes will not be reaped",
            );
        }
        daemon => reap_as_init(daemon),
    }
}

/// pid 1's whole life after [`split_init`]: reap until the daemon exits,
/// then take the VM down.
///
/// Writes with `let _ =` rather than `eprintln!`, which panics when stderr is
/// gone: pid 1 must never exit, since exiting init panics the guest kernel.
fn reap_as_init(daemon: libc::pid_t) -> ! {
    let status = reap_until_exit(daemon, |_, _| {});
    let _ = writeln!(
        std::io::stderr(),
        "minimald: the daemon (pid {daemon}) is gone ({status:?}); shutting the VM down",
    );
    let error = crate::guest::shut_down_vm();
    let _ = writeln!(
        std::io::stderr(),
        "minimald: shutting the VM down failed ({error}); pid 1 keeps reaping",
    );
    loop {
        if reap_one().is_none() {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }
}

/// How a reaped child ended, as `waitpid` reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exit {
    /// Exited with this code.
    Code(i32),
    /// Killed by this signal.
    Signal(i32),
}

/// Waits for any child, blocking, and returns the pid and how it ended.
/// `None` once this process has no children left.
fn reap_one() -> Option<(libc::pid_t, Exit)> {
    loop {
        let mut status = 0;
        // SAFETY: `waitpid` writes the status through the pointer, which
        // points at a live local for the duration of the call.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
        if pid > 0 {
            let exit = if libc::WIFSIGNALED(status) {
                Exit::Signal(libc::WTERMSIG(status))
            } else {
                Exit::Code(libc::WEXITSTATUS(status))
            };
            return Some((pid, exit));
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            // ECHILD: no children at all.
            return None;
        }
    }
}

/// Reaps every child of this process until `daemon` exits, handing each
/// other one to `on_orphan`, and returns how the daemon ended. `None` if
/// this process runs out of children without having seen the daemon exit,
/// which means it was never this process's child.
///
/// Every other child is an orphan: run as [`split_init`]'s pid 1, the daemon
/// is the only child this process ever spawns.
pub(crate) fn reap_until_exit(
    daemon: libc::pid_t,
    mut on_orphan: impl FnMut(libc::pid_t, Exit),
) -> Option<Exit> {
    while let Some((pid, exit)) = reap_one() {
        if pid == daemon {
            return Some(exit);
        }
        on_orphan(pid, exit);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which half of the split a re-exec of this test binary plays.
    const ROLE_ENV: &str = "MINIMALD_REAPER_TEST_ROLE";
    /// Where the daemon half writes the pid of the orphan it made, so the
    /// reaper half can check it reaped exactly that process.
    const ORPHAN_PID_FILE_ENV: &str = "MINIMALD_REAPER_TEST_ORPHAN_PID_FILE";

    /// Re-runs this test binary for exactly one test, with `role` set.
    fn rerun(test: &str, role: &str) -> std::process::Command {
        let mut cmd =
            std::process::Command::new(std::env::current_exe().expect("locating the test binary"));
        cmd.args([test, "--exact", "--nocapture", "--test-threads=1"])
            .env(ROLE_ENV, role);
        cmd
    }

    /// The split end to end, with `PR_SET_CHILD_SUBREAPER` standing in for
    /// pid 1. A re-exec of this binary plays pid 1: it marks itself a
    /// subreaper, so orphans below it are reparented to it, spawns the
    /// "daemon" (another re-exec) and runs the real reap loop. The daemon
    /// half makes an orphan and owns children of its own, one reaped by
    /// tokio and one waited on blockingly, the way hakoniwa's
    /// `Child::wait()` is.
    ///
    /// The orphan must be reaped by the reaper half, and both owned
    /// children must still report their own exit codes while that reap loop
    /// runs, so the loop steals no exit status.
    ///
    /// Each half runs in its own process because a subreaper's `waitpid(-1)`
    /// would race every other test's children in a shared test process.
    #[test]
    fn pid_1_reaps_orphans_and_the_daemon_keeps_its_own_children() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let orphan_pid_file = dir.path().join("orphan.pid");
        let output = rerun("reaper::tests::reaper_half", "reaper")
            .env(ORPHAN_PID_FILE_ENV, &orphan_pid_file)
            .output()
            .expect("running the reaper half");
        assert!(
            output.status.success(),
            "the reaper half failed ({}):\n--- stdout\n{}\n--- stderr\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// pid 1's half: only does anything when re-run by the test above.
    #[test]
    fn reaper_half() {
        if std::env::var_os(ROLE_ENV).is_none_or(|role| role != "reaper") {
            return;
        }
        // SAFETY: `prctl` with integer arguments only.
        let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        assert_eq!(
            rc,
            0,
            "PR_SET_CHILD_SUBREAPER: {}",
            std::io::Error::last_os_error()
        );

        let daemon = rerun("reaper::tests::daemon_half", "daemon")
            .spawn()
            .expect("spawning the daemon half");
        let daemon_pid = libc::pid_t::try_from(daemon.id()).expect("a pid fits pid_t");
        // The reap loop below waits for it; `std`'s handle must not.
        drop(daemon);

        let mut orphans = Vec::new();
        let exit = reap_until_exit(daemon_pid, |pid, exit| orphans.push((pid, exit)));
        assert_eq!(
            exit,
            Some(Exit::Code(0)),
            "the daemon half reports its children's exit codes intact"
        );

        let orphan: libc::pid_t = std::fs::read_to_string(
            std::env::var_os(ORPHAN_PID_FILE_ENV).expect("the orphan pid file is named"),
        )
        .expect("the daemon half wrote the orphan's pid")
        .trim()
        .parse()
        .expect("the orphan's pid is a number");
        assert!(
            orphans.contains(&(orphan, Exit::Code(0))),
            "the orphan {orphan} was reaped by pid 1's half; reaped: {orphans:?}"
        );
    }

    /// The daemon's half: only does anything when re-run by the reaper half.
    #[test]
    fn daemon_half() {
        if std::env::var_os(ROLE_ENV).is_none_or(|role| role != "daemon") {
            return;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("a tokio runtime");
        runtime.block_on(async {
            // An orphan: `sh` backgrounds a subshell and exits at once, so
            // the subshell is reparented to the nearest subreaper, the
            // reaper half. It outlives `sh` by a moment so the reparenting
            // happens before it exits.
            let orphan = tokio::process::Command::new("sh")
                .args(["-c", "(sleep 0.2; exit 0) >/dev/null 2>&1 & echo $!"])
                .output()
                .await
                .expect("making an orphan");
            assert!(orphan.status.success());
            let orphan_pid = String::from_utf8(orphan.stdout).expect("utf-8 pid");
            std::fs::write(
                std::env::var_os(ORPHAN_PID_FILE_ENV).expect("the orphan pid file is named"),
                orphan_pid.trim(),
            )
            .expect("recording the orphan's pid");

            // A tokio-owned child: tokio's process driver reaps it.
            let status = tokio::process::Command::new("sh")
                .args(["-c", "sleep 0.3; exit 7"])
                .status()
                .await
                .expect("running a tokio child");
            assert_eq!(
                status.code(),
                Some(7),
                "tokio sees its own child's exit code"
            );

            // A child waited on blockingly by pid, as hakoniwa's
            // `Child::wait()` does for the session host.
            let status = tokio::task::spawn_blocking(|| {
                std::process::Command::new("sh")
                    .args(["-c", "sleep 0.3; exit 5"])
                    .status()
            })
            .await
            .expect("the blocking wait ran")
            .expect("running a blocking-waited child");
            assert_eq!(
                status.code(),
                Some(5),
                "a blocking wait sees its own child's exit code"
            );

            // The orphan is gone entirely, zombie included, which only a
            // wait by its new parent, the reaper half, can achieve.
            let proc_dir = format!("/proc/{}", orphan_pid.trim());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while std::path::Path::new(&proc_dir).exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the orphan {} was never reaped",
                    orphan_pid.trim()
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        });
    }
}
