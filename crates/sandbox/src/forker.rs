//! The one thread every sandbox container is forked on.
//!
//! hakoniwa's `Command::spawn` is a bare `fork()` on the calling thread, and
//! the forked container arms `PR_SET_PDEATHSIG(SIGKILL)`. Linux delivers that
//! signal when the parent *thread* exits, not the parent process, and nothing
//! ever clears it, so a container lives exactly as long as the thread that
//! forked it. Runtime threads are not a safe parent: `block_in_place`
//! displaces a worker onto a fresh thread and retires the old one after its
//! idle keep-alive, and blocking-pool threads are retired the same way. Every
//! container forked on a retired thread dies with a spurious SIGKILL, taking
//! unrelated sessions and builds with it.
//!
//! This module owns one thread, started on first use and never joined, and
//! runs every fork on it. The thread outlives every container it forks, so
//! callers may run on any thread the runtime cares to retire.

use std::sync::OnceLock;
use std::sync::mpsc;

type Job = Box<dyn FnOnce() + Send>;

fn sender() -> &'static mpsc::Sender<Job> {
    static SENDER: OnceLock<mpsc::Sender<Job>> = OnceLock::new();
    SENDER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("sandbox-fork".into())
            .spawn(move || {
                for job in rx {
                    job();
                }
            })
            .expect("spawn the sandbox fork thread");
        tx
    })
}

/// Runs `f` on the process-wide fork thread and blocks until it returns.
///
/// Anything that forks a container goes through here rather than forking on
/// its own thread; see the module docs. The caller blocks for the duration of
/// `f`, which for a container spawn is the fork-and-exec handshake, the same
/// time a direct `spawn()` costs.
///
/// A panic in `f` unwinds on the fork thread, is carried back, and is
/// re-raised here; the fork thread itself survives it.
pub fn on_fork_thread<T, F>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    let job: Job = Box::new(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        let _ = tx.send(result);
    });
    // The static sender keeps the receiver loop alive for the life of the
    // process, so neither send nor recv can fail.
    sender()
        .send(job)
        .expect("the sandbox fork thread has exited");
    match rx.recv().expect("the sandbox fork thread dropped a job") {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};
    use std::time::Duration;

    /// Spawns `sleep` with `PR_SET_PDEATHSIG(SIGKILL)` armed, as a hakoniwa
    /// container is, bound to whichever thread runs the spawn. `spawn`
    /// returns only after `exec` succeeded, so the signal is armed before
    /// the caller can exit.
    fn spawn_bound_to_parent_thread() -> Child {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        // SAFETY: the closure runs in the forked child before exec and makes
        // one async-signal-safe syscall; it allocates nothing and takes no
        // lock.
        unsafe {
            cmd.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().expect("spawn sleep")
    }

    /// Whether `child` is still running after `wait`; reaps it either way.
    fn alive_after(child: &mut Child, wait: Duration) -> bool {
        std::thread::sleep(wait);
        let alive = child.try_wait().expect("try_wait").is_none();
        let _ = child.kill();
        let _ = child.wait();
        alive
    }

    /// The control: what a spawn on a retired runtime thread does.
    #[test]
    fn a_fork_on_a_short_lived_thread_dies_with_it() {
        let mut child = std::thread::spawn(spawn_bound_to_parent_thread)
            .join()
            .expect("spawning thread");
        assert!(!alive_after(&mut child, Duration::from_millis(200)));
    }

    #[test]
    fn a_fork_on_the_fork_thread_outlives_the_caller() {
        let mut child = std::thread::spawn(|| on_fork_thread(spawn_bound_to_parent_thread))
            .join()
            .expect("spawning thread");
        assert!(alive_after(&mut child, Duration::from_millis(200)));
    }

    #[test]
    fn a_panic_is_reraised_and_the_fork_thread_survives() {
        let caught = std::panic::catch_unwind(|| on_fork_thread(|| panic!("boom")));
        assert!(caught.is_err());
        assert_eq!(on_fork_thread(|| 7), 7);
    }
}
