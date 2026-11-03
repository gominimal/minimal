//! The process backends: how a box's process is waited on, signalled and
//! accounted for when it ends.

use super::*;

/// How a session process ended, as `hakoniwa` accounts for it.
///
/// Kept alongside the portable exit code because the code alone cannot say
/// whether a session *ended* or was *killed*: a clean `exit 0` and a SIGKILL
/// both close every slave fd, both surface on the master as the same `EIO`,
/// and both otherwise raise the same silent shell-exit prompt. This is what
/// separates them, in the log and on the user's terminal.
#[derive(Debug, Clone)]
pub(crate) struct ExitReason {
    /// `hakoniwa`'s portable code: the inner process's own status when it
    /// exited normally, or `125` when the container itself failed or was
    /// signalled.
    pub(crate) code: i32,
    /// `Some(status)` when the inner process exited on its own, `None` when it
    /// was signalled or the container failed out from under it — the
    /// discriminator behind [`Self::is_abnormal`].
    pub(crate) exit_code: Option<i32>,
    /// `hakoniwa`'s human account, e.g. `container received signal SIGKILL` or
    /// `process(/usr/bin/bash) exited with code 0`. Shown to the user verbatim
    /// when the end was abnormal.
    pub(crate) reason: String,
}

impl ExitReason {
    /// Whether the process failed to exit under its own control — signalled,
    /// or the container failed. Exactly `hakoniwa`'s `exit_code: None`, which
    /// it sets both on its `received signal` path and on the `new_failure`
    /// path behind a container-level SIGKILL.
    pub(crate) fn is_abnormal(&self) -> bool {
        self.exit_code.is_none()
    }
}

/// A handle to a launched session process.
///
/// Abstracts the process the [`Host`] supervises so its runtime loop can be
/// driven against a real sandboxed process or a test double. `try_wait` and
/// `wait` reduce the `hakoniwa::ExitStatus` payload to a portable exit code;
/// [`Self::exit_reason`] carries the part of it that has to reach the user.
pub(crate) trait BoxProcess: Send + 'static {
    /// Returns the PID of hakoniwa's container supervisor — **not** the PID of
    /// the shell it exec'd.
    ///
    /// The supervisor unshared the sandbox's namespaces itself, so this is a
    /// valid handle for all of them except the PID namespace, which it created
    /// for its children without entering. Use
    /// [`Host::session_leader_pid`](Host::session_leader_pid) for the shell's
    /// own PID; see [`crate::nsenter`] for why the distinction matters.
    fn container_pid(&self) -> u32;
    /// Returns `Some(code)` if the process has exited, `None` if still running.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    /// Blocks until the process exits, returning its exit code.
    fn wait(&mut self) -> io::Result<i32>;
    /// Sends a kill signal to the process.
    fn kill(&mut self) -> io::Result<()>;
    /// `hakoniwa`'s account of how the process ended, available once
    /// [`Self::try_wait`] has returned `Some` or [`Self::wait`] has returned.
    ///
    /// `None` until the reap; [`HostProcess`] caches the reason at that point
    /// and answers from it thereafter.
    fn exit_reason(&self) -> Option<ExitReason>;
}

/// A backend's answer to a reap: the portable code a [`BoxProcess`] reduces
/// the child's status to, plus the account to cache for
/// [`BoxProcess::exit_reason`].
pub(crate) struct ExitReport {
    /// The code `wait`/`try_wait` returns.
    pub(super) code: i32,
    /// The account cached on the first reap.
    pub(super) reason: ExitReason,
}

/// The process-creation backend behind [`HostProcess`]: the one part of a
/// [`BoxProcess`] that differs between the real sandboxed child and the
/// test double. Everything else — the exit-reason cache and its record-once
/// policy — lives in [`HostProcess`] and is shared.
pub(crate) trait ProcessBackend: Send + 'static {
    /// See [`BoxProcess::container_pid`].
    fn container_pid(&self) -> u32;
    /// See [`BoxProcess::try_wait`]; `Ok(None)` while the process runs.
    fn try_wait(&mut self) -> io::Result<Option<ExitReport>>;
    /// See [`BoxProcess::wait`].
    fn wait(&mut self) -> io::Result<ExitReport>;
    /// See [`BoxProcess::kill`].
    fn kill(&mut self) -> io::Result<()>;
    /// Logs the backend's account of an observed exit. Called exactly once per
    /// session by [`HostProcess::record_exit`]; the default is silent, so a
    /// backend with nothing to say (the mock) need not implement it.
    fn log_exit(_reason: &ExitReason) {}
}

/// The single [`BoxProcess`] implementation, generic over the backend that
/// owns the actual child. Holds the exit reason cached at the first reap, so
/// [`BoxProcess::exit_reason`] can answer after the fact for both the real
/// sandboxed child and the test double.
pub(crate) struct HostProcess<B: ProcessBackend> {
    backend: B,
    /// The reason captured at the reap; `None` until then.
    exit: Option<ExitReason>,
}

impl<B: ProcessBackend> HostProcess<B> {
    pub(super) fn new(backend: B) -> Self {
        Self {
            backend,
            exit: None,
        }
    }

    /// Logs the backend's account of an observed exit and caches it for
    /// [`BoxProcess::exit_reason`], returning the portable code.
    ///
    /// Caches and logs on the first reap only, not on every subsequent one: the
    /// child caches its own status, so a `wait` following a `try_wait` that
    /// already saw the death would otherwise log the same end twice.
    fn record_exit(&mut self, report: ExitReport) -> i32 {
        if self.exit.is_none() {
            B::log_exit(&report.reason);
            self.exit = Some(report.reason);
        }
        report.code
    }
}

impl<B: ProcessBackend> BoxProcess for HostProcess<B> {
    fn container_pid(&self) -> u32 {
        self.backend.container_pid()
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        let report = self.backend.try_wait()?;
        Ok(report.map(|r| self.record_exit(r)))
    }

    fn wait(&mut self) -> io::Result<i32> {
        let report = self.backend.wait()?;
        Ok(self.record_exit(report))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.backend.kill()
    }

    fn exit_reason(&self) -> Option<ExitReason> {
        self.exit.clone()
    }
}

/// The real sandboxed child backend: a [`hakoniwa::Child`].
pub(crate) struct SandboxBackend {
    pub(super) child: hakoniwa::Child,
    /// The box's classifier leaf (NET-079), removed when this backend — and
    /// so the session's last process — is dropped: a leaf does not outlive the
    /// box it decided.
    pub(super) leaf: Option<sandbox::config::ClassifierLeaf>,
}

impl SandboxBackend {
    /// Reduces `hakoniwa`'s account of an exit to the shared [`ExitReport`].
    fn report(s: hakoniwa::ExitStatus) -> ExitReport {
        ExitReport {
            code: s.code,
            reason: ExitReason {
                code: s.code,
                exit_code: s.exit_code,
                reason: s.reason,
            },
        }
    }
}

impl ProcessBackend for SandboxBackend {
    fn container_pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        let status = self
            .child
            .try_wait()
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))?;
        Ok(status.map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        // The blocking reap the pty/step error path takes — in practice the
        // one that fires, since the master's `EIO` beats the loop's `try_wait`
        // poll to every ordinary exit.
        let s = self
            .child
            .wait()
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))?;
        Ok(Self::report(s))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child
            .kill()
            .map_err(|e| io::Error::other(format!("kill failed: {e}")))
    }

    /// Logs on every exit, not just the non-zero ones, exactly once per session
    /// (gated by [`HostProcess::record_exit`]'s cache): `hakoniwa` caches the
    /// status, so a `wait` following a `try_wait` that already saw it would
    /// otherwise log the same death twice.
    fn log_exit(reason: &ExitReason) {
        if reason.code != 0 {
            tracing::warn!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "DIAG hakoniwa container/process exited non-zero"
            );
        } else {
            tracing::info!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "hakoniwa container/process exited"
            );
        }
    }
}

impl Drop for SandboxBackend {
    /// Tears the box down and removes its leaf (NET-079): a leaf does not
    /// outlive the box it decided, and a [`hakoniwa::Child`] does not
    /// terminate when dropped — without the kill, dropping a host that never
    /// reaped its process would both orphan the sandbox and leave a leaf in
    /// the tree with a process still in it.
    ///
    /// In the ordinary paths both are no-ops: `mainloop` reaps the process
    /// before it returns (even on a kill — the loop's `wait()` at the
    /// bottom), and `hakoniwa` caches the status so `wait` after a reap
    /// returns it instead of blocking. The kill+wait here is for the paths
    /// that skip all of that — an aborted loop future, most notably — where
    /// SIGKILL is the bounded way out.
    fn drop(&mut self) {
        let Some(leaf) = self.leaf.take() else {
            return;
        };
        // `kill` and `wait` are independent: a process that already exited
        // fails the kill with `ESRCH` but still needs reaping.
        if let Err(e) = self.child.kill() {
            tracing::warn!(error = %e, "killing session process at teardown");
        }
        if let Err(e) = self.child.wait() {
            tracing::warn!(error = %e, "reaping session process at teardown");
        }
        // The leaf goes last, once nothing is in it — and outlasting the
        // box's last moments, because a SIGKILLed box's cgroup can refuse
        // its `rmdir` (`EBUSY`) for a few milliseconds after the reap while
        // the kernel empties it. A refusal at the first try would leak the
        // leaf until a later launch of the same session id reclaimed it or
        // the daemon restarted, so the removal is retried briefly before it
        // is warned about; a leaf that still refuses is a warn and an empty
        // directory — named by its session's id, so no later session can be
        // launched into it, and swept away at the next daemon start.
        if let Err(e) = remove_box_leaf_patiently(leaf.dir(), DROP_LEAF_REMOVAL_ATTEMPTS, |_| {
            std::thread::sleep(DROP_LEAF_REMOVAL_PAUSE)
        }) {
            tracing::warn!(
                leaf = %leaf.dir().display(),
                error = %e,
                "removing the session's classifier leaf"
            );
        }
    }
}

/// How many times a teardown tries to remove the box's leaf before warning
/// about a leak. One first try plus four retries.
pub(super) const DROP_LEAF_REMOVAL_ATTEMPTS: usize = 5;

/// The pause between those tries: long enough for the kernel to finish
/// emptying a just-killed cgroup, short enough that a wedged teardown never
/// parks on it — 4 × 20 ms after the first refusal.
pub(super) const DROP_LEAF_REMOVAL_PAUSE: std::time::Duration =
    std::time::Duration::from_millis(20);

/// Removes the box's leaf, retrying while a just-reaped box's cgroup may
/// still be dying: the `rmdir` of a cgroup the kernel has not finished
/// emptying comes back `EBUSY` for a few milliseconds after the last
/// process is reaped, and the removal is owed once — not indefinitely, so
/// the attempts are counted and the last refusal is returned for the caller
/// to warn.
///
/// `pause` is called with the number of the attempt that just failed —
/// before the next try — and is the seam the test drives: production sleeps
/// [`DROP_LEAF_REMOVAL_PAUSE`], a test clears the obstruction between two
/// attempts and proves the retry is what healed the removal.
pub(super) fn remove_box_leaf_patiently(
    leaf: &std::path::Path,
    attempts: usize,
    mut pause: impl FnMut(usize),
) -> io::Result<()> {
    let attempts = attempts.max(1);
    for attempt in 1..attempts {
        if sandbox::classifier::remove_box_leaf(leaf).is_ok() {
            return Ok(());
        }
        pause(attempt);
    }
    // The last attempt is the return, not another pause: its refusal is
    // what the caller warns with.
    sandbox::classifier::remove_box_leaf(leaf)
}

/// A launched session process backed by a sandboxed [`hakoniwa::Child`].
pub(crate) type SandboxProcess = HostProcess<SandboxBackend>;
