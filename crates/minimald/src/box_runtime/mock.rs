//! Test doubles for the process backend and the launcher.

use super::*;

/// The test backend: a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) struct MockBackend {
    pub(super) child: std::process::Child,
}

#[cfg(test)]
impl MockBackend {
    /// Translates a plain process status into the shape `hakoniwa` reports, so
    /// the host cannot tell a mock reap from a sandboxed one: a signalled
    /// process has no exit code of its own and carries the container's 125.
    ///
    /// The report's `code` is unchanged from what this mock always returned, so
    /// the reap value every existing test asserts on is untouched.
    fn report(s: std::process::ExitStatus) -> ExitReport {
        use std::os::unix::process::ExitStatusExt;
        let code = s.code().unwrap_or(-1);
        let reason = match s.signal() {
            Some(sig) => ExitReason {
                code: 125,
                exit_code: None,
                reason: format!("process(mock) received signal {sig}"),
            },
            None => ExitReason {
                code,
                exit_code: Some(code),
                reason: format!("process(mock) exited with code {code}"),
            },
        };
        ExitReport { code, reason }
    }
}

#[cfg(test)]
impl ProcessBackend for MockBackend {
    fn container_pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        let status = self.child.try_wait()?;
        Ok(status.map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        let s = self.child.wait()?;
        Ok(Self::report(s))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

/// A launched session process backed by a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) type MockProcess = HostProcess<MockBackend>;

/// The sentinel stdin line that makes [`MockLauncher`]'s program exit; any
/// other line is echoed back. Lets a test observe an echo round trip while the
/// process is still alive, then trigger teardown deterministically.
#[cfg(test)]
pub(crate) const MOCK_EXIT_LINE: &str = "quit";

/// A test [`BoxLauncher`] that wires a plain, un-sandboxed host process to a
/// freshly opened PTY — so the [`Host`] runtime can be exercised end-to-end
/// without building a real sandbox (which needs packages unavailable in the
/// unit-test environment).
///
/// The launched program echoes each line of stdin back prefixed with `got:`,
/// and exits only on the [`MOCK_EXIT_LINE`] sentinel — so a test can confirm
/// stdin delivery and stdout forwarding before deterministically triggering
/// process-exit teardown.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockLauncher {
    /// Attached to the launched process as `Launched::net_guard`, so a test can
    /// observe network teardown; `None` for the plain mock (mirroring
    /// `HostNet`/`NoNet`).
    net_guard: Option<Box<dyn sandbox::NetGuard>>,
    /// The placement outcome this mock launch reports (NET-079): seeded by
    /// the session's test launcher from the daemon's one node fact —
    /// `per_box` when the fact's cause says the tree is there to place a
    /// leaf in (`fact_places_a_leaf`), `none` when it does not — so a test
    /// that injects a classifier reading and re-reads the fact has the
    /// launches it drives record each box's own placement outcome over it.
    /// The mock has no sandbox, so it places nothing and models the
    /// placement's outcome; the real launcher's placement-to-record mapping
    /// is pinned where it is written, in this module's launch proofs.
    host_ip_enforcement: Option<HostIpEnforcement>,
    /// The listen plan this mock launch carries in its [`Launched`], so a
    /// test can drive the host's listener watcher over the mock box the way
    /// a real launch drives one over a sandboxed box — and, left `None`,
    /// prove a launch that carries no plan starts no watcher at all.
    listen_plan: Option<crate::net::listeners::ListenPlan>,
}

#[cfg(test)]
impl MockLauncher {
    /// A mock that attaches `net_guard`, for the network-teardown tests.
    pub(crate) fn with_net_guard(net_guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            net_guard: Some(net_guard),
            host_ip_enforcement: None,
            listen_plan: None,
        }
    }

    /// A mock whose launch carries `host_ip_enforcement` as its placement
    /// outcome — the value the session's test launcher seeds from the
    /// daemon's node fact, so a test's launches record each box's own
    /// outcome over the fact a test's injected reading set.
    pub(crate) fn with_host_ip_enforcement(host_ip_enforcement: HostIpEnforcement) -> Self {
        Self {
            host_ip_enforcement: Some(host_ip_enforcement),
            ..Default::default()
        }
    }

    /// This mock with `net_guard` attached as well, so a test can observe
    /// the teardown of a host-address box's launch.
    pub(crate) fn and_net_guard(self, net_guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            net_guard: Some(net_guard),
            ..self
        }
    }

    /// This mock with `listen_plan` attached, so a test can drive a box's
    /// listener watcher under whatever else its launch mirrors. The mock has
    /// no sandbox and no network namespace of its own, so the watcher
    /// resolves the box's leader as the sole child its shell runs — the
    /// shape a real container's supervisor gives the resolution — and the
    /// leader's socket table is the daemon's own, where the listening
    /// sockets the test binds in its process are the box's.
    pub(crate) fn and_listen_plan(
        mut self,
        listen_plan: crate::net::listeners::ListenPlan,
    ) -> Self {
        self.listen_plan = Some(listen_plan);
        self
    }
}

#[cfg(test)]
impl BoxLauncher for MockLauncher {
    type Process = MockProcess;
    type Guard = ();

    async fn launch(
        self,
        _guest: bool,
        _session_id: boxes::SessionId,
        _name: String,
        _username: String,
        _paths: BoxPaths,
        sz: WinSize,
    ) -> io::Result<Launched<MockProcess, ()>> {
        let pty = Pty::open(sz)?;

        // A launch that carries a listen plan starts a watcher that
        // resolves its box's leader, and a mock box's leader is the sole
        // child of its shell — so the script runs one (`sleep`, doing
        // nothing but holding the shape) beside its echo loop. The child
        // is never a job-control one — the mock's shell is not interactive
        // — so it reads no tty and touches no foreground rights.
        let leader_child = if self.listen_plan.is_some() {
            "sleep 60 & "
        } else {
            ""
        };
        let script = format!(
            r#"{leader_child}while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(&script);
        command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
        let tty_path = pty.slave_path().to_path_buf();
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));

        let process = command.spawn()?;

        Ok(Launched {
            master,
            process: MockProcess::new(MockBackend { child: process }),
            guard: (),
            net_guard: self.net_guard,
            tty_path,
            seal_injection: false,
            // The mock has no sandbox, so no classifier placed it anywhere.
            leaf: None,
            host_ip_enforcement: self.host_ip_enforcement,
            // The plan the launch gathered, riding to the host the way a
            // real launch's plan rides: taken when the host builds.
            listen_plan: self.listen_plan,
            // The mock's process is a plain host child with no pre-exec
            // closure to hold it.
            start_gate: None,
        })
    }
}
