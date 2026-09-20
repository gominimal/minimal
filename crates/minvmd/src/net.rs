//! Per-host gvproxy switch supervision and per-PTask switch attachment for
//! `minvmd` (R1.4, R1.5, R1.8).
//!
//! On DM1/DM3/DM4 a libkrun VM runs `minimald`; `minvmd` supervises exactly one
//! gvproxy process per host VM ([`GvproxySupervisor`]) that serves every own-IP
//! PTask as a switch client. `minvmd` owns the gvproxy **process** lifecycle
//! only; the in-guest `minimald` performs the per-PTask attach (R1.5) — a tap in
//! the PTask netns plus an async TAP↔gvproxy relay over the vsock shuttle — and
//! assigns IPs from the switch subnet. The host switch starts with an empty
//! `dhcpStaticLeases` table; the guest assigns PTask IPs statically.
//!
//! The gvproxy v0.8.9 spike (`docs/spikes/2026-06-21-gvproxy-attachment.md`)
//! established that the attachment is **not** an SCM_RIGHTS fd-pass but a bare
//! `POST /connect` HTTP upgrade on gvproxy's control socket followed by raw
//! Ethernet frames framed with a 2-byte little-endian length prefix (the
//! HyperKit protocol). `minvmd`'s role is to write the gvproxy `-config` YAML
//! carrying the subnet, gateway, NAT alias, and `dhcpStaticLeases`
//! ([`render_gvproxy_config`]) — the subnet is YAML-only (gvproxy v0.8.9 has no
//! `-subnet` CLI flag). Opening the per-PTask tap and running the TAP↔gvproxy
//! relay happen in the guest `minimald` over the vsock shuttle (see the
//! `shuttle` module); this module owns only the switch process.
//!
//! The supervisor tears gvproxy down with the same SIGTERM → timeout → SIGKILL
//! sequence the vmm child uses ([`GvproxySupervisor::stop`], R1.4) and runs a
//! background tokio task that detects an unexpected gvproxy exit, emits a
//! `tracing::error!`, and fires the [`SwitchExit`] notification returned from
//! [`GvproxyConfig::spawn`] (R1.4 detection half). Every switch lifecycle event
//! — spawn, stop, attach (with assigned IP), detach — is emitted as a structured
//! `tracing` event (R1.8). This module contains no `println!`/`eprintln!`.
//!
//! Supervision is async: [`GvproxyConfig::spawn`] and [`GvproxySupervisor::stop`]
//! run within a tokio runtime (the async networking layer the spec mandates),
//! so neither blocks a worker thread during teardown.
//!
//! The switch is not the only host process the VM's network needs. The box
//! egress proxy ([`HostBep`], BEP-015) stands **beside** gvproxy, supervised the
//! same way and for the same lifetime: gvproxy carries a box's ordinary egress,
//! the proxy terminates its declared credentialed hosts so `git` and `gh` inside
//! a box reach GitHub with only the sealed value the box was created with. It is
//! a separate process with its own binary, listener and log lines — the two
//! never share state (spec 24, BEP-047).

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use minimald_rpc::IpProto;
// gvproxy-switch primitives live in the shared `switch` crate. Re-exported so
// `minvmd::net::{SwitchSubnet, MacAddr, …}` keeps working.
pub use switch::{DEFAULT_MTU, MacAddr, SwitchSubnet, render_gvproxy_config};
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

mod shuttle;
pub use shuttle::{VSOCK_GVPROXY_SHUTTLE_PORT, resolve_switch_sock};

/// Default time to wait for gvproxy to exit on SIGTERM before escalating to
/// SIGKILL.
pub const DEFAULT_TERM_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for gvproxy to bind its `-listen` switch socket after spawn
/// before reporting the host switch ready (or failing the bring-up).
const SWITCH_SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the background datapath probe dials the switch's `-listen`
/// socket to confirm it is still accepting connections (NET-023). Well under
/// the one-minute warning bound the requirement sets, so a lost datapath is
/// always caught with room to spare.
const DATAPATH_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Poll-connect `sock` until gvproxy's `-listen` socket accepts a connection or
/// `timeout` elapses. A gvproxy that exits during startup never binds the
/// socket, so a timeout here means the switch is not usable — surfaced as an
/// error rather than reporting a dead switch as ready.
async fn wait_for_switch_socket(sock: &Path, timeout: Duration) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::UnixStream::connect(sock).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "gvproxy switch socket {} did not appear within {timeout:?}: {e}",
                        sock.display()
                    ),
                ));
            }
        }
    }
}

/// Background task (NET-023): every `interval`, dial `switch_socket` to check
/// the switch is still accepting connections. Warns only on the
/// healthy→unreachable transition — a switch that stays down after the first
/// warning does not re-warn every tick — and stops probing once `stopping` is
/// set, since an intentional teardown legitimately takes the socket away.
///
/// `interval` sits well under NET-023's one-minute bound
/// ([`DATAPATH_PROBE_INTERVAL`] in production), so the switch being killed out
/// from under a running VM is always caught with room to spare.
///
/// This covers the socket-level loss (gvproxy hung or the socket gone without
/// the process exiting); [`HostGvproxy::spawn`]'s unexpected-exit path calls
/// [`warn_datapath_lost`] directly for the process-exited case, since that
/// path tears the supervisor down (aborting this probe) within milliseconds —
/// long before the next tick here would fire.
async fn probe_datapath(switch_socket: PathBuf, interval: Duration, stopping: Arc<AtomicBool>) {
    let mut healthy = true;
    loop {
        tokio::time::sleep(interval).await;
        if stopping.load(Ordering::Acquire) {
            return;
        }
        let reachable = tokio::net::UnixStream::connect(&switch_socket)
            .await
            .is_ok();
        if healthy && !reachable {
            warn_datapath_lost(&switch_socket);
        }
        healthy = reachable;
    }
}

/// Emit the NET-023 "datapath lost" warning naming `switch_socket`. Shared by
/// [`probe_datapath`]'s periodic check and [`HostGvproxy::spawn`]'s
/// unexpected-exit path.
fn warn_datapath_lost(switch_socket: &Path) {
    tracing::warn!(
        switch_socket = %switch_socket.display(),
        "gvproxy switch datapath lost",
    );
}

/// Builder for the per-host gvproxy switch process.
#[derive(Debug, Clone)]
pub struct GvproxyConfig {
    /// Path to the gvproxy binary (vendored/built per Unit 1; see #495).
    binary: PathBuf,
    /// Unix socket gvproxy listens on for switch-client attachment.
    switch_socket: PathBuf,
    /// Path the `-config` YAML is written to before spawn.
    config_path: PathBuf,
    /// Subnet the switch assigns to own-IP PTasks.
    subnet: SwitchSubnet,
    /// Grace period before SIGTERM escalates to SIGKILL on teardown.
    term_timeout: Duration,
}

impl GvproxyConfig {
    /// Construct a config for the gvproxy `binary` listening on `switch_socket`.
    ///
    /// The `-config` YAML defaults to `gvproxy.yaml` alongside `switch_socket`;
    /// override it with [`with_config_path`](Self::with_config_path).
    #[must_use]
    pub fn new(binary: PathBuf, switch_socket: PathBuf) -> Self {
        let config_path = switch_socket
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("gvproxy.yaml");
        Self {
            binary,
            switch_socket,
            config_path,
            subnet: SwitchSubnet::default(),
            term_timeout: DEFAULT_TERM_TIMEOUT,
        }
    }

    /// Override the path the gvproxy `-config` YAML is written to.
    #[must_use]
    pub fn with_config_path(mut self, config_path: PathBuf) -> Self {
        self.config_path = config_path;
        self
    }

    /// Override the switch subnet (default `100.64.0.0/16`).
    #[must_use]
    pub fn with_subnet(mut self, subnet: SwitchSubnet) -> Self {
        self.subnet = subnet;
        self
    }

    /// Override the SIGTERM grace period (default [`DEFAULT_TERM_TIMEOUT`]).
    #[must_use]
    pub fn with_term_timeout(mut self, term_timeout: Duration) -> Self {
        self.term_timeout = term_timeout;
        self
    }

    /// The path the `-config` YAML is written to.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// The argument vector passed to the gvproxy binary: it reads the subnet +
    /// static leases from the `-config` YAML and listens on the switch socket
    /// for client attachment.
    ///
    /// `-ssh-port -1` disables gvproxy's default `127.0.0.1:2222 → :22` forward,
    /// which targets an address that does not exist on our custom subnet.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        vec![
            "-config".to_string(),
            self.config_path.display().to_string(),
            "-listen".to_string(),
            format!("unix://{}", self.switch_socket.display()),
            "-ssh-port".to_string(),
            "-1".to_string(),
        ]
    }

    /// Write the gvproxy `-config` YAML for the configured subnet with the given
    /// static `leases`, creating the parent directory if needed.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the parent directory or the file cannot be
    /// written.
    pub fn write_config(&self, leases: &[(Ipv4Addr, MacAddr)]) -> io::Result<()> {
        if let Some(dir) = self.config_path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(
            &self.config_path,
            render_gvproxy_config(self.subnet, leases),
        )
    }

    /// Spawn and begin supervising the gvproxy switch process (R1.4), returning
    /// the switch handle and a [`SwitchExit`] that fires if gvproxy exits
    /// unexpectedly.
    ///
    /// The `-config` YAML is (re)written from `leases` before spawn so gvproxy's
    /// static-lease table matches the caller's address book. Pass `&[]` to start
    /// with an empty lease map (leases seed only at spawn time).
    ///
    /// Must be called within a tokio runtime: a background supervision task is
    /// spawned to await the child and detect an unexpected exit.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the config cannot be written or the gvproxy
    /// binary cannot be launched.
    pub fn spawn(
        self,
        leases: &[(Ipv4Addr, MacAddr)],
    ) -> io::Result<(GvproxySupervisor, SwitchExit)> {
        self.write_config(leases)?;
        let child = Command::new(&self.binary).args(self.argv()).spawn()?;
        let (switch, exit) =
            GvproxySupervisor::supervise(child, self.term_timeout, self.switch_socket)?;
        tracing::info!(
            pid = switch.pid(),
            binary = %self.binary.display(),
            switch_socket = %switch.switch_socket().display(),
            config = %self.config_path.display(),
            "gvproxy switch spawned",
        );
        Ok((switch, exit))
    }
}

/// A running, supervised gvproxy switch.
///
/// Call [`stop`](GvproxySupervisor::stop) for an orderly async teardown
/// (SIGTERM → grace → SIGKILL, driven on the tokio timer). Dropping the handle
/// is a best-effort fallback that SIGKILLs the process without blocking; the
/// background supervision task reaps it.
#[derive(Debug)]
pub struct GvproxySupervisor {
    /// PID of the supervised gvproxy process; used for logging. The `Child`
    /// itself is owned by the supervision task, which is the sole reaper.
    pid: u32,
    /// pidfd for the supervised gvproxy process. A pidfd refers to the exact
    /// process instance — `pidfd_send_signal` returns `ESRCH` after the
    /// process exits, never landing on a recycled PID.
    #[cfg(target_os = "linux")]
    pidfd: Arc<OwnedFd>,
    term_timeout: Duration,
    switch_socket: PathBuf,
    /// Set before any intentional teardown so the supervision task classifies
    /// the resulting child exit as a clean stop rather than an unexpected crash.
    stopping: Arc<AtomicBool>,
    /// Handle to the background supervision task; `None` once [`stop`] has
    /// consumed it.
    ///
    /// [`stop`]: GvproxySupervisor::stop
    supervisor: Option<tokio::task::JoinHandle<()>>,
    /// Handle to the background datapath probe (NET-023); `None` once
    /// [`stop`](GvproxySupervisor::stop) has aborted it.
    probe: Option<tokio::task::JoinHandle<()>>,
}

impl GvproxySupervisor {
    /// Adopt an already-spawned gvproxy `child` and start its background
    /// supervision task (R1.4 detection half). Must be called within a tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if `pidfd_open(2)` fails (Linux only).
    pub(crate) fn supervise(
        child: Child,
        term_timeout: Duration,
        switch_socket: PathBuf,
    ) -> io::Result<(Self, SwitchExit)> {
        let pid = child
            .id()
            .expect("a freshly spawned child always has a PID before it is awaited");
        #[cfg(target_os = "linux")]
        let pidfd = {
            // SAFETY: syscall(SYS_pidfd_open, pid, 0) is the pidfd_open(2) syscall:
            // takes a pid_t and flags=0, touches no memory, returns an fd or -1.
            // Opening the pidfd before the supervision task is spawned guarantees
            // the child has not yet been reaped by any reaper.
            let raw = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_open,
                    pid as libc::c_long,
                    0i32 as libc::c_long,
                ) as libc::c_int
            };
            if raw < 0 {
                let err = io::Error::last_os_error();
                // No supervision task exists yet, so dropping `child` would not
                // reap it; kill it explicitly to avoid leaking the gvproxy process.
                let mut child = child;
                let _ = child.start_kill();
                return Err(err);
            }
            // SAFETY: raw is a valid file descriptor just returned by pidfd_open.
            Arc::new(unsafe { OwnedFd::from_raw_fd(raw) })
        };
        let stopping = Arc::new(AtomicBool::new(false));
        let (exit_tx, exit_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervise_switch(child, pid, Arc::clone(&stopping), exit_tx));
        let probe = tokio::spawn(probe_datapath(
            switch_socket.clone(),
            DATAPATH_PROBE_INTERVAL,
            Arc::clone(&stopping),
        ));
        let switch = Self {
            pid,
            #[cfg(target_os = "linux")]
            pidfd,
            term_timeout,
            switch_socket,
            stopping,
            supervisor: Some(supervisor),
            probe: Some(probe),
        };
        Ok((switch, SwitchExit { rx: exit_rx }))
    }

    /// The PID of the supervised gvproxy process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The unix socket gvproxy listens on for switch-client attachment.
    #[must_use]
    pub fn switch_socket(&self) -> &Path {
        &self.switch_socket
    }

    /// Tear the switch down cleanly (R1.4): deliver SIGTERM, wait up to
    /// `term_timeout` for gvproxy to exit, then escalate to SIGKILL.
    ///
    /// The grace period is driven on the tokio timer
    /// ([`tokio::time::timeout`]) against the supervision task, so no thread is
    /// blocked — call this from async context for an orderly shutdown. `Drop`
    /// is only a best-effort, non-blocking fallback.
    pub async fn stop(mut self) {
        // Mark the exit intentional *before* signalling so the supervision task
        // classifies the resulting `wait()` as a clean stop, not a crash. Use
        // `swap` (not `store`) so this is symmetric with the guard on
        // `GvproxySupervisor::Drop`: if a drop already claimed teardown and sent
        // SIGKILL, the child may already be reaped and its PID recycled, so
        // `stop()` must not re-signal `pid` — it only awaits the supervisor for
        // the exit.
        let already_claimed = self.stopping.swap(true, Ordering::AcqRel);
        if let Some(probe) = self.probe.take() {
            probe.abort();
        }
        let Some(mut supervisor) = self.supervisor.take() else {
            // Already stopped.
            return;
        };
        if !already_claimed {
            #[cfg(target_os = "linux")]
            signal_via_pidfd(&self.pidfd, libc::SIGTERM, "SIGTERM");
            #[cfg(not(target_os = "linux"))]
            signal_child(self.pid as libc::pid_t, libc::SIGTERM, "SIGTERM");
        }
        // The supervision task completes once it has reaped the child, so
        // awaiting it (bounded by the grace period) is the exit signal.
        if tokio::time::timeout(self.term_timeout, &mut supervisor)
            .await
            .is_err()
        {
            // Always escalate to SIGKILL on timeout, even when another path
            // already claimed teardown and sent SIGTERM. If the SIGKILL were
            // gated on `!already_claimed`, a gvproxy that ignores SIGTERM would
            // never be killed here and `supervisor.await` below would block
            // daemon shutdown forever. On Linux the fd-based signal targets the
            // exact process instance (ESRCH after exit is benign), so this never
            // lands on a recycled PID — no more dangerous than the SIGTERM
            // already sent.
            #[cfg(target_os = "linux")]
            signal_via_pidfd(&self.pidfd, libc::SIGKILL, "SIGKILL");
            #[cfg(not(target_os = "linux"))]
            signal_child(self.pid as libc::pid_t, libc::SIGKILL, "SIGKILL");
            let _ = supervisor.await;
        }
    }
}

impl Drop for GvproxySupervisor {
    fn drop(&mut self) {
        // `stop()` already consumed the supervisor and tore the switch down.
        let Some(_supervisor) = self.supervisor.take() else {
            return;
        };
        if let Some(probe) = self.probe.take() {
            probe.abort();
        }
        // Fire-and-forget fallback: `Drop` cannot await, so mark the exit
        // intentional and SIGKILL immediately, leaving the detached supervision
        // task to reap the child. No blocking poll runs here (the async
        // `stop()` is the path that waits for a graceful SIGTERM exit).
        //
        // Only SIGKILL if this drop is the first to claim teardown. If `stop()`
        // (or anything else) already flipped `stopping` the child is reaped and
        // its PID may have been recycled, so an unconditional SIGKILL could land
        // on an unrelated process. `swap` makes the claim atomic.
        if !self.stopping.swap(true, Ordering::AcqRel) {
            #[cfg(target_os = "linux")]
            signal_via_pidfd(&self.pidfd, libc::SIGKILL, "SIGKILL");
            #[cfg(not(target_os = "linux"))]
            signal_child(self.pid as libc::pid_t, libc::SIGKILL, "SIGKILL");
            tracing::debug!(
                pid = self.pid,
                "gvproxy switch dropped without stop(); SIGKILL sent, reap deferred to supervisor",
            );
        }
    }
}

/// Notification that the supervised gvproxy switch exited **unexpectedly** —
/// i.e. not via [`GvproxySupervisor::stop`] or `Drop` (R1.4 detection half).
/// Returned from [`GvproxyConfig::spawn`]; await it to react to an unplanned
/// gvproxy death.
///
/// Per #522's scope this carries detection plus the signal only; the consumer
/// that tears down the host's own-IP PTasks on this signal is deferred to #526.
#[derive(Debug)]
#[must_use = "await SwitchExit to learn when the gvproxy switch exits unexpectedly"]
pub struct SwitchExit {
    rx: oneshot::Receiver<ExitStatus>,
}

impl SwitchExit {
    /// Await the unexpected-exit notification. Resolves to `Some(status)` with
    /// the gvproxy [`ExitStatus`] when the switch exits unexpectedly.
    ///
    /// `None` means the notify channel closed without a value, which covers two
    /// cases: an intentional teardown via [`GvproxySupervisor::stop`] or `Drop`, and
    /// the rare supervision failure where `child.wait()` itself errored (no
    /// `ExitStatus` exists to report — that path is logged via `tracing::error!`
    /// in [`supervise_switch`]). A caller that must distinguish the two relies on
    /// whether it requested the teardown.
    pub async fn recv(self) -> Option<ExitStatus> {
        self.rx.await.ok()
    }
}

/// Background supervision task body (R1.4 detection half): await the supervised
/// gvproxy `child` and classify its exit. An intentional teardown sets
/// `stopping` before signalling, so a resolved `wait()` with `stopping` set is
/// an orderly stop; otherwise the exit is unexpected — a `tracing::error!` is
/// emitted and `exit_tx` fires so a caller can react. This task is the sole
/// reaper of the child.
async fn supervise_switch(
    mut child: Child,
    pid: u32,
    stopping: Arc<AtomicBool>,
    exit_tx: oneshot::Sender<ExitStatus>,
) {
    match child.wait().await {
        Ok(status) => {
            if stopping.load(Ordering::Acquire) {
                tracing::info!(pid, code = status.code(), "gvproxy switch stopped");
            } else {
                tracing::error!(
                    pid,
                    code = status.code(),
                    "gvproxy switch exited unexpectedly",
                );
                // Receiver may already be dropped; the exit is logged regardless.
                let _ = exit_tx.send(status);
            }
        }
        Err(error) => {
            tracing::error!(pid, %error, "waiting on gvproxy switch failed");
        }
    }
}

/// Deliver `signal` to the process referred to by `pidfd` via
/// `pidfd_send_signal(2)`. A pidfd is bound to the exact process instance
/// opened at spawn, so this call returns `ESRCH` after the process exits
/// rather than accidentally targeting a recycled PID. `ESRCH` is silenced
/// (the process has already exited); other errors are logged via
/// `tracing::warn!`.
#[cfg(target_os = "linux")]
fn signal_via_pidfd(pidfd: &OwnedFd, signal: libc::c_int, signal_name: &str) {
    // SAFETY: syscall(SYS_pidfd_send_signal, pidfd, sig, 0, 0) is the
    // pidfd_send_signal(2) syscall with a null siginfo_t (equivalent to kill(2));
    // it takes machine-word arguments, touches no memory, and returns 0 or -1.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd() as libc::c_long,
            signal as libc::c_long,
            0usize as libc::c_long, // null siginfo_t pointer
            0i32 as libc::c_long,   // flags = 0
        ) as libc::c_int
    };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            tracing::warn!(
                signal = signal_name,
                %error,
                "signal delivery to gvproxy switch failed via pidfd",
            );
        }
    }
}

/// Deliver `signal` to `pid` best-effort, logging any delivery failure other
/// than the benign `ESRCH` (the process has already exited — the expected race
/// during teardown). The result is intentionally not propagated: teardown
/// cannot recover from a failed signal, but an unexpected errno (e.g. `EPERM`,
/// `EINVAL`) should be visible in the logs rather than silently swallowed.
#[cfg(not(target_os = "linux"))]
fn signal_child(pid: libc::pid_t, signal: libc::c_int, signal_name: &str) {
    // SAFETY: `kill(2)` takes a pid and a signal number and touches no memory.
    let rc = unsafe { libc::kill(pid, signal) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            tracing::warn!(
                pid,
                signal = signal_name,
                %error,
                "signal delivery to gvproxy switch failed",
            );
        }
    }
}

/// A host gvproxy switch owned by `minvmd`'s synchronous supervisor, running on
/// its own dedicated current-thread tokio runtime.
///
/// `minvmd`'s `run`/`boot` supervisor is synchronous, but [`GvproxyConfig::spawn`]
/// and [`GvproxySupervisor::stop`] need a tokio runtime (background exit-detection
/// and timer-driven teardown). [`HostGvproxy::spawn`] stands up a single-threaded
/// runtime on a dedicated thread, spawns + supervises gvproxy there, and keeps
/// the runtime alive for the VM's lifetime. [`HostGvproxy::stop`] (or `Drop`)
/// tears gvproxy down and joins the thread.
///
/// The switch is started with an **empty** static-lease table: the guest's
/// per-PTask shuttle configures each PTask's switch IP statically (the spike's
/// static-lease recipe), so `minvmd` does not need to own the per-PTask address
/// book — gvproxy still provides the subnet gateway and the host-loopback NAT
/// alias from the config YAML.
#[derive(Debug)]
#[must_use = "dropping HostGvproxy stops the host gvproxy switch"]
pub struct HostGvproxy {
    /// Channel that tells the runtime thread to stop the switch and exit.
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// The runtime thread; joined on [`stop`](Self::stop) / `Drop`.
    thread: Option<std::thread::JoinHandle<()>>,
    /// PID of the spawned gvproxy, surfaced for logging/diagnostics.
    pid: u32,
}

impl HostGvproxy {
    /// Spawn and supervise the host gvproxy switch on a dedicated runtime.
    ///
    /// `binary` is the gvproxy binary; `switch_sock` is the host `-listen` UNIX
    /// socket libkrun bridges the guest shuttle to (see
    /// [`resolve_switch_sock`]). Blocks only until gvproxy is spawned
    /// and its PID known; supervision continues on the background runtime.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the runtime cannot be built, the config cannot
    /// be written, or the gvproxy binary cannot be launched.
    pub fn spawn(binary: PathBuf, switch_sock: PathBuf) -> io::Result<Self> {
        let config = GvproxyConfig::new(binary, switch_sock);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<u32>>();

        let thread = std::thread::Builder::new()
            .name("minvmd-gvproxy".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                runtime.block_on(async move {
                    // Empty lease table: the guest assigns PTask IPs statically.
                    let (switch, exit) = match config.spawn(&[]) {
                        Ok(pair) => pair,
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                            return;
                        }
                    };
                    let pid = switch.pid();
                    // Wait for gvproxy to bind its `-listen` switch socket before
                    // reporting ready, so a caller never treats a switch that died
                    // during startup (or never bound) as network-ready. A dead
                    // gvproxy never binds, so the timeout surfaces it as an error.
                    let sock = switch.switch_socket().to_path_buf();
                    if let Err(e) = wait_for_switch_socket(&sock, SWITCH_SOCKET_READY_TIMEOUT).await
                    {
                        switch.stop().await;
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                    if ready_tx.send(Ok(pid)).is_err() {
                        // Caller went away before learning the PID; tear down.
                        switch.stop().await;
                        return;
                    }
                    // Wait for either an explicit stop or an unexpected gvproxy
                    // exit, then tear down cleanly.
                    tokio::select! {
                        _ = stop_rx => {
                            switch.stop().await;
                        }
                        status = exit.recv() => {
                            tracing::error!(
                                pid,
                                code = status.and_then(|s| s.code()),
                                "host gvproxy switch exited unexpectedly",
                            );
                            // The process is gone, so the datapath is
                            // definitely lost (NET-023) — warn here rather
                            // than relying on probe_datapath's next tick,
                            // which dropping `switch` below aborts within
                            // milliseconds, long before that tick would fire.
                            warn_datapath_lost(switch.switch_socket());
                            // gvproxy is already gone; drop the handle (no signal).
                            drop(switch);
                        }
                    }
                });
            })?;

        match ready_rx.recv() {
            Ok(Ok(pid)) => Ok(Self {
                stop_tx: Some(stop_tx),
                thread: Some(thread),
                pid,
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            // The runtime thread panicked before reporting; surface a clear error.
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "host gvproxy supervisor thread exited before reporting readiness",
                ))
            }
        }
    }

    /// The PID of the supervised gvproxy process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Stop the switch and join the supervising runtime thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            // A failed send means the runtime thread already exited (e.g. gvproxy
            // crashed); nothing more to signal.
            let _ = stop_tx.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!(pid = self.pid, "host gvproxy supervisor thread panicked");
        }
    }
}

impl Drop for HostGvproxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// VM-wide egress policy stub (R2.5 / Unit 2), aligned with the per-PTask egress
/// types: a VM may restrict all of its traffic to the listed subnets, DNS
/// hosts, and protocols. An empty policy ([`VmEgressPolicy::allow_all`]) imposes
/// no restriction (absent egress defaults to allow-all). Enforcement lands in
/// Unit 2; this type fixes the wire shape `minvmd` will configure on gvproxy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmEgressPolicy {
    allow_subnets: Vec<String>,
    allow_dns_hosts: Vec<String>,
    allow_protocols: Vec<IpProto>,
}

impl VmEgressPolicy {
    /// An empty allow-all policy (no egress restriction).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Restrict egress to the given CIDR subnets.
    #[must_use]
    pub fn with_subnets(mut self, subnets: impl IntoIterator<Item = String>) -> Self {
        self.allow_subnets = subnets.into_iter().collect();
        self
    }

    /// Restrict egress to the given DNS hostnames.
    #[must_use]
    pub fn with_dns_hosts(mut self, hosts: impl IntoIterator<Item = String>) -> Self {
        self.allow_dns_hosts = hosts.into_iter().collect();
        self
    }

    /// Restrict egress to the given IP protocols.
    #[must_use]
    pub fn with_protocols(mut self, protocols: impl IntoIterator<Item = IpProto>) -> Self {
        self.allow_protocols = protocols.into_iter().collect();
        self
    }

    /// Whether this policy imposes no restriction (every field empty).
    #[must_use]
    pub fn is_allow_all(&self) -> bool {
        self.allow_subnets.is_empty()
            && self.allow_dns_hosts.is_empty()
            && self.allow_protocols.is_empty()
    }

    /// The allowed egress subnets.
    #[must_use]
    pub fn allow_subnets(&self) -> &[String] {
        &self.allow_subnets
    }

    /// The allowed egress DNS hostnames.
    #[must_use]
    pub fn allow_dns_hosts(&self) -> &[String] {
        &self.allow_dns_hosts
    }

    /// The allowed egress protocols.
    #[must_use]
    pub fn allow_protocols(&self) -> &[IpProto] {
        &self.allow_protocols
    }
}

// ── The host box egress proxy (BEP-015) ─────────────────────────────────────

/// The loopback port the box egress proxy's redemption listener binds. A box
/// created under `proxy_env` steering gets `HTTPS_PROXY` pointing here
/// (`sessions::BEP_PROXY_URL`), so the two definitions must agree — the tests
/// assert they do.
pub const DEFAULT_BEP_PORT: u16 = 7655;

/// The directory the proxy keeps its files in, under the minimal state dir:
/// the same `bep/` the `min` CLI reads the control socket and the published
/// interception root from, so the host's two sides cannot drift on where the
/// proxy's state lives.
pub const BEP_DIR: &str = "bep";

/// The audit log the proxy appends every decision to, inside [`BEP_DIR`].
pub const BEP_AUDIT_LOG_FILE: &str = "audit.log";

/// The box attachments the proxy attributes a connection's source address with,
/// inside [`BEP_DIR`]. Box creation owns the contents; the supervisor only
/// guarantees the file exists, because the proxy reads it at startup and will
/// not run without one.
pub const BEP_BOXES_FILE: &str = "boxes.json";

/// The proxy binary's file name, as an install places it.
const BEP_FILE: &str = "bep";

/// System-wide install path for the proxy binary: the last resort when no
/// override is set and no user-local install exists.
const DEFAULT_BEP_BIN: &str = "/usr/lib/minimal/bin/bep";

/// How long to wait for the proxy to answer on its redemption listener after
/// spawn before reporting it ready (or failing the bring-up).
const BEP_LISTENER_READY_TIMEOUT: Duration = Duration::from_secs(5);

/// `<state base>/bep`: where the proxy keeps its audit log and attachments,
/// beside the control socket and published root the `min` CLI already uses.
#[must_use]
pub fn resolve_bep_dir() -> PathBuf {
    crate::state::state_base_dir()
        .as_utf8_path()
        .as_std_path()
        .join(BEP_DIR)
}

/// Resolve the box egress proxy binary: the `MINVMD_BEP_BIN` override, then the
/// user-local install the curl|sh installer stamps (`$MINIMAL_BIN`, else
/// `$HOME/.local/bin`), else [`DEFAULT_BEP_BIN`].
///
/// Like [`crate::image::resolve_gvproxy_path`] this never errors: a host that
/// runs only boxes declaring no grant needs no proxy, so an absent binary is an
/// ordinary case — the caller warns with the concrete path it probed.
#[must_use]
pub fn resolve_bep_path() -> PathBuf {
    bep_binary_from(
        std::env::var("MINVMD_BEP_BIN")
            .ok()
            .filter(|v| !v.is_empty()),
        installer_bin_dir(),
        Path::new(DEFAULT_BEP_BIN),
    )
}

/// The user-local bin directory an install stamps into: `$MINIMAL_BIN`, else
/// `$HOME/.local/bin`. Mirrors `scripts/install.sh`'s `bin` prefix, the same
/// resolution `switch` makes for gvproxy (private to that crate).
fn installer_bin_dir() -> Option<PathBuf> {
    if let Some(bin) = std::env::var("MINIMAL_BIN").ok().filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(bin));
    }
    std::env::var("HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".local/bin"))
}

/// The resolution itself, with every probed location passed in so the tiers are
/// testable without mutating the process environment.
fn bep_binary_from(
    override_path: Option<String>,
    bin_dir: Option<PathBuf>,
    system: &Path,
) -> PathBuf {
    if let Some(path) = override_path {
        return PathBuf::from(path);
    }
    if let Some(local) = bin_dir.map(|dir| dir.join(BEP_FILE))
        && local.exists()
    {
        return local;
    }
    system.to_path_buf()
}

/// Builder for the host box-egress-proxy process.
#[derive(Debug, Clone)]
pub struct BepConfig {
    /// Path to the proxy binary.
    binary: PathBuf,
    /// The address the redemption listener binds.
    listen: SocketAddr,
    /// The audit log the proxy appends every decision to.
    audit_log: PathBuf,
    /// The box attachments the proxy attributes connections with.
    boxes: PathBuf,
    /// Grace period before SIGTERM escalates to SIGKILL on teardown.
    term_timeout: Duration,
}

impl BepConfig {
    /// Config for `binary`, keeping its audit log and attachments in `bep_dir`
    /// and binding the default loopback redemption listener.
    #[must_use]
    pub fn new(binary: PathBuf, bep_dir: &Path) -> Self {
        Self {
            binary,
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_BEP_PORT)),
            audit_log: bep_dir.join(BEP_AUDIT_LOG_FILE),
            boxes: bep_dir.join(BEP_BOXES_FILE),
            term_timeout: DEFAULT_TERM_TIMEOUT,
        }
    }

    /// Override the address the redemption listener binds (the tests bind an
    /// ephemeral port so a run never collides with a live proxy).
    #[must_use]
    pub fn with_listen(mut self, listen: SocketAddr) -> Self {
        self.listen = listen;
        self
    }

    /// The address the redemption listener binds.
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// The audit log the proxy appends every decision to.
    #[must_use]
    pub fn audit_log(&self) -> &Path {
        &self.audit_log
    }

    /// The box attachments the proxy attributes connections with.
    #[must_use]
    pub fn boxes(&self) -> &Path {
        &self.boxes
    }

    /// The argument vector passed to the proxy binary. The module host set and
    /// its version are the proxy's own defaults (the GitHub v1 set).
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        vec![
            "--listen".to_string(),
            self.listen.to_string(),
            "--audit-log".to_string(),
            self.audit_log.display().to_string(),
            "--boxes".to_string(),
            self.boxes.display().to_string(),
        ]
    }

    /// Create the proxy's directory and, when it is not there yet, an empty
    /// attachments list — the proxy reads that file at startup and will not run
    /// without one.
    ///
    /// An existing file is never rewritten: its contents are box creation's,
    /// not the supervisor's.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the directory or the attachments file cannot be
    /// written.
    pub fn ensure_files(&self) -> io::Result<()> {
        if let Some(dir) = self.boxes.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if !self.boxes.exists() {
            std::fs::write(&self.boxes, b"[]\n")?;
        }
        Ok(())
    }
}

/// A running, supervised host box egress proxy, on its own dedicated
/// current-thread tokio runtime — the same shape as [`HostGvproxy`], because the
/// proxy stands beside the switch for the VM's whole lifetime.
///
/// [`HostBep::stop`] (or `Drop`) tears the proxy down and joins the thread.
#[derive(Debug)]
#[must_use = "dropping HostBep stops the host box egress proxy"]
pub struct HostBep {
    /// Channel that tells the runtime thread to stop the proxy and exit.
    stop_tx: Option<oneshot::Sender<()>>,
    /// The runtime thread; joined on [`stop`](Self::stop) / `Drop`.
    thread: Option<std::thread::JoinHandle<()>>,
    /// PID of the spawned proxy, surfaced for logging/diagnostics.
    pid: u32,
    /// The address its redemption listener answers on.
    listen: SocketAddr,
}

impl HostBep {
    /// Spawn and supervise the host box egress proxy on a dedicated runtime.
    ///
    /// Blocks until the proxy answers on its redemption listener: a box's
    /// `HTTPS_PROXY` is set at creation, so a proxy that never bound would turn
    /// every credentialed request into a connection refused instead of a
    /// decision. Supervision continues on the background runtime.
    ///
    /// # Errors
    ///
    /// Returns the I/O error if the runtime cannot be built, the proxy's files
    /// cannot be laid down, the binary cannot be launched, or the redemption
    /// listener does not answer within [`BEP_LISTENER_READY_TIMEOUT`].
    pub fn spawn(config: BepConfig) -> io::Result<Self> {
        config.ensure_files()?;
        let listen = config.listen;
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<io::Result<u32>>();

        let thread = std::thread::Builder::new()
            .name("minvmd-bep".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                runtime.block_on(supervise_bep(config, stop_rx, ready_tx));
            })?;

        match ready_rx.recv() {
            Ok(Ok(pid)) => Ok(Self {
                stop_tx: Some(stop_tx),
                thread: Some(thread),
                pid,
                listen,
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            // The runtime thread panicked before reporting; surface a clear error.
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "host box egress proxy supervisor thread exited before reporting readiness",
                ))
            }
        }
    }

    /// The PID of the supervised proxy process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The address the proxy's redemption listener answers on.
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Stop the proxy and join the supervising runtime thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            // A failed send means the runtime thread already exited (e.g. the
            // proxy crashed); nothing more to signal.
            let _ = stop_tx.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::warn!(
                pid = self.pid,
                "host box egress proxy supervisor thread panicked"
            );
        }
    }
}

impl Drop for HostBep {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Bring the host box egress proxy up beside the gvproxy switch, or `None` when
/// this host has no proxy to run (BEP-015).
///
/// Best-effort, exactly like the switch: a host with no proxy binary — or one
/// whose proxy will not come up — still boots, because a box that declares no
/// grant needs neither, and the reason is logged with the path that was probed.
/// `binary` is [`resolve_bep_path`]'s answer, `bep_dir` [`resolve_bep_dir`]'s.
pub fn spawn_host_bep(binary: PathBuf, bep_dir: &Path) -> Option<HostBep> {
    if !binary.exists() {
        tracing::warn!(
            path = %binary.display(),
            "box egress proxy binary not found; booting without the credential lane \
             (set MINVMD_BEP_BIN to enable it)",
        );
        return None;
    }
    match HostBep::spawn(BepConfig::new(binary, bep_dir)) {
        Ok(bep) => {
            tracing::info!(
                pid = bep.pid(),
                listen = %bep.listen(),
                "host box egress proxy up",
            );
            Some(bep)
        }
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to bring up the host box egress proxy; booting without \
                 the credential lane",
            );
            None
        }
    }
}

/// Supervision task body for the host box egress proxy: spawn it, wait for its
/// redemption listener to answer, then wait for either an explicit stop or an
/// unexpected exit. Every transition — spawn, ready, stop, unexpected exit — is
/// one structured `tracing` event naming the listener address and, where there
/// is one, the exit status. This task is the sole reaper of the child.
async fn supervise_bep(
    config: BepConfig,
    stop_rx: oneshot::Receiver<()>,
    ready_tx: std::sync::mpsc::Sender<io::Result<u32>>,
) {
    let mut child = match Command::new(&config.binary).args(config.argv()).spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = ready_tx.send(Err(error));
            return;
        }
    };
    let pid = child
        .id()
        .expect("a freshly spawned child always has a PID before it is awaited");
    tracing::info!(
        pid,
        binary = %config.binary.display(),
        listen = %config.listen,
        audit_log = %config.audit_log.display(),
        boxes = %config.boxes.display(),
        "box egress proxy spawned",
    );

    if let Err(error) = wait_for_bep_listener(config.listen, BEP_LISTENER_READY_TIMEOUT).await {
        stop_bep(&mut child, pid, config.term_timeout).await;
        let _ = ready_tx.send(Err(error));
        return;
    }
    tracing::info!(pid, listen = %config.listen, "box egress proxy ready");
    if ready_tx.send(Ok(pid)).is_err() {
        // Caller went away before learning the PID; tear down.
        stop_bep(&mut child, pid, config.term_timeout).await;
        return;
    }

    // Either an explicit stop or the proxy dying on its own. `child.wait()`
    // borrows the child only for the select, so the teardown below can take it
    // mutably again.
    let stop_requested = tokio::select! {
        _ = stop_rx => true,
        exited = child.wait() => {
            match exited {
                Ok(status) => tracing::error!(
                    pid,
                    listen = %config.listen,
                    code = status.code(),
                    "box egress proxy exited unexpectedly",
                ),
                Err(error) => tracing::error!(
                    pid,
                    %error,
                    "waiting on the box egress proxy failed",
                ),
            }
            false
        }
    };
    if stop_requested {
        stop_bep(&mut child, pid, config.term_timeout).await;
    }
}

/// Tear the proxy down: SIGTERM, wait up to `grace`, then SIGKILL. `child` is
/// unreaped until this returns, so `pid` still names that exact process and a
/// signal cannot land on a recycled PID. The exit is logged with its status.
async fn stop_bep(child: &mut Child, pid: u32, grace: Duration) {
    signal_bep(pid, libc::SIGTERM, "SIGTERM");
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(Ok(status)) => {
            tracing::info!(pid, code = status.code(), "box egress proxy stopped");
        }
        Ok(Err(error)) => {
            tracing::error!(pid, %error, "waiting on the box egress proxy failed");
        }
        Err(_) => {
            tracing::warn!(
                pid,
                "box egress proxy ignored SIGTERM; escalating to SIGKILL"
            );
            match child.kill().await {
                Ok(()) => tracing::info!(pid, "box egress proxy killed"),
                Err(error) => {
                    tracing::error!(pid, %error, "killing the box egress proxy failed");
                }
            }
        }
    }
}

/// Deliver `signal` to the proxy's `pid` best-effort. The `Child` is unreaped
/// while this runs, so the PID names that exact process; `ESRCH` (it exited on
/// its own first) is the benign teardown race and is silenced, while any other
/// errno is logged rather than swallowed.
fn signal_bep(pid: u32, signal: libc::c_int, signal_name: &str) {
    // SAFETY: `kill(2)` takes a pid and a signal number and touches no memory.
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if rc != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            tracing::warn!(
                pid,
                signal = signal_name,
                %error,
                "signal delivery to the box egress proxy failed",
            );
        }
    }
}

/// Poll-connect `listen` until the proxy's redemption listener accepts a
/// connection or `timeout` elapses. A proxy that dies during startup never
/// answers, so a timeout here means the credential lane is not usable —
/// surfaced as an error rather than reporting a dead proxy as ready.
async fn wait_for_bep_listener(listen: SocketAddr, timeout: Duration) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::TcpStream::connect(listen).await {
            Ok(_) => return Ok(()),
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "the box egress proxy's redemption listener {listen} did not answer \
                         within {timeout:?}: {e}"
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` accumulating everything written into a shared buffer, so a
    /// test can assert on a `tracing` event without a real log sink.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn spawn_sleep() -> Child {
        // A long-lived child to stand in for gvproxy in supervision tests.
        Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn sleep")
    }

    fn pid_is_alive(pid: u32) -> bool {
        // signal 0 probes for existence without delivering a signal.
        // SAFETY: kill(pid, 0) touches no memory and only reports liveness.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    /// Path to a stand-in "gvproxy" that stays alive regardless of the argv
    /// [`HostGvproxy::spawn`] hands it (`-config … -listen … -ssh-port -1`).
    ///
    /// A bare `sleep` misparses those flags and exits within ~1 ms, which races
    /// the supervisor's background reaper against the `pid_is_alive` assertions —
    /// a CI flake on slow/contended runners. Real gvproxy runs until signalled,
    /// so the stand-in must too: this script `exec`s a long sleep, ignoring its
    /// arguments, making the liveness and teardown assertions deterministic.
    fn stayalive_gvproxy(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("stayalive-gvproxy.sh");
        std::fs::write(&path, "#!/bin/sh\nexec sleep 1000\n").expect("write stand-in gvproxy");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stand-in gvproxy");
        path
    }

    #[test]
    fn argv_listens_on_switch_socket() {
        let cfg = GvproxyConfig::new(
            PathBuf::from("/usr/bin/gvproxy"),
            PathBuf::from("/run/minvmd/switch.sock"),
        );
        assert_eq!(
            cfg.argv(),
            vec![
                "-config".to_string(),
                "/run/minvmd/gvproxy.yaml".to_string(),
                "-listen".to_string(),
                "unix:///run/minvmd/switch.sock".to_string(),
                "-ssh-port".to_string(),
                "-1".to_string(),
            ]
        );
        assert_eq!(cfg.config_path(), Path::new("/run/minvmd/gvproxy.yaml"));
    }

    #[test]
    fn config_yaml_carries_subnet_gateway_and_leases() {
        let ip = Ipv4Addr::new(100, 64, 0, 2);
        let mac = MacAddr::for_switch_ip(ip);
        let yaml = render_gvproxy_config(SwitchSubnet::default(), &[(ip, mac)]);
        assert!(yaml.contains("subnet: \"100.64.0.0/16\""));
        assert!(yaml.contains("gatewayIP: \"100.64.0.1\""));
        assert!(yaml.contains(&format!("\"{ip}\": \"{mac}\"")));
        // Host alias is NAT'd to loopback and never allocated.
        assert!(yaml.contains("\"100.64.255.254\": \"127.0.0.1\""));
    }

    #[test]
    fn empty_config_still_emits_a_lease_map() {
        let yaml = render_gvproxy_config(SwitchSubnet::default(), &[]);
        assert!(yaml.contains("dhcpStaticLeases:"));
        assert!(yaml.contains("{}"));
    }

    #[test]
    fn write_config_creates_parent_and_file() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let cfg = GvproxyConfig::new(
            PathBuf::from("/usr/bin/gvproxy"),
            dir.path().join("nested/switch.sock"),
        );
        let ip = Ipv4Addr::new(100, 64, 0, 2);
        cfg.write_config(&[(ip, MacAddr::for_switch_ip(ip))])
            .expect("write config");
        let body = std::fs::read_to_string(cfg.config_path()).expect("read config");
        assert!(body.contains("100.64.0.0/16"));
    }

    fn supervise_sleep() -> (GvproxySupervisor, SwitchExit) {
        GvproxySupervisor::supervise(
            spawn_sleep(),
            Duration::from_secs(2),
            PathBuf::from("/run/minvmd/switch.sock"),
        )
        .expect("supervise sleep")
    }

    /// Wait up to ~2 s for `pid` to be reaped, yielding to the supervision task
    /// between probes (the reap is asynchronous).
    async fn await_reaped(pid: u32) -> bool {
        for _ in 0..200 {
            if !pid_is_alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn stop_terminates_supervised_child() {
        let (switch, _exit) = supervise_sleep();
        let pid = switch.pid();
        assert!(pid_is_alive(pid), "child should be alive before stop");

        // SIGTERM on `sleep` is immediate; stop() awaits the supervisor's reap.
        switch.stop().await;
        assert!(!pid_is_alive(pid), "child must be terminated after stop");
    }

    #[tokio::test]
    async fn drop_sigkills_supervised_child_without_blocking() {
        let (switch, _exit) = supervise_sleep();
        let pid = switch.pid();
        assert!(pid_is_alive(pid), "child should be alive before drop");

        // Drop is fire-and-forget: it SIGKILLs immediately and leaves the
        // detached supervision task to reap the child asynchronously.
        drop(switch);
        assert!(
            await_reaped(pid).await,
            "child must be killed and reaped after drop",
        );
    }

    #[tokio::test]
    async fn unexpected_exit_fires_notify() {
        // A child that exits on its own — no stop()/drop — is an unexpected
        // exit: the supervisor emits tracing::error! and fires the notify
        // channel (R1.4 detection half).
        let (switch, exit) = GvproxySupervisor::supervise(
            Command::new("true").spawn().expect("spawn true"),
            Duration::from_secs(2),
            PathBuf::from("/run/minvmd/switch.sock"),
        )
        .expect("supervise true");

        let status = tokio::time::timeout(Duration::from_secs(5), exit.recv())
            .await
            .expect("unexpected-exit notify should fire within 5s");
        assert!(
            status.is_some(),
            "an unexpected exit must deliver an ExitStatus over the notify channel",
        );

        // `switch` is kept alive until after the notify so `stopping` stays
        // false while the supervisor classifies the exit.
        drop(switch);
    }

    /// A pidfd opened before a child is reaped refers to that exact process
    /// instance. After the child exits and is reaped, `pidfd_send_signal` must
    /// return `ESRCH` — never silently land on a recycled PID (R1.4 / G2).
    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_signal_to_reaped_child_returns_esrch() {
        // Spawn a short-lived child; `true` exits with status 0 immediately.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();

        // Open the pidfd before reaping so it is bound to this exact process
        // instance — not the numeric PID that the OS may recycle after reap.
        // SAFETY: syscall(SYS_pidfd_open, pid, 0) touches no memory and returns an fd or -1.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_pidfd_open,
                pid as libc::c_long,
                0i32 as libc::c_long,
            ) as libc::c_int
        };
        assert!(
            raw >= 0,
            "pidfd_open should succeed for a running/zombie child"
        );
        // SAFETY: raw is the valid fd just returned by pidfd_open.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Reap the child; it is now gone from the process table.
        let status = child.wait().expect("wait");
        assert!(status.success(), "true must exit 0");

        // Signal via pidfd after reap must return ESRCH — confirming the
        // pidfd never resolves to a recycled PID.
        // SAFETY: syscall(SYS_pidfd_send_signal, ...) touches no memory; returns 0 or -1.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd() as libc::c_long,
                libc::SIGTERM as libc::c_long,
                0usize as libc::c_long,
                0i32 as libc::c_long,
            ) as libc::c_int
        };
        assert_eq!(rc, -1, "pidfd_send_signal to reaped child must fail");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "errno must be ESRCH — not a recycled-PID hit",
        );
    }

    #[test]
    fn host_gvproxy_spawns_supervises_and_stops() {
        // A stay-alive script stands in for gvproxy: HostGvproxy::spawn only
        // needs a binary it can launch, read a PID from, and later signal. Real
        // gvproxy binds the `-listen` switch socket, which the supervisor now
        // probes for readiness before reporting ready, so bind a stand-in
        // listener here (the script ignores the gvproxy argv it is handed).
        let dir = tempfile::TempDir::new().expect("tempdir");
        let sock = dir.path().join("gvproxy-switch.sock");
        let _switch_listener =
            std::os::unix::net::UnixListener::bind(&sock).expect("bind stand-in switch socket");
        let gvproxy =
            HostGvproxy::spawn(stayalive_gvproxy(dir.path()), sock).expect("spawn host gvproxy");
        let pid = gvproxy.pid();
        assert!(
            pid_is_alive(pid),
            "host gvproxy should be alive after spawn"
        );
        gvproxy.stop();
        // stop() signals SIGTERM and joins the supervising runtime thread, which
        // only returns once gvproxy has been reaped.
        assert!(
            !pid_is_alive(pid),
            "host gvproxy must be stopped after stop()"
        );
    }

    #[test]
    fn host_gvproxy_drop_stops_the_switch() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let sock = dir.path().join("gvproxy-switch.sock");
        let _switch_listener =
            std::os::unix::net::UnixListener::bind(&sock).expect("bind stand-in switch socket");
        let gvproxy =
            HostGvproxy::spawn(stayalive_gvproxy(dir.path()), sock).expect("spawn host gvproxy");
        let pid = gvproxy.pid();
        assert!(pid_is_alive(pid));
        drop(gvproxy);
        assert!(
            !pid_is_alive(pid),
            "dropping HostGvproxy must stop the switch"
        );
    }

    #[test]
    fn host_gvproxy_spawn_reports_launch_failure() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let sock = dir.path().join("gvproxy-switch.sock");
        let err = HostGvproxy::spawn(PathBuf::from("/nonexistent/definitely/not/gvproxy"), sock)
            .expect_err("spawning a missing binary must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// Path to a stand-in "bep" that stays alive regardless of the argv
    /// [`HostBep::spawn`] hands it, for the same reason as
    /// [`stayalive_gvproxy`]: the real proxy runs until signalled, so the
    /// liveness and teardown assertions must not race a stand-in that exits.
    /// Its listener is stood up by the test itself (the script binds nothing),
    /// exactly as the switch-socket stand-in is.
    fn stayalive_bep(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("stayalive-bep.sh");
        std::fs::write(&path, "#!/bin/sh\nexec sleep 1000\n").expect("write stand-in bep");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod stand-in bep");
        path
    }

    /// The host's two network processes are supervised at once and
    /// independently (BEP-015, BEP-047): gvproxy on its `-listen` switch socket
    /// carries a box's ordinary egress, the box egress proxy on its redemption
    /// listener carries its credentialed hosts. The proxy is reported ready only
    /// once that listener answers — which is what makes `git` and `gh` in a box
    /// reach a decision instead of a connection refused — its files are laid
    /// down where the `min` CLI looks for them, and stopping either process
    /// leaves the other running.
    #[test]
    fn bep_proxy_supervised_beside_gvproxy() {
        let dir = tempfile::TempDir::new().expect("tempdir");

        // The switch, as the other supervision tests stand it up.
        let switch_sock = dir.path().join("gvproxy-switch.sock");
        let _switch_listener = std::os::unix::net::UnixListener::bind(&switch_sock)
            .expect("bind stand-in switch socket");
        let gvproxy = HostGvproxy::spawn(stayalive_gvproxy(dir.path()), switch_sock)
            .expect("spawn host gvproxy");

        // The proxy, beside it. An ephemeral port so a run never collides with
        // a live proxy on this host's 7655.
        let proxy_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind stand-in redemption listener");
        let listen = proxy_listener.local_addr().expect("listener address");
        let bep_dir = dir.path().join(BEP_DIR);
        let bep =
            HostBep::spawn(BepConfig::new(stayalive_bep(dir.path()), &bep_dir).with_listen(listen))
                .expect("spawn host box egress proxy");

        let (gvproxy_pid, bep_pid) = (gvproxy.pid(), bep.pid());
        assert_ne!(
            gvproxy_pid, bep_pid,
            "the proxy must be its own process, not the switch",
        );
        assert!(
            pid_is_alive(gvproxy_pid),
            "the switch should be alive beside the proxy",
        );
        assert!(
            pid_is_alive(bep_pid),
            "the proxy should be alive beside the switch",
        );

        // Ready means the redemption listener answers at the address a steered
        // box's HTTPS_PROXY was set to.
        assert_eq!(bep.listen(), listen);
        drop(
            std::net::TcpStream::connect(listen)
                .expect("the proxy's redemption listener must answer once it is reported ready"),
        );
        // The attachments file the proxy reads at startup exists, beside the
        // audit log it appends to.
        assert!(
            bep_dir.join(BEP_BOXES_FILE).is_file(),
            "the proxy cannot start without an attachments file",
        );

        // Independent lifecycles: stopping the proxy leaves the switch up.
        bep.stop();
        assert!(
            !pid_is_alive(bep_pid),
            "the proxy must be stopped after stop()"
        );
        assert!(
            pid_is_alive(gvproxy_pid),
            "stopping the proxy must not disturb the switch",
        );

        gvproxy.stop();
        assert!(
            !pid_is_alive(gvproxy_pid),
            "the switch must be stopped after stop()",
        );
    }

    #[test]
    fn host_bep_drop_stops_the_proxy() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let proxy_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("bind stand-in redemption listener");
        let listen = proxy_listener.local_addr().expect("listener address");
        let bep = HostBep::spawn(
            BepConfig::new(stayalive_bep(dir.path()), &dir.path().join(BEP_DIR))
                .with_listen(listen),
        )
        .expect("spawn host box egress proxy");
        let pid = bep.pid();
        assert!(pid_is_alive(pid));
        drop(bep);
        assert!(
            !pid_is_alive(pid),
            "dropping HostBep must stop the box egress proxy",
        );
    }

    #[test]
    fn host_bep_spawn_reports_launch_failure() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let err = HostBep::spawn(BepConfig::new(
            PathBuf::from("/nonexistent/definitely/not/bep"),
            &dir.path().join(BEP_DIR),
        ))
        .expect_err("spawning a missing binary must fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    /// A host with no proxy binary still boots: the bring-up warns and returns
    /// `None`, and lays nothing down.
    #[test]
    fn spawn_host_bep_without_a_binary_is_none() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bep_dir = dir.path().join(BEP_DIR);
        assert!(
            spawn_host_bep(PathBuf::from("/nonexistent/definitely/not/bep"), &bep_dir).is_none()
        );
        assert!(
            !bep_dir.exists(),
            "an absent proxy must not leave state behind",
        );
    }

    #[test]
    fn bep_argv_carries_the_listener_audit_log_and_attachments() {
        let cfg = BepConfig::new(
            PathBuf::from("/usr/lib/minimal/bin/bep"),
            Path::new("/s/bep"),
        );
        assert_eq!(
            cfg.argv(),
            vec![
                "--listen".to_string(),
                "127.0.0.1:7655".to_string(),
                "--audit-log".to_string(),
                "/s/bep/audit.log".to_string(),
                "--boxes".to_string(),
                "/s/bep/boxes.json".to_string(),
            ]
        );
        assert_eq!(cfg.audit_log(), Path::new("/s/bep/audit.log"));
        assert_eq!(cfg.boxes(), Path::new("/s/bep/boxes.json"));
    }

    /// The attachments file is created empty so the proxy can start, and an
    /// existing one is left alone: its contents are box creation's.
    #[test]
    fn bep_attachments_file_is_created_empty_and_never_clobbered() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let bep_dir = dir.path().join("nested").join(BEP_DIR);
        let cfg = BepConfig::new(PathBuf::from("/usr/lib/minimal/bin/bep"), &bep_dir);
        cfg.ensure_files().expect("lay down the proxy's files");
        assert_eq!(
            std::fs::read_to_string(cfg.boxes()).expect("read attachments"),
            "[]\n"
        );

        let declared = r#"[{"source":"100.64.0.2","box":"b","addressing":"own_ip"}]"#;
        std::fs::write(cfg.boxes(), declared).expect("write attachments");
        cfg.ensure_files()
            .expect("lay down the proxy's files again");
        assert_eq!(
            std::fs::read_to_string(cfg.boxes()).expect("read attachments"),
            declared,
            "declared attachments must survive a restart",
        );
    }

    /// The listener minvmd binds is the one a steered box's `HTTPS_PROXY` is
    /// pointed at, so the two definitions cannot drift (BEP-012, BEP-015).
    #[test]
    fn bep_default_listener_is_the_box_proxy_url() {
        let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, DEFAULT_BEP_PORT));
        assert_eq!(format!("http://{listen}"), sessions::BEP_PROXY_URL);
    }

    #[test]
    fn bep_binary_prefers_the_override_then_a_user_local_install() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let system = Path::new("/usr/lib/minimal/bin/bep");

        // The override is honoured verbatim, without an existence check.
        assert_eq!(
            bep_binary_from(
                Some("/custom/bep".to_string()),
                Some(dir.path().into()),
                system
            ),
            PathBuf::from("/custom/bep"),
        );
        // No override and no user-local install: the system path.
        assert_eq!(
            bep_binary_from(None, Some(dir.path().into()), system),
            system.to_path_buf(),
        );
        // A user-local install wins over the system path.
        let local = dir.path().join(BEP_FILE);
        std::fs::write(&local, b"bep").expect("write user-local bep");
        assert_eq!(
            bep_binary_from(None, Some(dir.path().into()), system),
            local,
        );
    }

    #[test]
    fn vm_egress_policy_allow_all_by_default() {
        assert!(VmEgressPolicy::allow_all().is_allow_all());
        let policy = VmEgressPolicy::allow_all()
            .with_subnets(["10.0.0.0/8".to_string()])
            .with_protocols([IpProto::Tcp]);
        assert!(!policy.is_allow_all());
        assert_eq!(policy.allow_subnets(), ["10.0.0.0/8"]);
        assert_eq!(policy.allow_protocols(), [IpProto::Tcp]);
        assert!(policy.allow_dns_hosts().is_empty());
    }

    /// NET-023: killing the switch under a running VM must warn within one
    /// minute that its datapath is gone. Drives [`probe_datapath`] directly
    /// against a stand-in switch socket at a test-scale interval — the
    /// production interval ([`DATAPATH_PROBE_INTERVAL`]) is itself far under
    /// the one-minute bound, so proving the healthy→lost transition warns
    /// promptly at any interval proves the bound holds in production too.
    ///
    /// `flavor = "current_thread"` is pinned explicitly (it is already
    /// `tokio::test`'s default): the `tracing::subscriber::set_default` guard
    /// below is thread-local, so the spawned `probe_datapath` task only sees
    /// it while running on this same thread.
    #[tokio::test(flavor = "current_thread")]
    async fn lost_datapath_warns_within_one_minute() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let sock = dir.path().join("switch.sock");
        let listener =
            std::os::unix::net::UnixListener::bind(&sock).expect("bind stand-in switch socket");

        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let stopping = Arc::new(AtomicBool::new(false));
        let probe = tokio::spawn(probe_datapath(
            sock.clone(),
            Duration::from_millis(20),
            Arc::clone(&stopping),
        ));

        // A couple of healthy ticks against the live socket must not warn.
        tokio::time::sleep(Duration::from_millis(70)).await;
        assert!(
            buf.contents().is_empty(),
            "no warning while the switch is reachable"
        );

        // Kill the switch out from under the (simulated) running VM.
        drop(listener);

        let warned = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if buf.contents().contains("gvproxy switch datapath lost") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        probe.abort();
        drop(guard);

        assert!(
            warned.is_ok(),
            "expected a datapath-lost warning after the switch was killed"
        );
        let logged = buf.contents();
        assert!(
            logged.contains(&sock.display().to_string()),
            "warning must name the switch socket, got: {logged}"
        );
    }
}
