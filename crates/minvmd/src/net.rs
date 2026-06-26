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
//! established that the attachment is **not** an SCM_RIGHTS fd-pass. Instead
//! `minvmd`:
//!
//! 1. writes a gvproxy `-config` YAML carrying the subnet, gateway, NAT alias,
//!    and `dhcpStaticLeases` ([`render_gvproxy_config`]) — the subnet is
//!    YAML-only (gvproxy v0.8.9 has no `-subnet` CLI flag);
//! 2. opens a tap device in the host namespace ([`open_tap`]) and (the caller)
//!    moves it into the PTask's netns and configures its MAC/IP/route there,
//! 3. runs an async relay ([`attach_to_switch`]) that bridges the host-side tap
//!    fd to gvproxy's control socket: a bare `POST /connect` HTTP upgrade, then
//!    raw Ethernet frames framed with a 2-byte little-endian length prefix (the
//!    HyperKit protocol).
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

use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};

use minimald_rpc::IpProto;
use tokio::process::{Child, Command};
use tokio::sync::oneshot;

#[cfg(target_os = "linux")]
mod relay;
#[cfg(target_os = "linux")]
pub use relay::{SwitchRelay, attach_to_switch, open_tap};

mod shuttle;
pub use shuttle::{VSOCK_GVPROXY_SHUTTLE_PORT, resolve_switch_sock};

/// Default time to wait for gvproxy to exit on SIGTERM before escalating to
/// SIGKILL.
pub const DEFAULT_TERM_TIMEOUT: Duration = Duration::from_secs(3);

/// MTU advertised to the switch and the tap devices. gvproxy's own default.
pub const DEFAULT_MTU: u16 = 1500;

/// Stable, locally-administered MAC for the switch gateway.
pub const GATEWAY_MAC: MacAddr = MacAddr([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd]);

/// Error returned when [`SwitchSubnet::new`] is called with a prefix that
/// would make every [`SwitchSubnet::host`] call return `None`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SwitchSubnetError {
    /// The prefix is outside the range that allows at least one host address.
    ///
    /// Valid range: `1..=30`. A prefix of `0` overflows the host-bit shift;
    /// a prefix of `31` or `32` leaves no integer index where
    /// [`SwitchSubnet::host`] returns `Some`; a prefix above `32` is not
    /// a valid IPv4 prefix length.
    #[error("prefix /{0} is invalid for a gvproxy subnet (valid: /1..=/30)")]
    InvalidPrefix(u8),
}

/// The IPv4 subnet the gvproxy switch hands out to own-IP PTasks.
///
/// Defaults to the RFC-6598 shared-address range `100.64.0.0/16`. Index 0 is the
/// network address and the final address is the broadcast address; index 1 is
/// reserved for the switch gateway, so client IPs are allocated from index 2 up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchSubnet {
    base: Ipv4Addr,
    prefix: u8,
}

impl Default for SwitchSubnet {
    fn default() -> Self {
        Self {
            base: Ipv4Addr::new(100, 64, 0, 0),
            prefix: 16,
        }
    }
}

impl fmt::Display for SwitchSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.base, self.prefix)
    }
}

impl SwitchSubnet {
    /// Construct a subnet from its network base address and prefix length.
    ///
    /// # Errors
    ///
    /// Returns [`SwitchSubnetError::InvalidPrefix`] for a prefix outside
    /// `1..=30`. A prefix of `0` makes every [`host`](Self::host) call return
    /// `None` via shift overflow; a prefix of `31` or `32` leaves no integer
    /// index where `host` returns `Some`.
    pub fn new(base: Ipv4Addr, prefix: u8) -> Result<Self, SwitchSubnetError> {
        if !(1..=30).contains(&prefix) {
            return Err(SwitchSubnetError::InvalidPrefix(prefix));
        }
        Ok(Self { base, prefix })
    }

    /// The gateway address the switch itself answers on (index 1).
    #[must_use]
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.host(1)
    }

    /// The host-alias address gvproxy NATs to the host loopback so a PTask can
    /// reach host services (the last usable address). `None` for a
    /// subnet too small to carry one.
    #[must_use]
    pub fn host_alias(&self) -> Option<Ipv4Addr> {
        let span = 1u32.checked_shl(u32::from(32 - self.prefix.min(32)))?;
        // broadcast - 1 (span - 2 from the base); reuse `host` for the bounds.
        self.host(span.checked_sub(2)?)
    }

    /// The host address at `index` within the subnet, or `None` when `index`
    /// falls outside the usable host range (network, broadcast, or beyond the
    /// subnet span).
    #[must_use]
    pub fn host(&self, index: u32) -> Option<Ipv4Addr> {
        // Total addresses in the subnet; a /0 or out-of-range prefix yields None.
        let span = 1u32.checked_shl(u32::from(32 - self.prefix.min(32)))?;
        // Exclude the network address (0) and the broadcast address (span - 1).
        if index == 0 || index >= span.checked_sub(1)? {
            return None;
        }
        let addr = u32::from(self.base).checked_add(index)?;
        Some(Ipv4Addr::from(addr))
    }
}

/// A 48-bit Ethernet MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl MacAddr {
    /// Derives a stable, locally-administered unicast MAC for a switch IP.
    ///
    /// Uses the QEMU OUI `52:54:00` (locally administered) followed by the low
    /// three octets of the address. Within a single `/16` (or narrower) switch
    /// subnet the low three octets are unique, so the derived MAC is
    /// collision-free and deterministic — `minvmd` can pre-seed gvproxy's
    /// static-lease table without round-tripping through DHCP.
    #[must_use]
    pub fn for_switch_ip(ip: Ipv4Addr) -> Self {
        let o = ip.octets();
        Self([0x52, 0x54, 0x00, o[1], o[2], o[3]])
    }
}

/// Renders the gvproxy `-config` YAML for the given subnet and static leases.
///
/// gvproxy v0.8.9 has no `-subnet` CLI flag: the subnet, gateway, NAT alias, and
/// DHCP static leases are all expressed through a `-config` YAML file (see the
/// spike). `minvmd` owns the allocation table and writes it here before every
/// (re)start so the switch's static leases match `minvmd`'s address book.
///
/// gvproxy reads this file only at spawn time, so a rewrite triggered by a later
/// attach takes effect only on the next switch (re)start. That is intentional:
/// an `OwnIp` PTask configures its switch address statically (the spike's
/// static-lease recipe) rather than via DHCP, so `dhcpStaticLeases` is a
/// startup-time seed, not a live source a running gvproxy must re-read.
#[must_use]
pub fn render_gvproxy_config(subnet: SwitchSubnet, leases: &[(Ipv4Addr, MacAddr)]) -> String {
    let mut s = String::with_capacity(256 + leases.len() * 48);
    s.push_str("stack:\n");
    s.push_str(&format!("  mtu: {DEFAULT_MTU}\n"));
    s.push_str(&format!("  subnet: \"{subnet}\"\n"));
    if let Some(gateway) = subnet.gateway() {
        s.push_str(&format!("  gatewayIP: \"{gateway}\"\n"));
    }
    s.push_str(&format!("  gatewayMacAddress: \"{GATEWAY_MAC}\"\n"));
    if let Some(alias) = subnet.host_alias() {
        s.push_str("  nat:\n");
        s.push_str(&format!("    \"{alias}\": \"127.0.0.1\"\n"));
        s.push_str("  gatewayVirtualIPs:\n");
        s.push_str(&format!("    - \"{alias}\"\n"));
    }
    s.push_str("  dhcpStaticLeases:\n");
    if leases.is_empty() {
        // gvproxy accepts an empty map; keep the key present for clarity.
        s.push_str("    {}\n");
    } else {
        for (ip, mac) in leases {
            s.push_str(&format!("    \"{ip}\": \"{mac}\"\n"));
        }
    }
    s
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
        let switch = Self {
            pid,
            #[cfg(target_os = "linux")]
            pidfd,
            term_timeout,
            switch_socket,
            stopping,
            supervisor: Some(supervisor),
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn default_subnet_is_rfc6598_slash16() {
        let net = SwitchSubnet::default();
        assert_eq!(net.gateway(), Some(Ipv4Addr::new(100, 64, 0, 1)));
        // First client IP (index 2) and a high host within /16.
        assert_eq!(net.host(2), Some(Ipv4Addr::new(100, 64, 0, 2)));
        assert_eq!(net.host(258), Some(Ipv4Addr::new(100, 64, 1, 2)));
        // Host alias is the second-from-last usable address.
        assert_eq!(net.host_alias(), Some(Ipv4Addr::new(100, 64, 255, 254)));
        assert_eq!(net.to_string(), "100.64.0.0/16");
    }

    #[test]
    fn subnet_rejects_network_and_broadcast() {
        let net = SwitchSubnet::default();
        assert_eq!(net.host(0), None, "network address is not a host");
        // /16 broadcast is index 65535 (span - 1).
        assert_eq!(net.host(65535), None, "broadcast address is not a host");
        assert_eq!(net.host(65534), Some(Ipv4Addr::new(100, 64, 255, 254)));
    }

    #[test]
    fn mac_is_derived_deterministically_from_ip() {
        // 52:54:00 OUI followed by the low three octets of 100.64.0.2 in hex.
        let ip = Ipv4Addr::new(100, 64, 0, 2);
        assert_eq!(MacAddr::for_switch_ip(ip).to_string(), "52:54:00:40:00:02");
        assert_eq!(MacAddr::for_switch_ip(ip), MacAddr::for_switch_ip(ip));
    }

    #[test]
    fn subnet_new_rejects_zero_prefix() {
        assert!(
            matches!(
                SwitchSubnet::new(Ipv4Addr::new(100, 64, 0, 0), 0),
                Err(SwitchSubnetError::InvalidPrefix(0))
            ),
            "prefix /0 makes host() always return None via shift overflow",
        );
    }

    #[test]
    fn subnet_new_rejects_prefix_31() {
        // /31 has span=2, span-1=1; every host() index satisfies index>=1 → None.
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 31),
            Err(SwitchSubnetError::InvalidPrefix(31))
        ));
    }

    #[test]
    fn subnet_new_rejects_prefix_32() {
        // /32 has span=1, span-1=0; host(0) is the network address → None, so
        // every host() call returns None — the pathology the validation guards.
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 32),
            Err(SwitchSubnetError::InvalidPrefix(32))
        ));
    }

    #[test]
    fn subnet_new_rejects_prefix_above_32() {
        assert!(matches!(
            SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 33),
            Err(SwitchSubnetError::InvalidPrefix(33))
        ));
    }

    #[test]
    fn subnet_new_accepts_valid_prefixes() {
        // /1 (widest valid) and /30 (narrowest valid — gateway at index 1 fits).
        assert!(SwitchSubnet::new(Ipv4Addr::new(128, 0, 0, 0), 1).is_ok());
        assert!(SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 30).is_ok());
        let net = SwitchSubnet::new(Ipv4Addr::new(10, 0, 0, 0), 30).unwrap();
        assert_eq!(net.gateway(), Some(Ipv4Addr::new(10, 0, 0, 1)));
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
        // `sleep` stands in for gvproxy: HostGvproxy::spawn only needs a binary
        // it can launch and read a PID from; the socket is dialed by libkrun in
        // production, not by this supervisor. Use a temp socket path so no real
        // file is needed (gvproxy would bind it; sleep ignores its argv).
        let dir = tempfile::TempDir::new().expect("tempdir");
        let sock = dir.path().join("gvproxy-switch.sock");
        let gvproxy = HostGvproxy::spawn(PathBuf::from("sleep"), sock).expect("spawn host gvproxy");
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
        let gvproxy = HostGvproxy::spawn(PathBuf::from("sleep"), sock).expect("spawn host gvproxy");
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
}
