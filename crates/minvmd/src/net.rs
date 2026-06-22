//! Per-host gvproxy switch supervision and per-PTask switch attachment for
//! `minvmd` (R1.4, R1.5, R1.8).
//!
//! On DM1/DM3/DM4 a libkrun VM runs `minimald`; `minvmd` supervises exactly one
//! gvproxy process per host VM ([`GvproxySwitch`]) that serves every own-IP
//! PTask as a switch client. A PTask attaches over the per-PTask vsock shuttle
//! already used for boot signalling: its tap fd is handed to gvproxy as a new
//! switch client and the PTask is assigned a unique IP from the switch subnet
//! ([`GvproxySwitch::attach_ptask`], R1.5).
//!
//! The supervisor terminates gvproxy with the same SIGTERM → timeout → SIGKILL
//! sequence the vmm child uses ([`terminate_child`], R1.4), and every switch
//! lifecycle event — spawn, stop, attach (with assigned IP), detach — is emitted
//! as a structured `tracing` event (R1.8). This module contains no
//! `println!`/`eprintln!`.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use minimald_rpc::IpProto;

/// Default time to wait for gvproxy to exit on SIGTERM before escalating to
/// SIGKILL.
pub const DEFAULT_TERM_TIMEOUT: Duration = Duration::from_secs(3);

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

impl SwitchSubnet {
    /// Construct a subnet from its network base address and prefix length.
    #[must_use]
    pub fn new(base: Ipv4Addr, prefix: u8) -> Self {
        Self { base, prefix }
    }

    /// The gateway address the switch itself answers on (index 1).
    #[must_use]
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.host(1)
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

/// Builder for the per-host gvproxy switch process.
#[derive(Debug, Clone)]
pub struct GvproxyConfig {
    /// Path to the gvproxy binary (vendored/built per Unit 1; see #495).
    binary: PathBuf,
    /// Unix socket gvproxy listens on for switch-client attachment.
    switch_socket: PathBuf,
    /// Subnet the switch assigns to own-IP PTasks.
    subnet: SwitchSubnet,
    /// Grace period before SIGTERM escalates to SIGKILL on teardown.
    term_timeout: Duration,
}

impl GvproxyConfig {
    /// Construct a config for the gvproxy `binary` listening on `switch_socket`.
    #[must_use]
    pub fn new(binary: PathBuf, switch_socket: PathBuf) -> Self {
        Self {
            binary,
            switch_socket,
            subnet: SwitchSubnet::default(),
            term_timeout: DEFAULT_TERM_TIMEOUT,
        }
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

    /// The argument vector passed to the gvproxy binary: it listens on the
    /// switch socket for client attachment. The switch subnet and per-client
    /// routes are configured over gvproxy's control API after start, not via
    /// argv.
    #[must_use]
    pub fn argv(&self) -> Vec<String> {
        vec![
            "-listen".to_string(),
            format!("unix://{}", self.switch_socket.display()),
        ]
    }

    /// Spawn and begin supervising the gvproxy switch process (R1.4).
    ///
    /// # Errors
    ///
    /// Returns the spawn error if the gvproxy binary cannot be launched.
    pub fn spawn(self) -> io::Result<GvproxySwitch> {
        let child = Command::new(&self.binary).args(self.argv()).spawn()?;
        let pid = child.id();
        tracing::info!(
            pid,
            binary = %self.binary.display(),
            switch_socket = %self.switch_socket.display(),
            "gvproxy switch spawned",
        );
        Ok(GvproxySwitch::new(
            child,
            self.subnet,
            self.term_timeout,
            self.switch_socket,
        ))
    }
}

/// A running, supervised gvproxy switch.
///
/// Dropping the handle tears the switch down with [`terminate_child`]. Each
/// own-IP PTask is attached with [`attach_ptask`](GvproxySwitch::attach_ptask),
/// which assigns it the next free switch IP and never reuses an IP for the
/// lifetime of this handle.
#[derive(Debug)]
pub struct GvproxySwitch {
    child: Child,
    subnet: SwitchSubnet,
    term_timeout: Duration,
    switch_socket: PathBuf,
    /// Next switch-client index to assign; starts at 2 (1 is the gateway).
    next_index: u32,
}

impl GvproxySwitch {
    /// Adopt an already-spawned gvproxy `child` for supervision.
    pub(crate) fn new(
        child: Child,
        subnet: SwitchSubnet,
        term_timeout: Duration,
        switch_socket: PathBuf,
    ) -> Self {
        Self {
            child,
            subnet,
            term_timeout,
            switch_socket,
            next_index: 2,
        }
    }

    /// The PID of the supervised gvproxy process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The unix socket gvproxy listens on for switch-client attachment.
    #[must_use]
    pub fn switch_socket(&self) -> &Path {
        &self.switch_socket
    }

    /// Attach an own-IP PTask as a switch client (R1.5), assigning it the next
    /// free IP from the switch subnet. `label` identifies the PTask in the
    /// emitted tracing event (R1.8).
    ///
    /// Returns `None` when the subnet is exhausted.
    ///
    /// The caller hands the PTask's tap file descriptor to gvproxy over the
    /// per-PTask vsock shuttle; that fd-pass is platform-specific (vsock on
    /// DM1, SCM_RIGHTS on DM2) and is layered on top of this assignment.
    pub fn attach_ptask(&mut self, label: impl Into<String>) -> Option<PtaskAttachment> {
        let index = self.next_index;
        let switch_ip = self.subnet.host(index)?;
        self.next_index += 1;
        let label = label.into();
        tracing::info!(
            ptask = %label,
            switch_ip = %switch_ip,
            gvproxy_pid = self.child.id(),
            "PTask attached to gvproxy switch",
        );
        Some(PtaskAttachment {
            label,
            switch_ip,
            index,
        })
    }

    /// Detach a previously attached PTask from the switch (R1.8). The IP is not
    /// returned to the pool — it is retired for this handle's lifetime so a
    /// later PTask never inherits a still-cached peer's address (R1.6 intent).
    pub fn detach_ptask(&self, attachment: &PtaskAttachment) {
        tracing::info!(
            ptask = %attachment.label,
            switch_ip = %attachment.switch_ip,
            gvproxy_pid = self.child.id(),
            "PTask detached from gvproxy switch",
        );
    }
}

impl Drop for GvproxySwitch {
    fn drop(&mut self) {
        let pid = self.child.id();
        // Best-effort teardown: Drop cannot propagate an error, so a failed
        // wait is logged rather than returned.
        match terminate_child(&mut self.child, self.term_timeout) {
            Ok(()) => tracing::info!(pid, "gvproxy switch stopped"),
            Err(error) => tracing::error!(pid, %error, "gvproxy switch teardown failed"),
        }
    }
}

/// A PTask's attachment to the gvproxy switch: the assigned IP plus the client
/// index it was allocated at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtaskAttachment {
    label: String,
    switch_ip: Ipv4Addr,
    index: u32,
}

impl PtaskAttachment {
    /// The PTask label this attachment was created for.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The IP assigned to this PTask on the switch subnet.
    #[must_use]
    pub fn switch_ip(&self) -> Ipv4Addr {
        self.switch_ip
    }

    /// The switch-client index this PTask was allocated at.
    #[must_use]
    pub fn index(&self) -> u32 {
        self.index
    }
}

/// Terminate `child` with the SIGTERM → `timeout` → SIGKILL sequence used for
/// the vmm child (R1.4), then reap it.
///
/// # Errors
///
/// Returns an I/O error if waiting on the child fails.
pub fn terminate_child(child: &mut Child, timeout: Duration) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        // Already exited; nothing to signal.
        return Ok(());
    }

    let pid = child.id() as libc::pid_t;
    signal_child(pid, libc::SIGTERM, "SIGTERM");

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    signal_child(pid, libc::SIGKILL, "SIGKILL");
    child.wait().map(|_| ())
}

/// Deliver `signal` to `pid` best-effort, logging any delivery failure other
/// than the benign `ESRCH` (the process has already exited — the expected race
/// during teardown). The result is intentionally not propagated: teardown
/// cannot recover from a failed signal, but an unexpected errno (e.g. `EPERM`,
/// `EINVAL`) should be visible in the logs rather than silently swallowed.
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
    fn argv_listens_on_switch_socket() {
        let cfg = GvproxyConfig::new(
            PathBuf::from("/usr/bin/gvproxy"),
            PathBuf::from("/run/minvmd/switch.sock"),
        );
        assert_eq!(
            cfg.argv(),
            vec![
                "-listen".to_string(),
                "unix:///run/minvmd/switch.sock".to_string(),
            ]
        );
    }

    #[test]
    fn attach_assigns_unique_sequential_ips() {
        let mut switch = GvproxySwitch::new(
            spawn_sleep(),
            SwitchSubnet::default(),
            Duration::from_secs(2),
            PathBuf::from("/run/minvmd/switch.sock"),
        );

        let a = switch.attach_ptask("ptask-a").expect("attach a");
        let b = switch.attach_ptask("ptask-b").expect("attach b");

        assert_eq!(a.switch_ip(), Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(b.switch_ip(), Ipv4Addr::new(100, 64, 0, 3));
        assert_ne!(a.switch_ip(), b.switch_ip(), "IPs must be unique");
        switch.detach_ptask(&a);
    }

    #[test]
    fn drop_terminates_supervised_child() {
        let child = spawn_sleep();
        let pid = child.id();
        assert!(pid_is_alive(pid), "child should be alive before drop");

        let switch = GvproxySwitch::new(
            child,
            SwitchSubnet::default(),
            Duration::from_secs(2),
            PathBuf::from("/run/minvmd/switch.sock"),
        );
        drop(switch);

        // SIGTERM on `sleep` is immediate; the child is reaped by Drop.
        assert!(!pid_is_alive(pid), "child must be terminated after drop");
    }

    #[test]
    fn terminate_child_reaps_running_child() {
        let mut child = spawn_sleep();
        let pid = child.id();
        terminate_child(&mut child, Duration::from_secs(2)).expect("terminate");
        assert!(!pid_is_alive(pid), "terminate_child must reap the process");
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
