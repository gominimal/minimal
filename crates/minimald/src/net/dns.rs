//! In-memory PTask hostname registry and a startup probe for the system
//! resolver: the DNS half of Unit 3 (UC2a) on the native-Linux (DM2) path.
//!
//! ## `*.localhost` + host-side proxy
//!
//! Open Question 1 of the networking spec is settled (spike #485): a PTask
//! hostname takes the form `<session>.<host-id>.localhost`. Every `*.localhost`
//! name is synthesized to a loopback address *statically* by the system
//! resolver (systemd-resolved on Linux, built in on macOS), with no privileged
//! per-session resolver write — the mechanism is fully rootless (R3.4). Because
//! that synthesis is static and lifecycle independent, the DNS layer cannot tell
//! one PTask from another; the discriminator is a host-side proxy that routes an
//! incoming request to the right PTask by its `Host:` header. This registry is
//! the lookup table that proxy consults — [`HostnameRegistry::resolve`] is the
//! routing decision for a `Host:` header. The HTTP reverse-proxy front end that
//! drives it (the rest of UC2a) is tracked separately and is not part of this
//! module.
//!
//! `HostNet` PTasks register to `127.0.0.1` (R3.6). `OwnIp` registration to the
//! gvproxy switch IP is deferred to #542 (the switch is not yet wired into the
//! live `minimald` session path); [`HostnameRegistry::register`] already takes
//! the target address, so that work is a caller change, not a registry change.
//!
//! Covers R3.4 (resolver probe), R3.5 (structured register/deregister tracing),
//! and R3.6 (`HostNet` registration).

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// The DNS suffix every PTask hostname carries (see the module docs).
pub const LOCALHOST_SUFFIX: &str = "localhost";

/// Default `<host-id>`: a stable short name for this `minimald` instance. The
/// host-id is configurable; this is the value used when none is configured.
pub const DEFAULT_HOST_ID: &str = "local";

/// The sentinel name the startup probe resolves to detect `*.localhost`
/// synthesis (R3.4). Never registered; only ever looked up.
pub const PROBE_HOSTNAME: &str = "minimald-probe.localhost";

/// The loopback address a local-only (non-DM5) PTask hostname routes to (R3.6).
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A registered PTask hostname of the form `<session>.<host-id>.localhost`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Builds the hostname for a PTask. DNS names are case-insensitive, so the
    /// rendered form is lower-cased to keep lookups stable.
    fn for_ptask(session_name: &str, host_id: &str) -> Self {
        Self(format!("{session_name}.{host_id}.{LOCALHOST_SUFFIX}").to_ascii_lowercase())
    }

    /// The hostname as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An in-memory registry of live PTask hostnames, owned by the sessions manager
/// (one per `minimald`). It maps each live PTask's hostname to the address a
/// host-side proxy routes its requests to, and tracks the reverse (session →
/// hostname) so a hostname is withdrawn when its session exits.
#[derive(Debug)]
pub struct HostnameRegistry {
    /// The `<host-id>` component shared by every hostname this registry mints.
    host_id: String,
    /// hostname → the address a host-side proxy routes its requests to.
    by_host: HashMap<Hostname, IpAddr>,
    /// session name → its registered hostname, for withdrawal on exit.
    by_session: HashMap<String, Hostname>,
}

impl HostnameRegistry {
    /// Creates an empty registry whose hostnames use the given `<host-id>`.
    #[must_use]
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            by_host: HashMap::new(),
            by_session: HashMap::new(),
        }
    }

    /// Registers `session_name`'s hostname, routing it to `target`, and returns
    /// the hostname. Emits the R3.5 `registered` tracing event.
    pub fn register(&mut self, session_name: &str, target: IpAddr) -> Hostname {
        let hostname = Hostname::for_ptask(session_name, &self.host_id);
        self.by_session
            .insert(session_name.to_string(), hostname.clone());
        self.by_host.insert(hostname.clone(), target);
        tracing::info!(
            session_name,
            hostname = %hostname,
            ip = %target,
            action = "registered",
            "registered PTask hostname"
        );
        hostname
    }

    /// Registers a `HostNet` PTask, routing its hostname to `127.0.0.1` (R3.6).
    pub fn register_host_net(&mut self, session_name: &str) -> Hostname {
        self.register(session_name, LOOPBACK)
    }

    /// Withdraws `session_name`'s hostname, returning it if one was registered.
    /// Emits the R3.5 `deregistered` tracing event only when an entry is
    /// actually removed, so calling it for an unregistered session is a silent
    /// no-op.
    pub fn deregister(&mut self, session_name: &str) -> Option<Hostname> {
        let hostname = self.by_session.remove(session_name)?;
        let ip = self.by_host.remove(&hostname);
        tracing::info!(
            session_name,
            hostname = %hostname,
            ip = ?ip,
            action = "deregistered",
            "deregistered PTask hostname"
        );
        Some(hostname)
    }

    /// Resolves a `Host:` header to the address a host-side proxy routes the
    /// request to, or `None` if no live PTask owns that hostname.
    ///
    /// This is the registry/proxy contract: every `*.localhost` name resolves to
    /// loopback in the DNS layer, so the per-PTask routing decision is made here,
    /// by hostname. The header's optional `:port` suffix is ignored and matching
    /// is case-insensitive, matching how a real `Host:` header arrives.
    #[must_use]
    pub fn resolve(&self, host_header: &str) -> Option<IpAddr> {
        let host = host_header.split(':').next().unwrap_or(host_header);
        self.by_host
            .get(&Hostname(host.to_ascii_lowercase()))
            .copied()
    }
}

/// The result of probing the system resolver for `*.localhost` synthesis (R3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// `*.localhost` resolves to loopback; PTask hostnames will resolve.
    Active,
    /// `*.localhost` does not resolve; a remediation warning has been emitted.
    Inactive,
}

/// Resolves a hostname through the operating system resolver (`getaddrinfo`),
/// returning the addresses it yields. An NXDOMAIN/lookup failure surfaces as an
/// `Err`. Suitable as the `resolve` argument to [`probe_resolver`] in
/// production.
///
/// # Errors
///
/// Propagates the resolver error (including NXDOMAIN) verbatim.
pub fn system_resolver(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    Ok((hostname, 0u16)
        .to_socket_addrs()?
        .map(|s| s.ip())
        .collect())
}

/// Probes whether the system resolver synthesizes `*.localhost` to loopback,
/// emitting a `tracing::warn!` with a human-readable remediation when it does
/// not (R3.4). `resolve` performs the lookup; injecting it keeps the probe
/// testable without depending on the host's resolver configuration.
pub fn probe_resolver<F>(resolve: F) -> ProbeOutcome
where
    F: FnOnce(&str) -> std::io::Result<Vec<IpAddr>>,
{
    match resolve(PROBE_HOSTNAME) {
        Ok(addrs) if addrs.iter().any(|a| a.is_loopback()) => ProbeOutcome::Active,
        // Either the name did not resolve (NXDOMAIN) or it resolved to a
        // non-loopback address — in both cases `*.localhost` synthesis is not in
        // effect, so PTask hostnames will not resolve until it is enabled.
        Ok(_) | Err(_) => {
            tracing::warn!(
                resolver = "systemd-resolved",
                status = "inactive",
                remedy = "systemctl enable --now systemd-resolved",
                probe = PROBE_HOSTNAME,
                "system resolver does not synthesize *.localhost; PTask hostnames will not resolve until it is enabled"
            );
            ProbeOutcome::Inactive
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    /// A `MakeWriter` that accumulates everything written into a shared buffer,
    /// so a test can assert on the structured fields a `tracing` event emitted.
    #[derive(Clone, Default)]
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl CaptureWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CaptureWriter {
        type Writer = CaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Proof artifact 1 (registry/proxy contract): registering a `HostNet`
    /// PTask makes the host-side proxy route its `Host:` header to `127.0.0.1`;
    /// deregistering withdraws it so the proxy no longer routes it. `*.localhost`
    /// is synthesized to loopback statically by the resolver, so this asserts the
    /// registry/proxy routing contract, not a `getaddrinfo` lifecycle.
    #[test]
    fn host_net_registration_routes_by_host_header_then_withdraws() {
        let mut reg = HostnameRegistry::new("dev");

        let hostname = reg.register_host_net("myservice");
        assert_eq!(hostname.as_str(), "myservice.dev.localhost");

        // The host-side proxy routes a request by its `Host:` header to the PTask
        // — with or without the `:port` a real header carries.
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(reg.resolve("myservice.dev.localhost"), Some(loopback));
        assert_eq!(reg.resolve("myservice.dev.localhost:8080"), Some(loopback));

        // After the session exits the entry is gone and the proxy no longer
        // routes it.
        let removed = reg
            .deregister("myservice")
            .expect("hostname was registered");
        assert_eq!(removed.as_str(), "myservice.dev.localhost");
        assert_eq!(reg.resolve("myservice.dev.localhost"), None);
    }

    /// Deregistering a session that was never registered is a silent no-op, so
    /// the manager can call it unconditionally on session teardown.
    #[test]
    fn deregister_unknown_session_is_a_noop() {
        let mut reg = HostnameRegistry::new("dev");
        assert_eq!(reg.deregister("ghost"), None);
    }

    /// Proof artifact 2 (R3.4): when the resolver returns NXDOMAIN for the
    /// probe name, startup emits a `tracing::warn!` carrying the
    /// `resolver = "systemd-resolved"` and `status = "inactive"` structured
    /// fields, and the probe reports the resolver inactive.
    #[test]
    fn probe_warns_when_resolver_returns_nxdomain() {
        let buf = CaptureWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();

        let outcome = tracing::subscriber::with_default(subscriber, || {
            probe_resolver(|_name| Err(std::io::Error::from(std::io::ErrorKind::NotFound)))
        });

        assert_eq!(outcome, ProbeOutcome::Inactive);
        let logged = buf.contents();
        assert!(
            logged.contains(r#"resolver="systemd-resolved""#),
            "expected the resolver field, got: {logged}"
        );
        assert!(
            logged.contains(r#"status="inactive""#),
            "expected the inactive status field, got: {logged}"
        );
    }

    /// When `*.localhost` synthesizes to loopback the probe reports the resolver
    /// active and emits no warning.
    #[test]
    fn probe_is_active_when_localhost_synthesizes_to_loopback() {
        let outcome = probe_resolver(|_name| Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]));
        assert_eq!(outcome, ProbeOutcome::Active);
    }
}
