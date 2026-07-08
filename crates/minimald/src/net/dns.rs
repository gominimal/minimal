//! In-memory PTask hostname registry: the host-side routing table for the B5
//! egress proxy (Unit 3, UC2a) on the native-Linux (DM2) path.
//!
//! ## `*.min.internal` + host-side egress proxy
//!
//! Open Question 1 of the networking spec is settled in favour of the spec's B5
//! model (re-scoped 2026-06-23, superseding spike #485's systemd-resolved
//! finding): a PTask hostname takes the form `<session>.<host-id>.min.internal`,
//! and both resolution and routing stay **host-side**. The host resolver is
//! never consulted and `minimald` writes nothing to it — `*.min.internal` (the TLD
//! is an opaque label) is mapped internally by the host-side egress proxy
//! ([`super::proxy`]), which routes each incoming request to the right PTask by
//! its `Host:` header. This registry is the lookup table that proxy consults —
//! [`HostnameRegistry::resolve`] is the routing decision for a `Host:` header.
//! Because resolution is host-side, the no-systemd sandbox (hakoniwa) and
//! microVM (libkrun) runtimes never resolve anything, and the TLD choice is
//! irrelevant to correctness.
//!
//! Both `HostNet` (R3.6) and `OwnIp` (R3.1) PTasks register to `127.0.0.1`: a
//! `HostNet` PTask's listeners are on host loopback directly, and an `OwnIp`
//! PTask is reached through a gvproxy-**published loopback port** (its forwarder
//! API binds `127.0.0.1:<external>` → `lease:<internal>`), so the daemon is never
//! on the switch (the DM2 topology in `networking-with-diagrams.md`). The client
//! selects the published external port; the registry gates only on the host.
//! [`HostnameRegistry::register`] takes the target address, so both modes are the
//! same registry call with the same `127.0.0.1` target.
//!
//! Covers R3.5 (structured register/deregister tracing) and R3.6 (`HostNet`
//! registration). The former systemd-resolved startup probe (R3.4) is removed by
//! the re-scope; an egress-proxy reachability check
//! ([`super::proxy::bind_listener`]) replaces it.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use sessions::SessionId;

/// The DNS suffix every PTask hostname carries (see the module docs).
pub const HOSTNAME_SUFFIX: &str = "min.internal";

/// Default `<host-id>`: a stable short name for this `minimald` instance. The
/// host-id is configurable; this is the value used when none is configured.
pub const DEFAULT_HOST_ID: &str = "local";

/// The loopback address a local-only (non-DM5) PTask hostname routes to (R3.6).
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Where a resolved PTask hostname routes, and how its published ports remap.
///
/// `target` is the address a host-side consumer dials. `port_map` translates a
/// published *external* port in the request authority to the PTask-*internal*
/// port to dial, and is populated only for **in-VM lease routing** (DM1/3/4):
/// there the daemon reaches an `OwnIp` PTask by its switch lease directly,
/// because gvproxy's host-loopback forwarder lives in the *host* netns and is
/// unreachable from inside the VM (G-N9). It is empty for the published-loopback
/// model (DM2 / `HostNet`), where the authority's port is dialed unchanged
/// because the shared-netns forwarder already maps external→internal on host
/// loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The address a host-side consumer dials for this hostname.
    pub target: IpAddr,
    /// external→internal port remap, applied by [`Route::dial_port`]. Empty
    /// means the authority's port is dialed unchanged (published-loopback).
    pub port_map: Vec<(u16, u16)>,
}

impl Route {
    /// The published-loopback placeholder: loopback target, no remap. This is
    /// how every `OwnIp`/`HostNet` hostname is registered, and what an `OwnIp`
    /// entry reverts to when its live lease tears down.
    fn loopback() -> Self {
        Self {
            target: LOOPBACK,
            port_map: Vec::new(),
        }
    }

    /// The upstream port to dial for a request whose authority carried
    /// `external`: the mapped PTask-internal port when this route publishes a
    /// lease mapping for it, else `external` unchanged (published-loopback).
    #[must_use]
    pub fn dial_port(&self, external: u16) -> u16 {
        self.port_map
            .iter()
            .find(|(ext, _)| *ext == external)
            .map_or(external, |(_, internal)| *internal)
    }
}

/// A registered PTask hostname of the form `<session>.<host-id>.min.internal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Builds the hostname for a PTask. DNS names are case-insensitive, so the
    /// rendered form is lower-cased to keep lookups stable.
    fn for_ptask(session_name: &str, host_id: &str) -> Self {
        Self(format!("{session_name}.{host_id}.{HOSTNAME_SUFFIX}").to_ascii_lowercase())
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

/// A live registration: the hostname minted for a session, plus the stable
/// `SessionId` carried in its R3.5 tracing events. The id is captured at
/// registration so `deregister` (keyed by the mutable session name) emits the
/// same stable identifier the `registered` event did.
#[derive(Debug, Clone)]
struct Registration {
    id: SessionId,
    hostname: Hostname,
}

/// An in-memory registry of live PTask hostnames, owned by the sessions manager
/// (one per `minimald`). It maps each live PTask's hostname to the address a
/// host-side proxy routes its requests to, and tracks the reverse (session →
/// hostname) so a hostname is withdrawn when its session exits.
#[derive(Debug)]
pub struct HostnameRegistry {
    /// The `<host-id>` component shared by every hostname this registry mints.
    host_id: String,
    /// hostname → the [`Route`] a host-side proxy forwards its requests along.
    by_host: HashMap<Hostname, Route>,
    /// session name → its live registration, for withdrawal on exit.
    by_session: HashMap<String, Registration>,
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
    /// the hostname. Emits the R3.5 `registered` tracing event. `session_id` is
    /// the stable, unique identifier carried in that event for log correlation;
    /// `session_name` is the registry key (mutable, and reusable after the
    /// session exits), so both are emitted.
    pub fn register(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        target: IpAddr,
    ) -> Hostname {
        let hostname = Hostname::for_ptask(session_name, &self.host_id);
        self.by_session.insert(
            session_name.to_string(),
            Registration {
                id: session_id,
                hostname: hostname.clone(),
            },
        );
        self.by_host.insert(
            hostname.clone(),
            Route {
                target,
                port_map: Vec::new(),
            },
        );
        tracing::info!(
            session_id = %session_id,
            session_name,
            hostname = %hostname,
            ip = %target,
            action = "registered",
            "registered PTask hostname"
        );
        hostname
    }

    /// Registers a `HostNet` PTask, routing its hostname to `127.0.0.1` (R3.6).
    pub fn register_host_net(&mut self, session_id: SessionId, session_name: &str) -> Hostname {
        self.register(session_id, session_name, LOOPBACK)
    }

    /// Registers an `OwnIp` PTask, routing its hostname to `127.0.0.1` (R3.1).
    ///
    /// Under the published-loopback model (see the module docs) an `OwnIp` PTask's
    /// service is reached through a gvproxy-published loopback port
    /// (`127.0.0.1:<external>` → `lease:<internal>`), so — like a `HostNet` PTask
    /// — its hostname resolves to loopback and the daemon never touches the
    /// switch. The client selects the published external port; the registry gates
    /// only on the host.
    pub fn register_own_ip(&mut self, session_id: SessionId, session_name: &str) -> Hostname {
        self.register(session_id, session_name, LOOPBACK)
    }

    /// Withdraws `session_name`'s hostname, returning it if one was registered.
    /// Emits the R3.5 `deregistered` tracing event only when an entry is
    /// actually removed, so calling it for an unregistered session is a silent
    /// no-op. The event carries the same stable `session_id` the matching
    /// `registered` event did, and formats `ip` with `Display` to match it.
    pub fn deregister(&mut self, session_name: &str) -> Option<Hostname> {
        let Registration { id, hostname } = self.by_session.remove(session_name)?;
        let route = self
            .by_host
            .remove(&hostname)
            .expect("by_host is kept in sync with by_session by register");
        tracing::info!(
            session_id = %id,
            session_name,
            hostname = %hostname,
            ip = %route.target,
            action = "deregistered",
            "deregistered PTask hostname"
        );
        Some(hostname)
    }

    /// Publishes a live `OwnIp` PTask's switch `lease` into its
    /// already-registered hostname entry, so in-VM host→PTask consumers (the
    /// `:7654`/`:7655` proxies) dial the lease directly instead of the
    /// host-loopback forwarder, which is unreachable from inside the VM (G-N9).
    /// `port_map` carries the session's static TCP ingress mappings as
    /// external→internal pairs, so the consumer's published external port is
    /// translated to the PTask-internal port to dial.
    ///
    /// Keyed by the stable [`SessionId`] so a rename between attach and this
    /// call cannot lose the entry. A no-op (with a warning) when no hostname is
    /// registered for the session — e.g. a `NoNet` PTask, which never registers.
    /// The lease therefore exists in the routing table only while the sandbox
    /// runs; [`clear_own_ip_lease`](Self::clear_own_ip_lease) reverts it.
    pub fn set_own_ip_lease(
        &mut self,
        session_id: SessionId,
        lease: Ipv4Addr,
        port_map: Vec<(u16, u16)>,
    ) {
        let Some(hostname) = self.hostname_for_session(session_id) else {
            tracing::warn!(
                session_id = %session_id,
                "set_own_ip_lease: no registered hostname for session; lease not published"
            );
            return;
        };
        self.by_host.insert(
            hostname.clone(),
            Route {
                target: IpAddr::V4(lease),
                port_map,
            },
        );
        tracing::info!(
            session_id = %session_id,
            hostname = %hostname,
            lease = %lease,
            action = "lease-published",
            "published OwnIp PTask switch lease"
        );
    }

    /// Reverts an `OwnIp` PTask's hostname entry to the published-loopback
    /// placeholder when its sandbox — and therefore its lease — tears down. The
    /// hostname stays registered (the session lives on and may re-attach), but
    /// the lease is present in the routing table only while the sandbox runs.
    /// Keyed by the stable [`SessionId`]; a no-op when nothing is registered.
    pub fn clear_own_ip_lease(&mut self, session_id: SessionId) {
        let Some(hostname) = self.hostname_for_session(session_id) else {
            return;
        };
        self.by_host.insert(hostname.clone(), Route::loopback());
        tracing::info!(
            session_id = %session_id,
            hostname = %hostname,
            action = "lease-revoked",
            "reverted OwnIp PTask lease to the loopback placeholder"
        );
    }

    /// The current [`Route`] for a session's hostname, looked up by its stable
    /// id. Used by the SSH `direct-tcpip` handler to reach an `OwnIp` PTask by
    /// its live switch lease. `None` when the session has no registered
    /// hostname.
    #[must_use]
    pub fn route_for_session(&self, session_id: SessionId) -> Option<Route> {
        let hostname = self.hostname_for_session(session_id)?;
        self.by_host.get(&hostname).cloned()
    }

    /// The hostname registered for `session_id`, if any. Scans the session
    /// table (small: one entry per live session) so lookups survive a rename,
    /// which mutates the by-name key but not the id.
    fn hostname_for_session(&self, session_id: SessionId) -> Option<Hostname> {
        self.by_session
            .values()
            .find(|reg| reg.id == session_id)
            .map(|reg| reg.hostname.clone())
    }

    /// Resolves a `Host:` header to the full [`Route`] a host-side proxy
    /// forwards the request along — target address plus any external→internal
    /// port remap. The remap is applied by the proxy router
    /// ([`super::proxy::Router::route`]); read `route.target` for the address
    /// alone. Every `*.min.internal` name resolves to loopback in the DNS layer,
    /// so the per-PTask routing decision is made here, by hostname: the header's
    /// optional `:port` suffix is ignored and matching is case-insensitive,
    /// matching how a real `Host:` header arrives.
    #[must_use]
    pub fn resolve_route(&self, host_header: &str) -> Option<Route> {
        let host = host_component(host_header);
        self.by_host
            .get(&Hostname(host.to_ascii_lowercase()))
            .cloned()
    }
}

/// Extracts the host of a `Host:` header, stripping an optional `:port` suffix.
///
/// Handles both the common `name:port` form and the bracketed IPv6 literal
/// form (`[::1]:8080`), where the port follows the closing bracket rather than
/// the first colon. The registry only ever holds `*.min.internal` names, so an
/// IPv6 literal never routes; parsing it correctly keeps a naive split-on-first-
/// colon from silently truncating `[::1]` to `[`. Shared with [`super::proxy`],
/// which splits the same authority into host and port.
pub(crate) fn host_component(host_header: &str) -> &str {
    if host_header.starts_with('[') {
        // IPv6 literal: the host is everything up to and including the closing
        // bracket; any `:port` follows it.
        host_header
            .find(']')
            .map_or(host_header, |close| &host_header[..=close])
    } else {
        // `name` or `name:port`: the host ends at the first colon.
        host_header.split(':').next().unwrap_or(host_header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Proof artifact 1 (registry/proxy contract): registering a `HostNet`
    /// PTask makes the host-side proxy route its `Host:` header to `127.0.0.1`;
    /// deregistering withdraws it so the proxy no longer routes it. `*.min.internal`
    /// is synthesized to loopback statically by the resolver, so this asserts the
    /// registry/proxy routing contract, not a `getaddrinfo` lifecycle.
    #[test]
    fn host_net_registration_routes_by_host_header_then_withdraws() {
        let mut reg = HostnameRegistry::new("dev");

        let hostname = reg.register_host_net(SessionId::nil(), "myservice");
        assert_eq!(hostname.as_str(), "myservice.dev.min.internal");

        // The host-side proxy routes a request by its `Host:` header to the PTask
        // — with or without the `:port` a real header carries.
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            reg.resolve_route("myservice.dev.min.internal")
                .map(|r| r.target),
            Some(loopback)
        );
        assert_eq!(
            reg.resolve_route("myservice.dev.min.internal:8080")
                .map(|r| r.target),
            Some(loopback)
        );

        // After the session exits the entry is gone and the proxy no longer
        // routes it.
        let removed = reg
            .deregister("myservice")
            .expect("hostname was registered");
        assert_eq!(removed.as_str(), "myservice.dev.min.internal");
        assert_eq!(
            reg.resolve_route("myservice.dev.min.internal")
                .map(|r| r.target),
            None
        );
    }

    /// Under the published-loopback model an `OwnIp` PTask registers to
    /// `127.0.0.1` (R3.1) — the same target as a `HostNet` PTask — because it is
    /// reached through a gvproxy-published loopback port, not the switch IP. The
    /// client then uses the published external port in the authority.
    #[test]
    fn own_ip_registration_routes_to_loopback() {
        let mut reg = HostnameRegistry::new("dev");
        let hostname = reg.register_own_ip(SessionId::nil(), "web");
        assert_eq!(hostname.as_str(), "web.dev.min.internal");

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            reg.resolve_route("web.dev.min.internal").map(|r| r.target),
            Some(loopback)
        );
        // The published external port is carried in the authority; the registry
        // gates on the host only.
        assert_eq!(
            reg.resolve_route("web.dev.min.internal:18080")
                .map(|r| r.target),
            Some(loopback)
        );

        assert_eq!(
            reg.deregister("web").map(|h| h.as_str().to_string()),
            Some("web.dev.min.internal".to_string())
        );
        assert_eq!(
            reg.resolve_route("web.dev.min.internal").map(|r| r.target),
            None
        );
    }

    /// An `OwnIp` PTask's switch lease is present in the routing table only
    /// between attach (`set_own_ip_lease`) and teardown (`clear_own_ip_lease`),
    /// and while present it routes the hostname to the lease with the published
    /// external→internal port remap (G-N9 in-VM lease routing). Before attach
    /// and after teardown the entry is the loopback placeholder.
    #[test]
    fn own_ip_lease_is_published_only_between_attach_and_teardown() {
        let mut reg = HostnameRegistry::new("dev");
        let id = SessionId::nil();
        reg.register_own_ip(id, "web");

        // Before attach: the loopback placeholder, no remap.
        assert_eq!(
            reg.resolve_route("web.dev.min.internal:18080")
                .map(|r| r.target),
            Some(LOOPBACK)
        );
        assert_eq!(reg.route_for_session(id).map(|r| r.target), Some(LOOPBACK));

        // At attach: the live lease is published with the ingress port map.
        let lease = Ipv4Addr::new(100, 64, 0, 9);
        reg.set_own_ip_lease(id, lease, vec![(18080, 8080)]);
        let route = reg
            .resolve_route("web.dev.min.internal:18080")
            .expect("lease published");
        assert_eq!(route.target, IpAddr::V4(lease));
        // The published external port remaps to the PTask-internal port.
        assert_eq!(route.dial_port(18080), 8080);
        // An unmapped port passes through unchanged.
        assert_eq!(route.dial_port(9999), 9999);

        // At teardown: reverted to the loopback placeholder; the lease is gone.
        reg.clear_own_ip_lease(id);
        assert_eq!(
            reg.resolve_route("web.dev.min.internal:18080")
                .map(|r| r.target),
            Some(LOOPBACK)
        );
        assert_eq!(reg.route_for_session(id).map(|r| r.target), Some(LOOPBACK));
    }

    /// Publishing a lease for a session with no registered hostname (e.g. a
    /// `NoNet` PTask, which never registers) is a silent no-op, so the attach
    /// path can call it unconditionally.
    #[test]
    fn set_own_ip_lease_for_unregistered_session_is_a_noop() {
        let mut reg = HostnameRegistry::new("dev");
        reg.set_own_ip_lease(SessionId::nil(), Ipv4Addr::new(100, 64, 0, 9), vec![]);
        assert_eq!(reg.route_for_session(SessionId::nil()), None);
    }

    /// Port stripping handles both the common `name:port` form and the
    /// bracketed IPv6 literal form, where the port follows the closing bracket.
    /// The registry never holds an IPv6 literal, so this guards the parse from
    /// silently truncating `[::1]` to `[` at the first colon.
    #[test]
    fn host_component_strips_port_including_bracketed_ipv6() {
        assert_eq!(
            host_component("svc.dev.min.internal"),
            "svc.dev.min.internal"
        );
        assert_eq!(
            host_component("svc.dev.min.internal:8080"),
            "svc.dev.min.internal"
        );
        assert_eq!(host_component("[::1]:8080"), "[::1]");
        assert_eq!(host_component("[::1]"), "[::1]");
    }

    /// Deregistering a session that was never registered is a silent no-op, so
    /// the manager can call it unconditionally on session teardown.
    #[test]
    fn deregister_unknown_session_is_a_noop() {
        let mut reg = HostnameRegistry::new("dev");
        assert_eq!(reg.deregister("ghost"), None);
    }
}
