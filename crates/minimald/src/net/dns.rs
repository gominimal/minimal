//! In-memory PTask hostname registry: the host-side routing table for the B5
//! egress proxy (Unit 3, UC2a) on the native-Linux (DM2) path.
//!
//! ## `*.min.internal` + host-side egress proxy
//!
//! Open Question 1 of the networking spec is settled in favour of the spec's B5
//! model (re-scoped 2026-06-23, superseding spike #485's systemd-resolved
//! finding): a PTask's box name is `<session>.min.internal`, and both
//! resolution and routing stay **host-side**. The host resolver is never
//! consulted and `minimald` writes nothing to it — `*.min.internal` (the TLD is
//! an opaque label) is mapped internally by the host-side egress proxy
//! ([`super::proxy`]), which routes each incoming request to the right PTask by
//! its `Host:` header. This registry is the lookup table that proxy consults —
//! [`HostnameRegistry::resolve`] is the routing decision for a `Host:` header.
//! Because resolution is host-side, the no-systemd sandbox (hakoniwa) and
//! microVM (libkrun) runtimes never resolve anything, and the TLD choice is
//! irrelevant to correctness.
//!
//! The registry still answers for the former three-label zone
//! `<session>.<host-id>.min.internal` (default host id `local`), resolving it
//! to the same entry with a deprecation notice (NET-002), for one release.
//!
//! A route is where a request to the name forwards:
//!
//! - A `HostNet` PTask's listeners are on host loopback, so its name routes
//!   there (R3.6).
//! - An `OwnIp` PTask (R3.1) depends on where the daemon sits relative to the
//!   gvproxy switch. On a VM host (DM1/3/4) the daemon holds its own tap on the
//!   switch, so the name routes **straight to the box's lease** (NET-001), with
//!   the box's ingress declaration carried as an external→internal port map so
//!   a URL naming a published port reaches the internal one behind it. On a
//!   native host (DM2) the daemon is off the switch and the name keeps the
//!   **published-loopback** model: the box's gvproxy forwarder binds
//!   `127.0.0.1:<external>` → `lease:<internal>`, and the client selects the
//!   published external port. Either way the `OwnIp` name registers only once
//!   the attach path has reported the lease — a box with no lease has no
//!   address to route to.
//!
//! Covers R3.5 (structured register/deregister tracing) and R3.6 (`HostNet`
//! registration). The former systemd-resolved startup probe (R3.4) is removed by
//! the re-scope; an egress-proxy reachability check
//! ([`super::proxy::bind_listener`]) replaces it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use sessions::SessionId;

/// The DNS suffix every PTask box name carries (see the module docs).
pub const HOSTNAME_SUFFIX: &str = "min.internal";

/// Default `<host-id>` of the deprecated three-label zone: a stable short name
/// for this `minimald` instance. The host-id is configurable; this is the value
/// used when none is configured.
pub const DEFAULT_HOST_ID: &str = "local";

/// The loopback address a `HostNet` PTask's name routes to (R3.6), and the
/// published-loopback forwarder an `OwnIp` PTask keeps on a native host.
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A registered PTask box name of the form `<session>.min.internal`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Builds the two-label box name for a PTask. DNS names are
    /// case-insensitive, so the rendered form is lower-cased to keep lookups
    /// stable.
    fn for_ptask(session_name: &str) -> Self {
        Self(format!("{session_name}.{HOSTNAME_SUFFIX}").to_ascii_lowercase())
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

/// Where a box name routes: the upstream socket a request forwards on, and the
/// session that owns the name — what a request "resolved to", which the proxy's
/// refusal logs carry for the diagnostics bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    target: Target,
    session: String,
}

/// The upstream a [`Route`] forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    /// Host loopback: a `HostNet` box's listeners (R3.6) — and, on a native
    /// host, an `OwnIp` box's published-loopback forwarder, where the requested
    /// port is the published external one.
    Loopback,
    /// An `OwnIp` box at its lease on the switch (a VM host): the daemon is on
    /// the switch, so a request reaches the box itself instead of the guest
    /// loopback. `ports` is the box's ingress declaration as an
    /// external→internal map, so a URL naming a published port reaches the
    /// internal one behind it; a port outside the map passes through, because
    /// the whole box is directly addressable at its lease.
    Lease {
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    },
}

impl Route {
    /// A route to host loopback, owned by `session`.
    pub(crate) fn loopback(session: impl Into<String>) -> Self {
        Self {
            target: Target::Loopback,
            session: session.into(),
        }
    }

    /// A route to an `OwnIp` box at `lease`, owned by `session`, carrying the
    /// box's ingress declaration as an external→internal port map.
    pub(crate) fn lease(
        session: impl Into<String>,
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    ) -> Self {
        Self {
            target: Target::Lease { lease, ports },
            session: session.into(),
        }
    }

    /// The upstream socket a request for `port` forwards to.
    #[must_use]
    pub fn target(&self, port: u16) -> SocketAddr {
        match &self.target {
            Target::Loopback => SocketAddr::new(LOOPBACK, port),
            Target::Lease { lease, ports } => SocketAddr::new(
                IpAddr::V4(*lease),
                ports.get(&port).copied().unwrap_or(port),
            ),
        }
    }

    /// The session that owns the name — what a request to it resolved to.
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    /// The box address the name routes at, for the R3.5 tracing events.
    fn address(&self) -> IpAddr {
        match &self.target {
            Target::Loopback => LOOPBACK,
            Target::Lease { lease, .. } => IpAddr::V4(*lease),
        }
    }
}

/// A live registration: the box name minted for a session, plus the stable
/// `SessionId` carried in its R3.5 tracing events. The id is captured at
/// registration so `deregister` (keyed by the mutable session name) emits the
/// same stable identifier the `registered` event did.
#[derive(Debug, Clone)]
struct Registration {
    id: SessionId,
    hostname: Hostname,
}

/// The lease an `OwnIp` box attached with, kept by the stable `SessionId`: the
/// attach path reports it once, and every later registration of the session's
/// name (spawn, finalize, rename) routes against it until the session ends.
#[derive(Debug, Clone)]
struct OwnAddress {
    lease: Ipv4Addr,
    /// The box's ingress declaration as an external→internal port map.
    ports: BTreeMap<u16, u16>,
}

/// An in-memory registry of live PTask box names, owned by the sessions manager
/// (one per `minimald`). It maps each live PTask's box name to the route a
/// host-side proxy forwards its requests on, and tracks the reverse (session →
/// box name) so a name is withdrawn when its session exits.
#[derive(Debug)]
pub struct HostnameRegistry {
    /// The `<host-id>` of the deprecated three-label zone this registry still
    /// answers for (NET-002).
    host_id: String,
    /// Whether the daemon sits on the gvproxy switch (a VM host): an `OwnIp`
    /// box's route then targets its lease; on a native host it keeps the
    /// published-loopback model.
    on_switch: bool,
    /// box name → the route a host-side proxy forwards its requests on.
    by_host: HashMap<Hostname, Route>,
    /// session name → its live registration, for withdrawal on exit.
    by_session: HashMap<String, Registration>,
    /// Reported `OwnIp` leases, by stable session id (see [`OwnAddress`]).
    own: HashMap<SessionId, OwnAddress>,
}

impl HostnameRegistry {
    /// Creates an empty registry whose deprecated three-label zone uses the
    /// given `<host-id>`, and which routes `OwnIp` boxes by whether the daemon
    /// sits on the gvproxy switch (`on_switch` — a VM host).
    #[must_use]
    pub fn new(host_id: impl Into<String>, on_switch: bool) -> Self {
        Self {
            host_id: host_id.into(),
            on_switch,
            by_host: HashMap::new(),
            by_session: HashMap::new(),
            own: HashMap::new(),
        }
    }

    /// Registers `session_name`'s box name routing it along `route`, and
    /// returns the name. Emits the R3.5 `registered` tracing event.
    /// `session_id` is the stable, unique identifier carried in that event for
    /// log correlation; `session_name` is the registry key (mutable, and
    /// reusable after the session exits), so both are emitted.
    fn register(&mut self, session_id: SessionId, session_name: &str, route: Route) -> Hostname {
        let hostname = Hostname::for_ptask(session_name);
        let address = route.address();
        self.by_session.insert(
            session_name.to_string(),
            Registration {
                id: session_id,
                hostname: hostname.clone(),
            },
        );
        self.by_host.insert(hostname.clone(), route);
        tracing::info!(
            session_id = %session_id,
            session_name,
            hostname = %hostname,
            ip = %address,
            action = "registered",
            "registered PTask hostname"
        );
        hostname
    }

    /// Registers a `HostNet` PTask, routing its box name to host loopback
    /// (R3.6).
    pub fn register_host_net(&mut self, session_id: SessionId, session_name: &str) -> Hostname {
        self.register(session_id, session_name, Route::loopback(session_name))
    }

    /// Registers an `OwnIp` PTask **once its lease exists** (R3.1, NET-001):
    /// the route reads the lease the attach path reported for this stable
    /// session id, and nothing is registered when there is none — a box with
    /// no lease has no address to route to. The session actor calls this at
    /// spawn, finalize, and rename; the attach path reports the lease with
    /// [`Self::report_own_address`] as soon as the box attaches.
    pub fn register_own_ip(
        &mut self,
        session_id: SessionId,
        session_name: &str,
    ) -> Option<Hostname> {
        let own = self.own.get(&session_id)?;
        let route = self.own_route(session_name, own);
        Some(self.register(session_id, session_name, route))
    }

    /// Reports the lease an `OwnIp` box attached with (from the attach path)
    /// and registers the session's box name against it now, so the name routes
    /// exactly when the box is reachable. The lease is kept by the stable
    /// `session_id` — a later rename re-registers against the same lease
    /// without a fresh report — until [`Self::forget_own_address`] drops it at
    /// session end.
    pub fn report_own_address(
        &mut self,
        session_id: SessionId,
        session_name: &str,
        lease: Ipv4Addr,
        ports: BTreeMap<u16, u16>,
    ) -> Hostname {
        let own = OwnAddress { lease, ports };
        let route = self.own_route(session_name, &own);
        self.own.insert(session_id, own);
        self.register(session_id, session_name, route)
    }

    /// Drops an ended session's lease fact. The route itself was already
    /// withdrawn by [`Self::deregister`]; this keeps the registry from
    /// outliving the box it pointed at, so a later session reusing the stable
    /// id — or the name — cannot route at a dead address. Not called by
    /// `deregister` itself: a rename withdraws and re-registers against the
    /// same lease.
    pub fn forget_own_address(&mut self, session_id: SessionId) {
        self.own.remove(&session_id);
    }

    /// The route an `OwnIp` box's name follows: straight to the lease on a VM
    /// host (the daemon is on the switch, NET-001), or the published-loopback
    /// model on a native host (the daemon is off the switch, and the client
    /// selects the published external port).
    fn own_route(&self, session_name: &str, own: &OwnAddress) -> Route {
        if self.on_switch {
            Route::lease(session_name, own.lease, own.ports.clone())
        } else {
            Route::loopback(session_name)
        }
    }

    /// Withdraws `session_name`'s box name, returning it if one was registered.
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
            ip = %route.address(),
            action = "deregistered",
            "deregistered PTask hostname"
        );
        Some(hostname)
    }

    /// Resolves a `Host:` header to the route a host-side proxy forwards the
    /// request on, or `None` if no live PTask owns that name.
    ///
    /// This is the registry/proxy contract: the per-PTask routing decision is
    /// made here, by hostname. The deprecated three-label form
    /// `<name>.<host-id>.min.internal` resolves to the same entry as
    /// `<name>.min.internal` (NET-002), with a deprecation notice naming the
    /// two-label form — one info line per deprecated three-label request,
    /// routed or not; a refused one is also named by the proxy's refusal warn
    /// line. The header's optional `:port` suffix is ignored and matching is
    /// case-insensitive, matching how a real `Host:` header arrives.
    #[must_use]
    pub fn resolve(&self, host_header: &str) -> Option<Route> {
        let host = host_component(host_header).to_ascii_lowercase();
        let mut route = self.by_host.get(&Hostname(host.clone())).cloned();
        if route.is_none()
            && let Some(two_label) = self.legacy_two_label(&host)
        {
            tracing::info!(
                component = "dns-proxy",
                host,
                two_label,
                "deprecated three-label hostname; use the two-label form"
            );
            route = self.by_host.get(&Hostname(two_label)).cloned();
        }
        route
    }

    /// The two-label name a deprecated three-label one maps to, when `host` is
    /// of the `<name>.<host-id>.min.internal` form (NET-002). The `<host-id>`
    /// label must equal this registry's own: a dotted session name (e.g.
    /// `my.app`) renders the two-label name `my.app.<host-id>.min.internal`,
    /// and a suffix match alone would strip the wrong label. A name that is
    /// both a live session's two-label name and a legacy form is unambiguous
    /// only while that session is live — exact lookups win, so a live dotted
    /// name routes to itself and only falls back to the legacy reading once it
    /// is withdrawn.
    fn legacy_two_label(&self, host: &str) -> Option<String> {
        let legacy_suffix = format!(".{}.{}", self.host_id, HOSTNAME_SUFFIX);
        host.strip_suffix(&legacy_suffix)
            .filter(|name| !name.is_empty())
            .map(|name| format!("{name}.{HOSTNAME_SUFFIX}"))
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

    /// A lease an attach path would report, with an `18080:8080` ingress
    /// declaration behind it.
    fn leased_ports() -> BTreeMap<u16, u16> {
        BTreeMap::from([(18080, 8080)])
    }

    /// Proof artifact 1 (registry/proxy contract): registering a `HostNet`
    /// PTask makes the host-side proxy route its `Host:` header to `127.0.0.1`;
    /// deregistering withdraws it so the proxy no longer routes it. `*.min.internal`
    /// is synthesized to loopback statically by the resolver, so this asserts the
    /// registry/proxy routing contract, not a `getaddrinfo` lifecycle.
    #[test]
    fn host_net_registration_routes_by_host_header_then_withdraws() {
        let mut reg = HostnameRegistry::new("dev", false);

        let hostname = reg.register_host_net(SessionId::nil(), "myservice");
        assert_eq!(hostname.as_str(), "myservice.min.internal");

        // The host-side proxy routes a request by its `Host:` header to the PTask
        // — with or without the `:port` a real header carries.
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        assert_eq!(
            reg.resolve("myservice.min.internal")
                .map(|r| r.target(8080)),
            Some(loopback)
        );
        assert_eq!(
            reg.resolve("myservice.min.internal:8080")
                .map(|r| r.target(8080)),
            Some(loopback)
        );
        assert_eq!(
            reg.resolve("myservice.min.internal")
                .map(|r| r.session().to_string()),
            Some("myservice".to_string())
        );

        // After the session exits the entry is gone and the proxy no longer
        // routes it.
        let removed = reg
            .deregister("myservice")
            .expect("hostname was registered");
        assert_eq!(removed.as_str(), "myservice.min.internal");
        assert_eq!(reg.resolve("myservice.min.internal"), None);
    }

    /// An `OwnIp` name registers only once its lease exists (NET-001): before
    /// the attach path reports it there is nothing to route to, and after the
    /// report the route follows the deployment. On a native host (off the
    /// switch) that is the published-loopback model — the requested port is the
    /// published external one (R3.1). The lease is kept by the stable session
    /// id, so a rename re-registers without a fresh report, and only the
    /// session's end drops it.
    #[test]
    fn own_ip_name_registers_once_the_lease_is_reported() {
        let mut reg = HostnameRegistry::new("dev", false);

        // No lease yet: the name registers nothing.
        assert!(reg.register_own_ip(SessionId::nil(), "web").is_none());
        assert_eq!(reg.resolve("web.min.internal"), None);

        // The attach path reports the lease with the box's ingress declaration.
        let hostname =
            reg.report_own_address(SessionId::nil(), "web", Ipv4Addr::LOCALHOST, leased_ports());
        assert_eq!(hostname.as_str(), "web.min.internal");

        // The published external port is carried in the URL; on a native host
        // the forwarder is on loopback at that same published port.
        let route = reg
            .resolve("web.min.internal")
            .expect("routes after the report");
        assert_eq!(route.target(18080), SocketAddr::new(loopback_addr(), 18080));
        assert_eq!(route.session(), "web");

        // A rename withdraws and re-registers against the same lease.
        reg.deregister("web");
        assert!(reg.register_own_ip(SessionId::nil(), "web").is_some());
        assert!(reg.resolve("web.min.internal").is_some());

        // At session end the fact is dropped: the name is withdrawn and
        // nothing routes anymore.
        reg.forget_own_address(SessionId::nil());
        assert_eq!(
            reg.deregister("web").map(|h| h.as_str().to_string()),
            Some("web.min.internal".to_string())
        );
        assert!(reg.register_own_ip(SessionId::nil(), "web").is_none());
        assert_eq!(reg.resolve("web.min.internal"), None);
    }

    /// The loopback a published-loopback route targets.
    fn loopback_addr() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// On a VM host (the daemon on the switch) an `OwnIp` box's name routes
    /// straight to its lease, translating the published external port through
    /// the ingress declaration's external→internal map; a port outside the map
    /// passes through (NET-001).
    #[test]
    fn own_ip_on_a_vm_host_routes_to_the_lease_through_the_ingress_map() {
        let mut reg = HostnameRegistry::new("dev", true);
        let lease = std::net::Ipv4Addr::new(100, 64, 0, 7);
        reg.report_own_address(SessionId::nil(), "web", lease, leased_ports());

        let route = reg.resolve("web.min.internal:18080").expect("routes");
        assert_eq!(
            route.target(18080),
            SocketAddr::new(IpAddr::V4(lease), 8080)
        );
        // A port the ingress declaration does not publish passes through.
        assert_eq!(route.target(9000), SocketAddr::new(IpAddr::V4(lease), 9000));
        assert_eq!(route.session(), "web");
    }

    /// The deprecated three-label form resolves to the same entry as the
    /// two-label one (NET-002). Matching keys on the `<host-id>` label, so a
    /// dotted session name is not stripped at the wrong label.
    #[test]
    fn legacy_three_label_resolves_to_the_same_entry() {
        let mut reg = HostnameRegistry::new("local", false);
        reg.register_host_net(SessionId::nil(), "web");

        let legacy = reg
            .resolve("web.local.min.internal")
            .expect("legacy form routes");
        assert_eq!(legacy.session(), "web");
        assert_eq!(
            reg.resolve("web.min.internal"),
            Some(legacy),
            "both forms resolve to the same entry"
        );

        // With an `:port` suffix, as a real header carries.
        assert!(reg.resolve("web.local.min.internal:8080").is_some());
        // An unknown session's legacy form does not route.
        assert_eq!(reg.resolve("ghost.local.min.internal"), None);
        // The bare `<host-id>.min.internal` is not a legacy session name.
        assert_eq!(reg.resolve("local.min.internal"), None);
    }

    /// Port stripping handles both the common `name:port` form and the
    /// bracketed IPv6 literal form, where the port follows the closing bracket.
    /// The registry never holds an IPv6 literal, so this guards the parse from
    /// silently truncating `[::1]` to `[` at the first colon.
    #[test]
    fn host_component_strips_port_including_bracketed_ipv6() {
        assert_eq!(host_component("svc.min.internal"), "svc.min.internal");
        assert_eq!(host_component("svc.min.internal:8080"), "svc.min.internal");
        assert_eq!(host_component("[::1]:8080"), "[::1]");
        assert_eq!(host_component("[::1]"), "[::1]");
    }

    /// Deregistering a session that was never registered is a silent no-op, so
    /// the manager can call it unconditionally on session teardown.
    #[test]
    fn deregister_unknown_session_is_a_noop() {
        let mut reg = HostnameRegistry::new("dev", false);
        assert_eq!(reg.deregister("ghost"), None);
    }
}
