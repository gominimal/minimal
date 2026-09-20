//! In-memory PTask hostname registry: the host-side routing table for the B5
//! egress proxy (Unit 3, UC2a) on the native-Linux (DM2) path.
//!
//! ## `*.min.internal` + host-side egress proxy
//!
//! Open Question 1 of the networking spec is settled in favour of the spec's B5
//! model (re-scoped 2026-06-23, superseding spike #485's systemd-resolved
//! finding): a box name takes the form `<name>.min.internal` (NET-001), and
//! both resolution and routing stay **host-side**. The host resolver is
//! never consulted and `minimald` writes nothing to it — `*.min.internal` (the TLD
//! is an opaque label) is mapped internally by the host-side egress proxy
//! ([`super::proxy`]), which routes each incoming request to the right PTask by
//! its `Host:` header. This registry is the lookup table that proxy consults —
//! [`HostnameRegistry::resolve`] is the routing decision for a `Host:` header.
//! Because resolution is host-side, the no-systemd sandbox (hakoniwa) and
//! microVM (libkrun) runtimes never resolve anything, and the TLD choice is
//! irrelevant to correctness.
//!
//! The three-label `<name>.<host-id>.min.internal` zone this registry used to
//! mint is kept for one release: a request arriving in that form is rewritten to
//! the two-label name, routed, and named in a deprecation notice in the log
//! (NET-002). Only the host id this registry ships is rewritten, so a name in
//! some other zone routes no more than an unregistered one does.
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

/// The `<host-id>` of the deprecated `<name>.<host-id>.min.internal` zone
/// (NET-002). Box names carry no host id any more; this is the one whose legacy
/// zone the registry still rewrites and routes.
pub const DEFAULT_HOST_ID: &str = "local";

/// The loopback address a local-only (non-DM5) PTask hostname routes to (R3.6).
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A registered box name of the form `<name>.min.internal` (NET-001).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Builds the name for a box. DNS names are case-insensitive, so the
    /// rendered form is lower-cased to keep lookups stable.
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

/// Where a box name routes: the address a host-side proxy forwards its requests
/// to, and the session that owns the name. The two travel together so a refusal
/// taken after the name resolved can say which box it resolved to (NET-001).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The address the request forwards to.
    pub target: IpAddr,
    /// The session whose name this is.
    pub session: String,
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
    /// The `<host-id>` of the deprecated zone this registry still rewrites
    /// (NET-002); no name it mints carries it.
    legacy_host_id: String,
    /// box name → where a host-side proxy routes its requests.
    by_host: HashMap<Hostname, Route>,
    /// session name → its live registration, for withdrawal on exit.
    by_session: HashMap<String, Registration>,
}

impl HostnameRegistry {
    /// Creates an empty registry that also rewrites the given `<host-id>`'s
    /// deprecated zone (NET-002); the names it mints are two-label.
    #[must_use]
    pub fn new(legacy_host_id: impl Into<String>) -> Self {
        Self {
            legacy_host_id: legacy_host_id.into(),
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
        let hostname = Hostname::for_ptask(session_name);
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
                session: session_name.to_string(),
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

    /// Resolves a `Host:` header to where a host-side proxy routes the request,
    /// or `None` if no live box owns that name (NET-001).
    ///
    /// This is the registry/proxy contract: every `*.min.internal` name resolves to
    /// loopback in the DNS layer, so the per-box routing decision is made here,
    /// by name. The header's optional `:port` suffix is ignored and matching is
    /// case-insensitive, matching how a real `Host:` header arrives. A header in
    /// the deprecated three-label zone is rewritten to its two-label name and
    /// resolved as that name, with one deprecation notice per request (NET-002).
    #[must_use]
    pub fn resolve(&self, host_header: &str) -> Option<Route> {
        let asked = host_component(host_header).to_ascii_lowercase();
        let name = match self.rewrite_legacy(&asked) {
            Some(two_label) => {
                tracing::info!(
                    component = "dns-proxy",
                    host = asked.as_str(),
                    routed_as = two_label.as_str(),
                    deprecation = "the <name>.<host-id>.min.internal zone is deprecated for one \
                                   release; use <name>.min.internal",
                    "routed a deprecated three-label box name"
                );
                two_label
            }
            None => asked,
        };
        self.by_host.get(&Hostname(name)).cloned()
    }

    /// Rewrites a `<name>.<host-id>.min.internal` header in this registry's
    /// deprecated zone to its two-label form, or `None` when the name is not in
    /// that zone (NET-002). `host` is already lower-cased and port-stripped.
    ///
    /// Only this registry's own host id is rewritten: a name in a zone the host
    /// never shipped is nobody's box, so it routes no more than an unregistered
    /// name does.
    fn rewrite_legacy(&self, host: &str) -> Option<String> {
        let zone = host.strip_suffix(HOSTNAME_SUFFIX)?.strip_suffix('.')?;
        let label = zone
            .strip_suffix(&self.legacy_host_id)?
            .strip_suffix('.')
            .filter(|label| !label.is_empty())?;
        Some(format!("{label}.{HOSTNAME_SUFFIX}"))
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

/// What the relay reads from one resolver answer (NET-066): the name the box
/// asked for, the IPv4 addresses the answer section holds for it, and the
/// shortest of their TTLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedName {
    /// The question name, lower-cased and without its trailing dot.
    pub name: String,
    /// Every A record in the answer section, in wire order. The owner names
    /// are not checked against the question: a CNAME chain leaves the A
    /// records under another owner, and what the resolver answered for the
    /// question is what the box will connect to.
    pub addresses: Vec<Ipv4Addr>,
    /// The shortest TTL among those records, in seconds.
    pub ttl: u32,
}

/// The A record type and the IN class, as a DNS answer spells them.
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
/// How many compression pointers one name may follow; a hostile answer that
/// loops its pointers is cut off here rather than spun on.
const MAX_POINTER_HOPS: usize = 16;

/// Parses a DNS message `payload` (the UDP body) as a successful response
/// carrying at least one A record, or `None` for anything else: a query, an
/// error rcode, a message cut short, or an answer with no address in it.
/// Length-checked at every step so a truncated or hostile message yields
/// `None` rather than an out-of-bounds read.
#[must_use]
pub fn parse_resolved_name(payload: &[u8]) -> Option<ResolvedName> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = flags & 0x8000 != 0;
    let rcode = flags & 0x000f;
    if !is_response || rcode != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 || ancount == 0 {
        return None;
    }

    let (name, next) = read_name(payload, 12)?;
    // The question's type and class, then any further questions (skipped).
    let mut pos = next + 4;
    for _ in 1..qdcount {
        let (_, next) = read_name(payload, pos)?;
        pos = next + 4;
    }

    let mut addresses = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..ancount {
        let (_, next) = read_name(payload, pos)?;
        let fixed = payload.get(next..next + 10)?;
        let rtype = u16::from_be_bytes([fixed[0], fixed[1]]);
        let rclass = u16::from_be_bytes([fixed[2], fixed[3]]);
        let rttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let rdlength = usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let rdata = payload.get(next + 10..next + 10 + rdlength)?;
        if rtype == TYPE_A && rclass == CLASS_IN && rdlength == 4 {
            addresses.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            ttl = ttl.min(rttl);
        }
        pos = next + 10 + rdlength;
    }
    if addresses.is_empty() {
        return None;
    }
    Some(ResolvedName {
        name,
        addresses,
        ttl,
    })
}

/// Reads the name at `pos`, following compression pointers, and returns it
/// lower-cased with the position just past the name's bytes at `pos` (a
/// pointer ends the name in place). `None` for a name that runs off the
/// message, a label that is neither plain nor a pointer, or a pointer chain
/// past [`MAX_POINTER_HOPS`].
fn read_name(payload: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut after: Option<usize> = None;
    let mut hops = 0;
    loop {
        let len = *payload.get(pos)?;
        match len {
            0 => {
                let end = after.unwrap_or(pos + 1);
                return Some((labels.join("."), end));
            }
            l if l & 0xc0 == 0xc0 => {
                let low = *payload.get(pos + 1)?;
                if after.is_none() {
                    after = Some(pos + 2);
                }
                hops += 1;
                if hops > MAX_POINTER_HOPS {
                    return None;
                }
                pos = usize::from(u16::from_be_bytes([l & 0x3f, low]));
            }
            l if l & 0xc0 == 0 => {
                let label = payload.get(pos + 1..pos + 1 + usize::from(l))?;
                labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
                pos += 1 + usize::from(l);
            }
            _ => return None,
        }
    }
}

/// Whether `name` is matched by one of a box's `egress.allow_dns_hosts`
/// entries. An entry matches its own name exactly, and an entry written
/// `*.example.com` matches every name below `example.com` (not the apex);
/// both are compared case-insensitively and without a trailing dot.
#[must_use]
pub fn name_allowed(rules: &[String], name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    rules.iter().any(|rule| {
        let rule = rule.trim_end_matches('.').to_ascii_lowercase();
        match rule.strip_prefix("*.") {
            Some(suffix) => name
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
            None => name == rule,
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A response for `question` whose answer section holds `records`
    /// (`(ttl, address)`), each owned by a pointer back to the question name.
    pub(crate) fn dns_response(question: &str, records: &[(u32, Ipv4Addr)]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
        for label in question.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        for (ttl, addr) in records {
            m.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
            m.extend_from_slice(&[0, 1, 0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]);
            m.extend_from_slice(&addr.octets());
        }
        m
    }

    /// NET-066: a resolver answer yields the question name, every A record
    /// and the shortest TTL; a CNAME ahead of the A record is skipped by its
    /// length, not misread.
    #[test]
    fn parse_resolved_name_reads_question_addresses_and_shortest_ttl() {
        let a = Ipv4Addr::new(140, 82, 112, 3);
        let b = Ipv4Addr::new(140, 82, 112, 4);
        let parsed = parse_resolved_name(&dns_response("GitHub.com", &[(60, a), (30, b)])).unwrap();
        assert_eq!(
            parsed,
            ResolvedName {
                name: "github.com".into(),
                addresses: vec![a, b],
                ttl: 30,
            }
        );

        let mut chained = dns_response("www.example.com", &[]);
        chained[6..8].copy_from_slice(&2u16.to_be_bytes());
        // CNAME www.example.com -> "x" (rdata: one label, root), TTL 10.
        chained.extend_from_slice(&[0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 10, 0, 3, 1, b'x', 0]);
        let x = chained.len() - 3;
        // A record owned by "x" (a pointer to the CNAME's rdata), TTL 20.
        chained.extend_from_slice(&[0xc0, x as u8, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4, 1, 2, 3, 4]);
        let parsed = parse_resolved_name(&chained).unwrap();
        assert_eq!(parsed.name, "www.example.com");
        assert_eq!(parsed.addresses, vec![Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(parsed.ttl, 20);
    }

    /// A query, an error, a message cut short, a looping pointer and an answer
    /// with no A record all parse to nothing.
    #[test]
    fn parse_resolved_name_rejects_what_is_not_a_usable_answer() {
        let good = dns_response("github.com", &[(60, Ipv4Addr::new(140, 82, 112, 3))]);
        let mut query = good.clone();
        query[2] = 0x01;
        assert!(parse_resolved_name(&query).is_none());
        let mut nxdomain = good.clone();
        nxdomain[3] = 0x83;
        assert!(parse_resolved_name(&nxdomain).is_none());
        for cut in [0, 11, 20, good.len() - 1] {
            assert!(parse_resolved_name(&good[..cut]).is_none(), "len {cut}");
        }
        // The answer's owner pointer made to point at itself.
        let mut looping = good.clone();
        let owner = 12 + "github.com".len() + 2 + 4;
        assert_eq!(looping[owner], 0xc0);
        looping[owner + 1] = owner as u8;
        assert!(parse_resolved_name(&looping).is_none());
        assert!(parse_resolved_name(&dns_response("github.com", &[])).is_none());
    }

    #[test]
    fn name_allowed_matches_exactly_or_below_a_wildcard() {
        let rules = vec![
            "github.com".to_string(),
            "*.githubusercontent.com".to_string(),
        ];
        assert!(name_allowed(&rules, "github.com"));
        assert!(name_allowed(&rules, "GitHub.COM."));
        assert!(!name_allowed(&rules, "api.github.com"));
        assert!(!name_allowed(&rules, "notgithub.com"));
        assert!(name_allowed(&rules, "raw.githubusercontent.com"));
        assert!(name_allowed(&rules, "a.b.githubusercontent.com"));
        assert!(!name_allowed(&rules, "githubusercontent.com"));
        assert!(!name_allowed(&rules, "xgithubusercontent.com"));
        assert!(!name_allowed(&[], "github.com"));
    }

    /// Proof artifact 1 (registry/proxy contract): registering a `HostNet`
    /// PTask makes the host-side proxy route its two-label `Host:` header to
    /// `127.0.0.1`; deregistering withdraws it so the proxy no longer routes it.
    /// `*.min.internal` is synthesized to loopback statically by the resolver, so
    /// this asserts the registry/proxy routing contract, not a `getaddrinfo`
    /// lifecycle.
    #[test]
    fn host_net_registration_routes_by_host_header_then_withdraws() {
        let mut reg = HostnameRegistry::new("dev");

        let hostname = reg.register_host_net(SessionId::nil(), "myservice");
        assert_eq!(hostname.as_str(), "myservice.min.internal");

        // The host-side proxy routes a request by its `Host:` header to the PTask
        // — with or without the `:port` a real header carries.
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            reg.resolve("myservice.min.internal").map(|r| r.target),
            Some(loopback)
        );
        assert_eq!(
            reg.resolve("myservice.min.internal:8080").map(|r| r.target),
            Some(loopback)
        );
        // The route names the session it belongs to, so a refusal taken after
        // the name resolved can say which box it resolved to.
        assert_eq!(
            reg.resolve("myservice.min.internal").map(|r| r.session),
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

    /// NET-002: a header in the deprecated `<name>.<host-id>.min.internal` zone
    /// resolves as the two-label name, and only for the host id this registry
    /// ships — a name in some other zone is nobody's box.
    #[test]
    fn legacy_zone_header_resolves_as_the_two_label_name() {
        let mut reg = HostnameRegistry::new("local");
        reg.register_host_net(SessionId::nil(), "web");

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            reg.resolve("web.local.min.internal").map(|r| r.target),
            Some(loopback)
        );
        assert_eq!(
            reg.resolve("web.local.min.internal:8080").map(|r| r.target),
            Some(loopback)
        );
        // Another host id's zone is not this host's, so it does not route.
        assert_eq!(reg.resolve("web.other.min.internal"), None);
        // The host id alone is not a box name.
        assert_eq!(reg.resolve("local.min.internal"), None);
    }

    /// Under the published-loopback model an `OwnIp` PTask registers to
    /// `127.0.0.1` (R3.1) — the same target as a `HostNet` PTask — because it is
    /// reached through a gvproxy-published loopback port, not the switch IP. The
    /// client then uses the published external port in the authority.
    #[test]
    fn own_ip_registration_routes_to_loopback() {
        let mut reg = HostnameRegistry::new("dev");
        let hostname = reg.register_own_ip(SessionId::nil(), "web");
        assert_eq!(hostname.as_str(), "web.min.internal");

        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(
            reg.resolve("web.min.internal").map(|r| r.target),
            Some(loopback)
        );
        // The published external port is carried in the authority; the registry
        // gates on the host only.
        assert_eq!(
            reg.resolve("web.min.internal:18080").map(|r| r.target),
            Some(loopback)
        );

        assert_eq!(
            reg.deregister("web").map(|h| h.as_str().to_string()),
            Some("web.min.internal".to_string())
        );
        assert_eq!(reg.resolve("web.min.internal"), None);
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
        let mut reg = HostnameRegistry::new("dev");
        assert_eq!(reg.deregister("ghost"), None);
    }
}
