//! The host-resolver side of in-zone name resolution (NET-122, NET-123).
//!
//! A daemon answers `*.{ZONE}` lookups from a UDP answerer it holds on the
//! host's loopback; the host's *native* resolver has to be pointed at that
//! answerer before any process on the host can resolve a box name with no
//! proxy settings (NET-009). The hook that points it is per-OS: a resolver
//! file under `/etc/resolver/` on macOS, a systemd-resolved routing domain
//! on a routable link on Linux. This module detects the hook, renders the
//! exact command that installs it, and reads the reserved range's loopback
//! state for the diagnostic bundle.
//!
//! Nothing here prompts. Detecting reads files and runs `resolvectl`
//! read-only; the advisory is pure string assembly over what those reads
//! found. The privilege prompt, when there is one, belongs to the command
//! the user chooses to copy and run — never to a session start (NET-122:
//! "with no privilege prompt"; NET-123's interim arm: neither prompt nor
//! hang).

use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

/// The zone the daemon's answerer holds. Mirrors
/// `minimald::net::dns::HOSTNAME_SUFFIX`; the CLI does not depend on the
/// daemon crate, so the two constants move together.
pub(crate) const ZONE: &str = "min.internal";

/// The reserved local range the daemon publishes per-box addresses from and
/// whose presence at session start NET-123's bind probe verifies. Mirrors
/// `minimald::net::dns::RESERVED_LOCAL_RANGE` — the probe here and the
/// publish there must agree on the range, so the constants move together.
pub(crate) const RESERVED_LOCAL_RANGE: (Ipv4Addr, u8) = (Ipv4Addr::new(127, 64, 0, 0), 24);

/// The resolver file the advisory's command writes on macOS. `nameserver`
/// plus `port` is the format the loopback-alias spike verified against
/// mDNSResponder (docs/spikes/2026-09-22-macos-loopback-alias.md).
#[cfg(any(test, target_os = "macos"))]
pub(crate) const RESOLVER_FILE: &str = "/etc/resolver/min.internal";

/// The state of the host resolver's hook for [`ZONE`]: what was read, and
/// the port it points the zone's lookups at, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Hook {
    /// What was read: the resolver file (macOS), the link carrying the
    /// routing domain (Linux), or the reason nothing could be read.
    pub source: String,
    /// The port the hook points the zone's lookups at, when the state
    /// names one.
    pub port: Option<u16>,
    /// One line describing the state, for the advisory and the bundle.
    pub detail: String,
}

impl Hook {
    fn configured(source: impl Into<String>, port: Option<u16>, detail: impl Into<String>) -> Self {
        Hook {
            source: source.into(),
            port,
            detail: detail.into(),
        }
    }

    fn absent(source: impl Into<String>, detail: impl Into<String>) -> Self {
        Hook {
            source: source.into(),
            port: None,
            detail: detail.into(),
        }
    }

    /// Whether this hook routes [`ZONE`] lookups to the answerer on
    /// `answerer_port` — the one condition NET-122's advisory stays quiet
    /// under (once the interim is out of the picture).
    pub(crate) fn routes(&self, answerer_port: u16) -> bool {
        self.port == Some(answerer_port)
    }
}

/// The value of the first `<key> <value>` directive in a resolver file, if
/// any. A bare word that only *starts* with the key is not a directive.
#[cfg(any(test, target_os = "macos"))]
fn directive<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().map(str::trim).find_map(|line| {
        let (directive, value) = line.split_once(char::is_whitespace)?;
        (directive == key).then_some(value.trim())
    })
}

/// The macOS hook: parse a `/etc/resolver/min.internal` file's contents
/// (or `None` for its absence) into a [`Hook`]. Pure, so it is unit-tested
/// on every platform the suite runs on.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn resolver_file_hook(contents: Option<&str>) -> Hook {
    let Some(text) = contents else {
        return Hook::absent(
            RESOLVER_FILE,
            "no resolver file for the zone; the stub resolver does not carry the zone",
        );
    };
    match directive(text, "nameserver") {
        Some("127.0.0.1") => match directive(text, "port").and_then(|value| value.parse().ok()) {
            Some(port) => Hook::configured(
                RESOLVER_FILE,
                Some(port),
                format!("resolver file routes {ZONE} to 127.0.0.1:{port}"),
            ),
            None => Hook::configured(
                RESOLVER_FILE,
                None,
                "resolver file names 127.0.0.1 with no `port` directive; the host \
                 would ask on 53, where the answerer does not listen",
            ),
        },
        Some(other) => Hook::configured(
            RESOLVER_FILE,
            None,
            format!("resolver file nameserver is {other}, expected 127.0.0.1"),
        ),
        None => Hook::configured(
            RESOLVER_FILE,
            None,
            "resolver file has no `nameserver` directive",
        ),
    }
}

/// The interface named by a `resolvectl` line's `Link N (<iface>)` prefix.
#[cfg(any(test, not(target_os = "macos")))]
fn link_name(prefix: &str) -> Option<&str> {
    let start = prefix.find('(')? + 1;
    let end = prefix.rfind(')')?;
    prefix.get(start..end)
}

/// The first `resolvectl` line whose carried value satisfies `carries`, as
/// (`<link>`, `<value>`).
#[cfg(any(test, not(target_os = "macos")))]
fn link_line(output: &str, carries: impl Fn(&str) -> bool) -> Option<(&str, &str)> {
    output.lines().find_map(|line| {
        let (prefix, value) = line.split_once(':')?;
        let link = link_name(prefix)?;
        carries(value).then_some((link, value))
    })
}

/// The answerer port a link's `resolvectl dns` line names, when it points a
/// `127.0.0.1:<port>` server at it.
#[cfg(any(test, not(target_os = "macos")))]
fn answerer_port_on_link(dns_output: &str, link: &str) -> Option<u16> {
    for line in dns_output.lines() {
        let Some((prefix, servers)) = line.split_once(':') else {
            continue;
        };
        if link_name(prefix) != Some(link) {
            continue;
        }
        for token in servers.split_whitespace() {
            let Some((server, port)) = token.split_once(':') else {
                continue;
            };
            if let Ok(port) = port.parse()
                && server == "127.0.0.1"
            {
                return Some(port);
            }
        }
    }
    None
}

/// The Linux hook: parse `resolvectl domain` and `resolvectl dns` output
/// (either `None` when the call could not be made) into a [`Hook`]. Pure,
/// so it is unit-tested on every platform the suite runs on.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn routing_domain_hook(domain_output: Option<&str>, dns_output: Option<&str>) -> Hook {
    let Some(domain_output) = domain_output else {
        return Hook::absent(
            "systemd-resolved",
            "`resolvectl domain` did not run; the routing domain cannot be read",
        );
    };
    let Some((link, _)) = link_line(domain_output, |domains| {
        // The routing domain `~min.internal` is what the advisory's command
        // sets; the bare form routes the zone too, so it counts as a hook.
        domains
            .split_whitespace()
            .any(|domain| domain == ZONE || domain == format!("~{ZONE}"))
    }) else {
        return Hook::absent(
            "systemd-resolved",
            "no link carries a routing domain for the zone",
        );
    };
    let source = format!("systemd-resolved routing domain on {link}");
    let Some(dns_output) = dns_output else {
        return Hook::configured(
            source,
            None,
            "the link carries the routing domain but its DNS servers did not read",
        );
    };
    match answerer_port_on_link(dns_output, link) {
        Some(port) => Hook::configured(
            source,
            Some(port),
            format!("the routing domain routes {ZONE} to 127.0.0.1:{port}"),
        ),
        None => Hook::configured(
            source,
            None,
            "the link carries the routing domain but no 127.0.0.1:<port> server",
        ),
    }
}

/// One read-only `resolvectl` query, or `None` when the binary is missing,
/// the call failed, or its output is not UTF-8. Reading through
/// systemd-resolved's read API writes nothing, so it cannot prompt.
#[cfg(not(target_os = "macos"))]
async fn resolvectl(args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new("resolvectl")
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Reads the host's current hook state (NET-122). Detection is read-only and
/// never prompts: one file read on macOS, two `resolvectl` queries on Linux.
pub(crate) async fn detect() -> Hook {
    host_hook().await
}

#[cfg(target_os = "macos")]
async fn host_hook() -> Hook {
    match tokio::fs::read_to_string(RESOLVER_FILE).await {
        Ok(text) => resolver_file_hook(Some(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => resolver_file_hook(None),
        Err(e) => Hook::absent(RESOLVER_FILE, format!("resolver file unreadable: {e}")),
    }
}

#[cfg(not(target_os = "macos"))]
async fn host_hook() -> Hook {
    let domain = resolvectl(&["domain"]).await;
    let dns = resolvectl(&["dns"]).await;
    routing_domain_hook(domain.as_deref(), dns.as_deref())
}

/// The routable link named by a `/proc/net/route` table: the one carrying
/// the default route, else the first non-`lo` link with any route — the
/// routing domain has to live on a link of routable scope. Pure over the
/// table's text, so it is unit-tested on every platform the suite runs on.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn link_from_route_table(route_table: &str) -> Option<String> {
    let mut routed = None;
    for line in route_table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(destination)) = (fields.next(), fields.next()) else {
            continue;
        };
        if iface == "lo" {
            continue; // a loopback link is not of routable scope
        }
        if destination == "00000000" {
            return Some(iface.to_string()); // the default route's link
        }
        if routed.is_none() {
            routed = Some(iface.to_string());
        }
    }
    routed
}

/// The host's routable link, read from `/proc/net/route` — a read of a few
/// hundred bytes of procfs, paid once per advisory.
#[cfg(not(target_os = "macos"))]
fn routable_link() -> Option<String> {
    std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|table| link_from_route_table(&table))
}

/// The exact command that points macOS's resolver at the answerer: one
/// `sudo` writing the resolver file the zone's hook reads. `mkdir -p`
/// because `/etc/resolver` does not exist until the first hook does.
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn macos_command(port: u16) -> String {
    format!(
        "sudo sh -c 'mkdir -p /etc/resolver && printf \"nameserver 127.0.0.1\\nport {port}\\n\" \
         > {RESOLVER_FILE}'"
    )
}

/// The exact command that points systemd-resolved at the answerer: set the
/// link's DNS server, then the routing domain that scopes it to the zone.
/// `~{ZONE}` is single-quoted so the shell does not expand the tilde.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn linux_command(port: u16, link: Option<&str>) -> String {
    let link = link.unwrap_or("<link>");
    format!(
        "sudo resolvectl dns {link} 127.0.0.1:{port} && \
         sudo resolvectl domain {link} '~{ZONE}'"
    )
}

/// The exact command that configures this host's resolver for [`ZONE`] at
/// `port` — the command NET-122's advisory names.
#[cfg(target_os = "macos")]
pub(crate) fn command(port: u16) -> String {
    macos_command(port)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn command(port: u16) -> String {
    linux_command(port, routable_link().as_deref())
}

/// The advisory for one session start, as a function of the hook state and
/// the daemon's interim verdict (NET-122, NET-123's interim arm). Pure.
///
/// `None` — nothing to say — when the hook already routes the zone to this
/// answerer *and* the daemon did not publish at the interim. Otherwise the
/// advisory says what is missing and names the exact command. The interim
/// re-surfaces the advisory even when the hook routes (NET-123: "re-surface
/// the advisory of NET-122"): a session on the interim is a fact the user
/// has no other way to see, and the advisory command is the same privileged
/// step that ends it. String assembly only, bar the one procfs read
/// [`command`] makes on Linux to name the routable link.
pub(crate) fn advisory_at(hook: &Hook, port: u16, interim: bool) -> Option<String> {
    if hook.routes(port) && !interim {
        return None;
    }
    let mut facts = Vec::new();
    if interim {
        facts.push(format!(
            "this session publishes at the shared 127.0.0.1 interim: the \
             reserved local range {} is not installed on this host",
            range_text()
        ));
    }
    if !hook.routes(port) {
        facts.push(format!(
            "*.{ZONE} does not resolve in host processes: the host's \
             resolver is not configured for the zone ({})",
            hook.detail
        ));
    }
    let facts = facts.join("; ");
    let command = command(port);
    Some(format!(
        "note: {facts}. Configure the host's resolver for the zone with:\n  {command}"
    ))
}

/// The advisory to print at this session's start, given what the daemon
/// reported on its create response.
///
/// `zone_answerer_port` is `None` while the daemon is still bringing its
/// answerer up (or from a daemon predating the field, which the create's
/// version gate already refuses); there is then no port to point a command
/// at, so the advisory stays quiet rather than naming a command that
/// cannot work. `interim_loopback` is the daemon's NET-123 verdict: its
/// session-start bind probe found the reserved range absent and it
/// published this session at the 127.0.0.1 interim.
///
/// Printed once per session start, to stderr; never prompts.
pub(crate) async fn session_advisory(
    zone_answerer_port: Option<u16>,
    interim_loopback: bool,
) -> Option<String> {
    let port = zone_answerer_port?;
    let hook = detect().await;
    advisory_at(&hook, port, interim_loopback)
}

/// The reserved range as `network/prefix`, the form the advisory and the
/// bundle print.
fn range_text() -> String {
    let (network, prefix) = RESERVED_LOCAL_RANGE;
    format!("{network}/{prefix}")
}

/// The result of bind-probing the reserved local range: one
/// `TcpListener::bind((address, 0))` per usable host address, where
/// `EADDRNOTAVAIL` is what an absent loopback alias looks like. The CLI-side
/// twin of the daemon's NET-123 probe (`minimald::net::loopback`), restated
/// because the CLI does not depend on the daemon crate; a partial alias set
/// reads as absent, the same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BindProbe {
    /// How many addresses in the range accepted a bind.
    pub bound: usize,
    /// How many addresses were probed — every usable host address in the
    /// range.
    pub probed: usize,
    /// The first address that refused, and why, when one did.
    pub first_refusal: Option<(String, String)>,
}

impl BindProbe {
    /// The probe that never ran, for a worker that died: reads as absent.
    pub(crate) fn failed_to_run() -> Self {
        BindProbe {
            bound: 0,
            probed: 0,
            first_refusal: None,
        }
    }

    /// The whole range accepted binds: the loopback aliases are installed.
    pub(crate) fn present(&self) -> bool {
        self.bound == self.probed && self.probed > 0
    }

    /// The host is on the 127.0.0.1 interim (NET-123): the reserved range
    /// is absent, so the daemon publishes session names at the shared
    /// host loopback address.
    pub(crate) fn interim(&self) -> bool {
        !self.present()
    }
}

/// Bind-probe the reserved local range from this host: the same 254 usable
/// host addresses the daemon's probe covers. About 2.5ms for a /24;
/// blocking, so callers run it on a blocking thread.
pub(crate) fn probe_range() -> BindProbe {
    let (network, prefix) = RESERVED_LOCAL_RANGE;
    let mut probe = BindProbe {
        bound: 0,
        probed: 0,
        first_refusal: None,
    };
    // Host parts 1 through 254: the network and broadcast addresses are not
    // aliases a session would publish from.
    for host in 1..(1u32 << (32 - u32::from(prefix))) - 1 {
        let address = Ipv4Addr::from(u32::from(network) + host);
        probe.probed += 1;
        match TcpListener::bind(SocketAddrV4::new(address, 0)) {
            Ok(_) => probe.bound += 1,
            Err(e) => {
                probe
                    .first_refusal
                    .get_or_insert((address.to_string(), e.kind().to_string()));
            }
        }
    }
    probe
}

/// The host's naming surface for the diagnostic bundle: the resolver hook
/// state (the macOS resolver file or the Linux routing-domain link), the
/// loopback aliases the bind probe found, the probe's result, and whether
/// the host is on the 127.0.0.1 interim (NET-122, NET-123).
#[derive(Debug, Serialize)]
pub(crate) struct NamingSurface {
    /// The zone the hooks and the range serve.
    pub zone: &'static str,
    /// The reserved local range, as `network/prefix`.
    pub reserved_range: String,
    /// The host resolver's hook state for the zone.
    pub resolver_hook: Hook,
    /// Whether every address in the reserved range accepted a bind.
    pub loopback_aliases_present: bool,
    /// The bind probe that decided the aliases question.
    pub bind_probe: BindProbe,
    /// Whether the host is on the 127.0.0.1 interim.
    pub interim_loopback: bool,
}

/// Reads everything [`NamingSurface`] holds, for `min bug` to record.
pub(crate) async fn naming_surface() -> NamingSurface {
    let hook = detect().await;
    let probe = tokio::task::spawn_blocking(probe_range)
        .await
        .unwrap_or_else(|join| {
            tracing::warn!(
                error = %join,
                "the naming-surface bind probe did not run; treating the \
                 reserved local range as absent"
            );
            BindProbe::failed_to_run()
        });
    NamingSurface {
        zone: ZONE,
        reserved_range: range_text(),
        loopback_aliases_present: probe.present(),
        interim_loopback: probe.interim(),
        resolver_hook: hook,
        bind_probe: probe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fragments the advisory must carry on this platform: the exact
    /// command differs per OS, and each lane checks its own.
    #[cfg(target_os = "macos")]
    fn command_markers(port: u16) -> Vec<String> {
        vec![
            "sudo".into(),
            RESOLVER_FILE.into(),
            format!("port {port}"),
            "nameserver 127.0.0.1".into(),
        ]
    }

    #[cfg(not(target_os = "macos"))]
    fn command_markers(port: u16) -> Vec<String> {
        vec![
            "sudo resolvectl".into(),
            format!("127.0.0.1:{port}"),
            format!("'~{ZONE}'"),
        ]
    }

    // NET-122's test name. The advisory names the exact command and nothing
    // in its path prompts: every builder here is pure over strings and the
    // reads behind `detect` are read-only — no reader is ever opened, so
    // the "no privilege prompt" clause holds by construction and the
    // assertions below pin the text it produces.
    #[test]
    fn session_start_advises_resolver_command_without_prompt() {
        let port = 15353;
        // An unconfigured host is advised, with the exact command to run.
        let unconfigured = Hook::absent("test", "no hook for the zone");
        let advisory =
            advisory_at(&unconfigured, port, false).expect("an unconfigured host must be advised");
        for marker in command_markers(port) {
            assert!(
                advisory.contains(&marker),
                "the advisory must name the exact command ({marker}): {advisory}"
            );
        }
        assert!(
            !advisory.contains('?'),
            "an advisory never asks a question — it names a command: {advisory}"
        );

        // A hook already routing this answerer is not advised again.
        let configured = Hook::configured("test", Some(port), "routes the zone");
        assert!(
            advisory_at(&configured, port, false).is_none(),
            "a configured host must not be re-advised"
        );

        // A hook routing a *stale* port is advised: the command points the
        // resolver at this daemon's answerer, not the old one's.
        let stale = Hook::configured("test", Some(port - 1), "routes the zone elsewhere");
        let advisory = advisory_at(&stale, port, false)
            .expect("a stale hook must be re-advised for this answerer's port");
        for marker in command_markers(port) {
            assert!(
                advisory.contains(&marker),
                "the re-advice must name the exact command ({marker}): {advisory}"
            );
        }

        // NET-123's interim arm: a session published at the 127.0.0.1
        // interim re-surfaces the advisory even when the hook routes.
        let interim =
            advisory_at(&configured, port, true).expect("the interim must re-surface the advisory");
        assert!(
            interim.contains("127.0.0.1 interim"),
            "the interim advisory must name the interim: {interim}"
        );
        assert!(interim.contains(&range_text()));
        for marker in command_markers(port) {
            assert!(
                interim.contains(&marker),
                "the interim advisory must name the exact command ({marker}): {interim}"
            );
        }
    }

    // The full path on this host: whatever `detect` finds, the advisory
    // either stays quiet because the hook already routes the port, or
    // names this platform's exact command. Either arm is a pass; only the
    // mismatch — advised without a command, or quiet while unconfigured —
    // fails.
    #[tokio::test]
    async fn session_advisory_agrees_with_the_hook_it_detected() {
        let port = 15353;
        let hook = detect().await;
        let advisory = session_advisory(Some(port), false).await;
        if hook.routes(port) {
            assert!(advisory.is_none(), "configured host must not be advised");
        } else {
            let advisory = advisory.expect("an unconfigured host must be advised");
            for marker in command_markers(port) {
                assert!(
                    advisory.contains(&marker),
                    "the advisory must name this host's exact command ({marker}): {advisory}"
                );
            }
        }
    }

    #[tokio::test]
    async fn session_advisory_without_a_port_stays_quiet() {
        // `None` is the daemon still bringing its answerer up — there is no
        // port to point a command at, so nothing is printed rather than a
        // command that cannot work.
        assert!(session_advisory(None, false).await.is_none());
    }

    #[cfg(any(test, target_os = "macos"))]
    #[test]
    fn resolver_file_hook_parses_nameserver_and_port() {
        let hook = resolver_file_hook(Some("nameserver 127.0.0.1\nport 15353\n"));
        assert_eq!(hook.port, Some(15353));
        assert!(hook.routes(15353));
        assert!(!hook.routes(15354));
    }

    #[cfg(any(test, target_os = "macos"))]
    #[test]
    fn resolver_file_hook_states_its_gaps() {
        assert_eq!(resolver_file_hook(None).port, None);
        assert!(
            resolver_file_hook(Some("search example.com\n"))
                .detail
                .contains("no `nameserver` directive"),
            "a file without a nameserver says so"
        );
        let no_port = resolver_file_hook(Some("nameserver 127.0.0.1\n"));
        assert_eq!(no_port.port, None);
        assert!(
            no_port.detail.contains("no `port` directive"),
            "{}",
            no_port.detail
        );
        let other = resolver_file_hook(Some("nameserver 10.0.0.1\nport 15353\n"));
        assert_eq!(other.port, None, "a foreign nameserver does not route here");
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn routing_domain_hook_finds_the_carrying_link_and_its_port() {
        let domain = "Global Domains: ~.\nLink 2 (enp3s0): ~min.internal\nLink 3 (wlp3s0): lab.example.com\n";
        let dns = "Global: 10.0.0.1\nLink 2 (enp3s0): 127.0.0.1:15353\nLink 3 (wlp3s0): 192.168.1.1 1.1.1.1\n";
        let hook = routing_domain_hook(Some(domain), Some(dns));
        assert_eq!(hook.port, Some(15353));
        assert!(hook.routes(15353));
        assert!(
            hook.source.contains("enp3s0"),
            "the hook names the carrying link: {}",
            hook.source
        );
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn routing_domain_hook_states_its_gaps() {
        let domain = "Global Domains: ~.\nLink 3 (wlp3s0): lab.example.com\n";
        let absent = routing_domain_hook(Some(domain), None);
        assert_eq!(absent.port, None);
        assert!(
            absent.detail.contains("no link carries"),
            "{}",
            absent.detail
        );

        assert_eq!(routing_domain_hook(None, None).port, None);

        // The bare (search-and-routing) form of the zone still routes it.
        let domain = "Link 2 (enp3s0): min.internal\n";
        let dns = "Link 2 (enp3s0): 1.1.1.1 127.0.0.1:15353\n";
        let hook = routing_domain_hook(Some(domain), Some(dns));
        assert_eq!(hook.port, Some(15353));

        // A carrying link whose DNS server is not the answerer is a hook
        // that does not route — the advisory must say so, not stay quiet.
        let dns = "Link 2 (enp3s0): 192.168.1.1\n";
        let hook = routing_domain_hook(Some(domain), Some(dns));
        assert_eq!(hook.port, None);
        assert!(hook.detail.contains("no 127.0.0.1"), "{}", hook.detail);
    }

    #[cfg(any(test, target_os = "macos"))]
    #[test]
    fn macos_command_writes_the_resolver_file_with_its_port() {
        let command = macos_command(15353);
        assert!(command.contains(RESOLVER_FILE), "{command}");
        assert!(
            command.contains("nameserver 127.0.0.1\\nport 15353\\n"),
            "{command}"
        );
        assert!(command.starts_with("sudo"), "{command}");
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn linux_command_scopes_the_routing_domain_to_the_zone() {
        let command = linux_command(15353, Some("enp3s0"));
        assert!(
            command.contains("resolvectl dns enp3s0 127.0.0.1:15353"),
            "{command}"
        );
        assert!(
            command.contains("resolvectl domain enp3s0 '~min.internal'"),
            "{command}"
        );
        // A host with no routable link still gets the command shape, with
        // the link left to fill in.
        let bare = linux_command(15353, None);
        assert!(
            bare.contains("resolvectl dns <link> 127.0.0.1:15353"),
            "{bare}"
        );
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn link_from_route_table_prefers_the_default_route() {
        let table = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                     lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n\
                     cfeth0\t00000000\t0180A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                     docker0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            link_from_route_table(table).as_deref(),
            Some("cfeth0"),
            "the default route's link wins over lo's and any other route's"
        );
        let no_default = "Iface\tDestination\tGateway\n\
                         lo\t00000000\t00000000\n\
                         docker0\t0001A8C0\t00000000\n";
        assert_eq!(
            link_from_route_table(no_default).as_deref(),
            Some("docker0"),
            "without a default route, the first routed link carries it"
        );
        assert_eq!(
            link_from_route_table("Iface\tDestination\tGateway\nlo\t00000000\t00000000\n"),
            None,
            "a loopback-only table has no routable link"
        );
    }

    #[test]
    fn probe_range_reports_every_address_in_the_range() {
        let probe = probe_range();
        let (_, prefix) = RESERVED_LOCAL_RANGE;
        let usable = ((1u32 << (32 - u32::from(prefix))) - 2) as usize;
        assert_eq!(probe.probed, usable, "every usable host address probed");
        assert!(probe.bound <= probe.probed);
        assert_eq!(
            probe.present(),
            probe.bound == probe.probed,
            "present means the whole range bound: {:?}",
            probe
        );
        assert_eq!(probe.interim(), !probe.present());
        assert_eq!(
            probe.first_refusal.is_none(),
            probe.present(),
            "a present range records no refusal: {:?}",
            probe
        );
    }

    #[test]
    fn naming_surface_records_hook_range_and_interim() {
        let surface = NamingSurface {
            zone: ZONE,
            reserved_range: range_text(),
            loopback_aliases_present: true,
            interim_loopback: false,
            resolver_hook: Hook::configured("test", Some(15353), "routes the zone"),
            bind_probe: BindProbe {
                bound: 254,
                probed: 254,
                first_refusal: None,
            },
        };
        let json = serde_json_lenient::to_string_pretty(&surface).unwrap();
        assert!(json.contains("\"zone\": \"min.internal\""), "{json}");
        assert!(json.contains("127.64.0.0/24"), "{json}");
        assert!(json.contains("\"interim_loopback\": false"), "{json}");
        assert!(json.contains("\"port\": 15353"), "{json}");
    }
}
