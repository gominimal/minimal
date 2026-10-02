//! The host-resolver side of in-zone name resolution (NET-122, NET-123).
//!
//! A daemon answers `*.{ZONE}` lookups from a UDP answerer it holds on the
//! host's loopback; the host's *native* resolver has to be pointed at that
//! answerer before any process on the host can resolve a box name with no
//! proxy settings (NET-009). The hook that points it is per-OS: a resolver
//! file under `/etc/resolver/` on macOS, a systemd-resolved routing domain
//! on a link dedicated to the zone on Linux. This module detects the hook,
//! renders the exact command that installs it, and reads the reserved
//! range's loopback state for the diagnostic bundle.
//!
//! Nothing here prompts. Detecting reads files and runs `resolvectl`
//! read-only; the advisory is pure string assembly over what those reads
//! found. The privilege prompt, when there is one, belongs to the command
//! the user chooses to copy and run — never to a session start (NET-122:
//! "with no privilege prompt"; NET-123's interim arm: neither prompt nor
//! hang).

// The answerer-liveness query's wire codec: the same codec the VM host
// daemon's answerer answers with, so the query and the answer agree by
// construction instead of by copy.
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use minimald_rpc::ZoneAnswererStatus;
use serde::Serialize;
#[cfg(any(test, not(target_os = "macos")))]
use std::net::Ipv4Addr;
use std::time::Duration;
use switch::loopback::RangeProbe;

/// The zone the daemon's answerer holds. Mirrors
/// `minimald::net::dns::HOSTNAME_SUFFIX`; the CLI does not depend on the
/// daemon crate, so the two constants move together.
pub(crate) const ZONE: &str = "min.internal";

/// The link dedicated to [`ZONE`]'s DNS hook on Linux: a dummy interface
/// the advisory's command creates, whose only job is to carry the routing
/// domain that scopes the zone to the answerer (NET-122: the design's
/// "dedicated link of routable scope"). The host's general-purpose DNS
/// link keeps its servers, domains and default-route flag untouched — a
/// link that exists for the zone alone is what keeps `resolvectl dns`'s
/// replace-semantics from ever reaching the host's upstream resolution.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) const ZONE_LINK: &str = "minzone0";

/// The address [`ZONE_LINK`] carries, as a `/32` of global scope: the
/// machine-internal plane's reserved-from-the-top address — the RFC 6598
/// `100.64.0.0/10` block the switch's default `100.64.0.0/16` subnet also
/// lives in, mirroring the switch's `host_alias` convention of reserving an
/// infrastructure address at `broadcast - 1` of its block, outside that
/// subnet's leases, and never one of [`RESERVED_LOCAL_RANGE`], whose aliases
/// belong to `lo` and the boxes publishing from it.
///
/// The address is what makes the link "of routable scope" at all:
/// systemd-resolved consults a link's DNS servers and routing domains only
/// while the link is *relevant* to it — up, with carrier, and carrying at
/// least one address whose scope is below `RT_SCOPE_LINK` (v255's
/// `link_relevant`/`link_address_relevant`) — and a link with no address
/// never has its DNS scope allocated, so the routing domain the command
/// sets is configuration nothing consults: the state the native lane's
/// `getent` failed on before this address existed. A `/32` routes nowhere
/// beyond the address itself.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) const ZONE_LINK_ADDR: Ipv4Addr = Ipv4Addr::new(100, 127, 255, 254);

/// The reserved local range the daemon publishes per-box addresses from and
/// whose presence at session start NET-123's bind probe verifies: the one
/// definition of the range, owned by the `switch` crate and re-exported by
/// the daemon's DNS zone (`minimald::net::dns::RESERVED_LOCAL_RANGE`), so the
/// probe here and the publish there are the same constant and cannot drift
/// on where published addresses live.
pub(crate) use switch::RESERVED_LOCAL_RANGE;

/// The resolver file the advisory's command writes on macOS. `nameserver`
/// plus `port` is the format the loopback-alias spike verified against
/// mDNSResponder (docs/spikes/2026-09-22-macos-loopback-alias.md).
#[cfg(any(test, target_os = "macos"))]
pub(crate) const RESOLVER_FILE: &str = "/etc/resolver/min.internal";

/// `/etc/resolv.conf`: the file every host process's lookup reads (through
/// the `dns` NSS module), and so the one that must name resolved's stub for
/// the routing-domain link to matter to host processes at all.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) const RESOLV_CONF: &str = "/etc/resolv.conf";

/// systemd-resolved's stub address, as `/etc/resolv.conf` names it on every
/// host resolved serves.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) const RESOLVED_STUB: &str = "127.0.0.53";

/// `/etc/nsswitch.conf`: the file that names the sources a host lookup
/// consults, in the order it consults them — the routing the stub-bypass
/// blocker reads before it decides a foreign `/etc/resolv.conf` can keep
/// this host's lookups from systemd-resolved.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) const NSSWITCH_CONF: &str = "/etc/nsswitch.conf";

/// The `resolve` NSS source's module, by the exact name glibc dlopen's for
/// it: the file whose presence makes a `resolve` entry in the `hosts:` chain
/// a source host lookups can consult at all.
#[cfg(any(test, not(target_os = "macos")))]
const NSS_RESOLVE_MODULE: &str = "libnss_resolve.so.2";

/// The directories glibc finds NSS service modules in, on the layouts the
/// shipped hosts run: Debian and Ubuntu's multiarch directories, then the
/// `/usr/lib64` layout Fedora and Alpine use, then the unmerged `/lib` and
/// the plain `/usr/lib` of a 32-bit host. A host with the module somewhere
/// else keeps the blocker — the safe arm, naming no command rather than
/// naming one this cannot prove the chain reaches.
#[cfg(any(test, not(target_os = "macos")))]
const NSS_MODULE_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/usr/lib/powerpc64le-linux-gnu",
    "/usr/lib/riscv64-linux-gnu",
    "/usr/lib/s390x-linux-gnu",
    "/usr/lib64",
    "/lib64",
    "/lib",
    "/usr/lib",
];

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
        // The foreign server is not echoed: the detail is printed in the
        // advisory and recorded verbatim in the `min bug` bundle, and a
        // host's DNS server address is not the bundle's to carry.
        Some(_) => Hook::configured(
            RESOLVER_FILE,
            None,
            "resolver file names a nameserver other than 127.0.0.1, so the \
             zone is not routed to the answerer",
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

/// What an `nsswitch.conf` action rule makes the chain do after the source
/// it follows reports a status.
#[cfg(any(test, not(target_os = "macos")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainAction {
    /// Stop the walk and return what this source reported.
    Return,
    /// Walk on to the next source.
    Continue,
    /// Take this source's answer and walk on anyway.
    Merge,
}

/// One status an NSS source reports for a lookup, as `nsswitch.conf`'s
/// action rules name them.
#[cfg(any(test, not(target_os = "macos")))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupStatus {
    Success,
    NotFound,
    Unavail,
    TryAgain,
}

// The NSS-chain machinery (this impl, `HostsRule`'s and `HostsSource`'s, the
// parsers below) is Linux-only, but gated `any(test, …)` so the suite unit-
// tests it everywhere — the macOS unit lane builds this crate's *lib* with
// no test cfg (`cargo test -p minimal` is off there: the CLI's dev-deps pull
// the Linux-only daemon), so the three impls carry the same cfg as their
// types or that lane dies on `cannot find type`.
#[cfg(any(test, not(target_os = "macos")))]
impl LookupStatus {
    /// The statuses a source that does not hold the zone's names can report
    /// for one: the misses. A rule that returns on a miss ends the walk
    /// before any source after it is reached.
    fn misses() -> [LookupStatus; 3] {
        [
            LookupStatus::NotFound,
            LookupStatus::Unavail,
            LookupStatus::TryAgain,
        ]
    }

    fn parse(word: &str) -> Option<Self> {
        match word.to_ascii_lowercase().as_str() {
            "success" => Some(LookupStatus::Success),
            "notfound" => Some(LookupStatus::NotFound),
            "unavail" => Some(LookupStatus::Unavail),
            "tryagain" => Some(LookupStatus::TryAgain),
            _ => None,
        }
    }
}

/// One `[STATUS=action]` rule of `nsswitch.conf`, the `!` negation included.
#[cfg(any(test, not(target_os = "macos")))]
struct HostsRule {
    /// The status the rule names, or `None` when it names none.
    status: Option<LookupStatus>,
    /// Whether the rule decides every status *but* the one it names.
    negated: bool,
    action: ChainAction,
}

#[cfg(any(test, not(target_os = "macos")))]
impl HostsRule {
    /// Whether this rule is the one that decides `status`: a plain rule
    /// decides the status it names, a negated one every status except it.
    fn decides(&self, status: LookupStatus) -> bool {
        match self.status {
            None => true,
            Some(named) => (named == status) != self.negated,
        }
    }
}

/// One source of an `nsswitch.conf` `hosts:` chain: its name and the action
/// rules written after it.
#[cfg(any(test, not(target_os = "macos")))]
struct HostsSource {
    name: String,
    rules: Vec<HostsRule>,
}

#[cfg(any(test, not(target_os = "macos")))]
impl HostsSource {
    /// What the chain does after this source reports `status`: the last rule
    /// that decides it, else glibc's default — the walk returns on a hit and
    /// continues past a miss, which is what makes `hosts: files dns` consult
    /// `dns` at all.
    fn action_for(&self, status: LookupStatus) -> ChainAction {
        let mut action = match status {
            LookupStatus::Success => ChainAction::Return,
            _ => ChainAction::Continue,
        };
        for rule in &self.rules {
            if rule.decides(status) {
                action = rule.action;
            }
        }
        action
    }

    /// Whether a lookup this source cannot answer walks on to the next one:
    /// every miss continues, the defaults included.
    fn passes_a_miss_by(&self) -> bool {
        LookupStatus::misses()
            .iter()
            .all(|miss| self.action_for(*miss) == ChainAction::Continue)
    }
}

/// The rules inside one bracket group, comma-separated as `nsswitch.conf`
/// writes them. `None` when one does not parse: a chain carrying a rule this
/// cannot read is a chain this cannot speak for.
#[cfg(any(test, not(target_os = "macos")))]
fn parse_hosts_rules(rules: &str) -> Option<Vec<HostsRule>> {
    rules
        .split(',')
        .filter(|rule| !rule.is_empty())
        .map(|rule| {
            let (status, action) = rule.trim().split_once('=')?;
            let status = status.trim();
            let (negated, status) = match status.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, status),
            };
            Some(HostsRule {
                status: LookupStatus::parse(status),
                negated,
                action: match action.trim().to_ascii_lowercase().as_str() {
                    "return" => ChainAction::Return,
                    "continue" => ChainAction::Continue,
                    "merge" => ChainAction::Merge,
                    _ => return None,
                },
            })
        })
        .collect()
}

/// The `hosts:` chain of an `/etc/nsswitch.conf`, as the sources a host
/// lookup walks, in order. `None` when the file carries no such line — or
/// carries one this cannot read: a chain that is not understood proves
/// nothing about where this host's lookups go.
#[cfg(any(test, not(target_os = "macos")))]
fn hosts_chain(nsswitch: &str) -> Option<Vec<HostsSource>> {
    let line = nsswitch.lines().map(str::trim).find(|line| {
        line.split_once(':')
            .is_some_and(|(database, _)| database.trim().eq_ignore_ascii_case("hosts"))
    })?;
    let mut chain: Vec<HostsSource> = Vec::new();
    for token in line.split_once(':')?.1.split_whitespace() {
        if token.starts_with('#') {
            break; // a trailing comment: nothing after it is a source
        }
        if let Some(rules) = token.strip_prefix('[') {
            let rules = rules.strip_suffix(']')?;
            chain.last_mut()?.rules.extend(parse_hosts_rules(rules)?);
            continue;
        }
        if token.contains('=') {
            return None; // a rule outside its brackets: not a form this reads
        }
        chain.push(HostsSource {
            name: token.to_ascii_lowercase(),
            rules: Vec::new(),
        });
    }
    Some(chain)
}

/// Whether this host's `hosts:` lookups consult systemd-resolved — the fact
/// that decides a foreign `/etc/resolv.conf` is not the bypass it looks like.
/// The `resolve` NSS source asks resolved directly, never the file's
/// servers, so where a lookup reaches it, a host process's question reaches
/// resolved however the file is written and the routing-domain command
/// works.
///
/// Proved only in its strictest form, because what this clears is the
/// blocker that withholds NET-122's command: `resolve` is in the chain and
/// its module is installed; the walk reaches it — nothing before it asks
/// `/etc/resolv.conf`'s servers (`dns`, the bypass this names, whose answer
/// or search-domain guess could end the walk before resolved is asked), and
/// no rule before it returns on a miss; and the walk stops where it answers
/// (`[SUCCESS=continue]` lets the sources after it answer after resolved
/// already has). Anything else — a chain with no `resolve`, a missing
/// module, a rule that passes it by, or no chain this could read at all —
/// leaves the blocker standing, so the advisory withholds a command it
/// cannot prove works rather than naming one that does nothing.
#[cfg(any(test, not(target_os = "macos")))]
fn lookups_reach_resolved(nsswitch: Option<&str>, module_installed: bool) -> bool {
    let Some(chain) = nsswitch.and_then(hosts_chain) else {
        return false;
    };
    let Some(at) = chain.iter().position(|source| source.name == "resolve") else {
        return false;
    };
    module_installed
        && chain[at].action_for(LookupStatus::Success) == ChainAction::Return
        && chain[..at]
            .iter()
            .all(|source| source.name != "dns" && source.passes_a_miss_by())
}

/// The paths the `resolve` source's module could be installed at, in the
/// order they are tried.
#[cfg(any(test, not(target_os = "macos")))]
fn resolve_module_candidates() -> impl Iterator<Item = String> {
    NSS_MODULE_DIRS
        .iter()
        .map(|dir| format!("{dir}/{NSS_RESOLVE_MODULE}"))
}

/// Whether the `resolve` source's module is installed where glibc finds it:
/// one `stat` per candidate directory, read-only. glibc dlopen's
/// `libnss_<source>.so.2` for every source the chain names, and a missing
/// module reads as UNAVAIL — the walk passes `resolve` by and lands on the
/// foreign `/etc/resolv.conf` servers, which is exactly the bypass the
/// blocker names, so a chain that names `resolve` without the module
/// clears nothing.
#[cfg(not(target_os = "macos"))]
async fn resolve_module_installed() -> bool {
    for path in resolve_module_candidates() {
        if tokio::fs::metadata(&path).await.is_ok() {
            return true;
        }
    }
    false
}

/// Why no routing-domain command would reach this host's lookups, when none
/// would: `/etc/resolv.conf` names a resolver other than systemd-resolved's
/// stub, and the `hosts:` chain a host lookup walks does not consult
/// `nss-resolve` first, so the lookup never travels through resolved and a
/// link's routing domain — however exactly it is configured — never applies
/// to it. The command NET-122's advisory names configures resolved; on this
/// host that is configuration nothing consults, so the advisory says this
/// instead of naming it.
///
/// `domain_read` is whether `resolvectl domain` answered: a host with no
/// resolved at all has no routing-domain command to withhold, so the blocker
/// is absent there. Also `None` when the stub is named (the command works,
/// alone or beside foreign servers — glibc asks every listed resolver), when
/// the file could not be read or names nothing, and when the chain consults
/// `nss-resolve` (see [`lookups_reach_resolved`]): there the command reaches
/// host lookups whatever the file names. Pure over the reads, so it is
/// unit-tested on every platform the suite runs on.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn stub_bypass_blocker(
    domain_read: Option<&str>,
    resolv_conf: Option<&str>,
    nsswitch: Option<&str>,
    resolve_module: bool,
) -> Option<String> {
    let text = resolv_conf?;
    let mut servers = Vec::new();
    for line in text.lines() {
        let mut tokens = line.split_whitespace();
        if tokens.next() != Some("nameserver") {
            continue;
        }
        let Some(server) = tokens.next() else {
            continue;
        };
        if server == RESOLVED_STUB {
            return None;
        }
        servers.push(server.to_string());
    }
    if servers.is_empty() || domain_read.is_none() {
        return None;
    }
    if lookups_reach_resolved(nsswitch, resolve_module) {
        return None;
    }
    Some(format!(
        "this host's lookups bypass systemd-resolved: {RESOLV_CONF} names {} \
         and not its {RESOLVED_STUB} stub, so the routing-domain command \
         cannot reach them; the zone resolves in host processes only once \
         their lookups reach that stub",
        servers.join(" ")
    ))
}

/// How long the detection's two `resolvectl` queries may take between
/// them before detection gives up on both: the deadline is the *pair's*,
/// paid once — the queries run together ([`host_detection`]), so a wedged
/// systemd-resolved costs the verb that reads this one wait, not one wait
/// per query. A healthy systemd-resolved answers in milliseconds, but a
/// wedged one — or its D-Bus bus — blocks each call indefinitely, and the
/// session start this deadline was sized for must neither prompt nor hang
/// (NET-123); a query the deadline outlives reads as absent, the arm the
/// advisory is safe under, instead of wedging the activate. Generous on
/// purpose: a loaded host's slow-but-healthy query must not misread. The
/// queries this bounds run on Linux; macOS's detection is one file read
/// that carries no deadline.
const RESOLVECTL_BOUND: Duration = Duration::from_secs(5);

/// The same deadline sized for the verb that must not wait:
/// [`ls_detection`] — `min ls`'s form of the same detection — reads under
/// this one. The list is the most frequently-invoked verb, run in loops
/// and from shell prompts, and its read of the host's resolver must stay
/// a status read, not a wait, so this is the deadline the list's own
/// host-side subprocess probes already carry (`minimal-client`'s
/// `GIT_PROBE_TIMEOUT`: "a list response must stay fast even when a
/// session's project sits on a wedged filesystem"). A wedged
/// systemd-resolved costs a `min ls` this one second — not the session
/// start's five, and not ten when its two queries each pay that five —
/// and a read the deadline outlives reads as absent, which is the
/// proxy's arm: the verdict that cannot strand the user (NET-019 keeps
/// the proxy serving), and the verdict a wedged resolver genuinely
/// leaves. The queries this bounds run on Linux; macOS's detection is one
/// file read that carries no deadline.
const LIST_RESOLVECTL_BOUND: Duration = Duration::from_secs(1);

/// One read-only query of `program`, or `None` when the binary is missing,
/// the call failed, or its output is not UTF-8. Reading through
/// systemd-resolved's read API writes nothing, so it cannot prompt.
/// `kill_on_drop` reaps a query the caller's deadline abandons — the
/// deadline itself is the caller's, over the pair of queries
/// [`host_detection`] makes — so a wedged call leaves no process behind
/// on the host it hung.
#[cfg(any(test, not(target_os = "macos")))]
async fn query(program: &str, args: &[&str]) -> Option<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await;
    let output = output.ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// [`query`] under `bound`: the form the deadline's mechanism is tested
/// in. The production reads run the pair under one deadline instead
/// ([`host_detection`]); this stays the seam that proves the mechanism —
/// a call that outlives its bound reads as absent and leaves nothing
/// behind on the host it hung.
#[cfg(all(test, not(target_os = "macos")))]
async fn bounded_query(program: &str, args: &[&str], bound: Duration) -> Option<String> {
    // A query that outlived its bound reads as absent.
    tokio::time::timeout(bound, query(program, args))
        .await
        .unwrap_or_default()
}

/// The query program a test installed in place of `resolvectl`, when one is
/// installed. A wedged `resolvectl`, or a slow-but-healthy one, is not a
/// state this host can be put in, so the tests that need one write a
/// stand-in script and install its path here — the same stand-in discipline
/// the daemon's tests use for their loopback probe. Process-global: under
/// libtest the tests of one binary share a process, so the tests that use
/// it hold the stand-in mutex in the tests module below for the whole
/// install→assert→clear window; the other detection readers assert on no
/// particular arm, so a stand-in they read by accident is a slower pass,
/// not a wrong one.
#[cfg(all(test, not(target_os = "macos")))]
static QUERY_STANDIN: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// The program the detection's queries run: `resolvectl`, or the stand-in
/// a test installed.
#[cfg(all(test, not(target_os = "macos")))]
fn query_program() -> String {
    QUERY_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_else(|| "resolvectl".to_string())
}

/// Reads the host's current hook state (NET-122's detection proper) and the
/// reason no zone command would reach this host's lookups, when there is one.
/// Detection is read-only and never prompts: on Linux, two `resolvectl`
/// queries under one [`RESOLVECTL_BOUND`] deadline — run together, so the
/// deadline is paid once, and a wedged systemd-resolved reads as absent
/// rather than hanging the activate — and three file reads; on macOS, one
/// file read.
pub(crate) async fn session_detection() -> (Hook, Option<String>) {
    host_detection(RESOLVECTL_BOUND).await
}

/// [`session_detection`] at [`LIST_RESOLVECTL_BOUND`], the deadline the
/// list's read carries: `min ls` is the most frequently-invoked verb, so
/// the same host state it reads must not make it a wait — the verdict a
/// wedged systemd-resolved leaves is decided inside this one second, and
/// it is the proxy's arm, the one that cannot strand the user, so the
/// worst a wedged resolver costs a list is a second, never the session
/// start's five.
async fn ls_detection() -> (Hook, Option<String>) {
    host_detection(LIST_RESOLVECTL_BOUND).await
}

#[cfg(target_os = "macos")]
async fn host_detection(_bound: Duration) -> (Hook, Option<String>) {
    // macOS's resolver consults the resolver file directly — there is no
    // stub for host lookups to bypass, so nothing can block the command,
    // and the one read this makes carries no deadline to bound.
    (host_hook().await, None)
}

#[cfg(not(target_os = "macos"))]
async fn host_detection(bound: Duration) -> (Hook, Option<String>) {
    // The queries' program: the stand-in a test installed, else
    // `resolvectl` itself.
    #[cfg(test)]
    let program = query_program();
    #[cfg(not(test))]
    let program = "resolvectl".to_string();
    // Both queries under the one deadline, run together: the deadline is
    // the pair's, paid once, so a wedged systemd-resolved costs the verb
    // that reads this one wait — not one per query — and a pair that
    // outlives it reads as absent, both queries reaped where they hang.
    let (domain, dns) = tokio::time::timeout(bound, async {
        tokio::join!(query(&program, &["domain"]), query(&program, &["dns"]))
    })
    .await
    .unwrap_or((None, None));
    let resolv_conf = tokio::fs::read_to_string(RESOLV_CONF).await.ok();
    let nsswitch = tokio::fs::read_to_string(NSSWITCH_CONF).await.ok();
    let resolve_module = resolve_module_installed().await;
    (
        routing_domain_hook(domain.as_deref(), dns.as_deref()),
        stub_bypass_blocker(
            domain.as_deref(),
            resolv_conf.as_deref(),
            nsswitch.as_deref(),
            resolve_module,
        ),
    )
}

#[cfg(target_os = "macos")]
async fn host_hook() -> Hook {
    match tokio::fs::read_to_string(RESOLVER_FILE).await {
        Ok(text) => resolver_file_hook(Some(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => resolver_file_hook(None),
        Err(e) => Hook::absent(RESOLVER_FILE, format!("resolver file unreadable: {e}")),
    }
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

/// The exact command that points systemd-resolved at the answerer: one
/// `sudo` configuring [`ZONE_LINK`] and nothing else. The dedicated link
/// exists because `resolvectl dns` and `resolvectl domain` *replace* a
/// link's server and domain lists: on the host's general-purpose link they
/// would wipe its upstream resolvers and search domains, and a link whose
/// only server is the answerer — which holds just the zone and forwards
/// nothing — must not carry the host's other queries either.
///
/// The steps, in the order they run: create the dedicated link if this host
/// does not have it yet (a re-run after `resolvectl revert`, which undoes
/// the DNS configuration but not the link, must not die on `File exists` —
/// the guard covers the link, and `ip addr replace` covers its address),
/// bring it up, give it [`ZONE_LINK_ADDR`] — the fact that makes resolved
/// treat the link as routable and ever consult its routing domain — take it
/// off the default route, then give it the answerer as its server and the
/// zone as its routing domain. `default-route false` comes *before* the
/// server because a link with servers and no routing domain is a
/// default-route link implicitly — the flag first means no partially-run
/// command ever routes non-zone queries here. `~{ZONE}` is single-quoted so
/// the inner shell does not expand the tilde.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn linux_command(port: u16) -> String {
    format!(
        "sudo sh -c \"[ -e /sys/class/net/{ZONE_LINK} ] \
         || ip link add {ZONE_LINK} type dummy \
         && ip link set {ZONE_LINK} up \
         && ip addr replace {ZONE_LINK_ADDR}/32 dev {ZONE_LINK} \
         && resolvectl default-route {ZONE_LINK} false \
         && resolvectl dns {ZONE_LINK} 127.0.0.1:{port} \
         && resolvectl domain {ZONE_LINK} '~{ZONE}'\""
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
    linux_command(port)
}

/// The advisory for one session start, as a function of the hook state, the
/// daemon's interim verdict, whether the reserved local range read present
/// on this host's own loopback, and whether anything blocks the command
/// (NET-122, NET-123's interim arm). Pure.
///
/// `None` — nothing to say — when the hook already routes the zone to this
/// answerer, the daemon did not publish at the interim, the range read
/// present on this host's own loopback, *and* nothing blocks the command.
/// Otherwise the advisory says what is missing and names the exact command.
/// The interim re-surfaces the advisory even when the hook routes (NET-123:
/// "re-surface
/// the advisory of NET-122"): a session on the interim is a fact the user
/// has no other way to see. The interim fact names the step that ends it:
/// installing the range on the host — by design §7.1 the job of the same
/// advisory command on macOS, once that command reserves the range (a
/// root-held boot step that T76
/// (<https://github.com/gominimal/minimal/issues/1817>) adds to the command
/// rendered here). The
/// command the advisory names is therefore said to configure the resolver,
/// and the range fact stands beside it rather than under it, so a user who
/// ran the command is not told it ended the interim. String assembly only.
///
/// `range_present` is this host's own read of the range — the one read the
/// live-surface verdict shares with this advisory (see
/// [`session_advisory_at`]) — and not the daemon's interim flag, which on a
/// VM-backed host reads the guest's loopback and always says present, so a
/// daemon's `false` cannot vouch for the host whose names the verdict
/// decides. A read that says absent keeps the advisory from falling quiet
/// on a hook that routes — the very state whose verdict names the proxy for
/// exactly that missing range — and adds the fact saying so. `None`, no
/// read made, claims nothing: the advisory stays quiet where it did, the
/// one start that reaches its quiet arm without a read being a reply whose
/// answerer is not bound, where no verdict prints beside it to disagree.
///
/// `blocker` names why the command would do nothing on this host — a host
/// whose lookups never reach the resolver the command configures — in which
/// case the advisory says that instead of naming a command: NET-122's
/// "exact command" is only ever one that works, and printing a dead one
/// would take a privilege prompt in exchange for configuration no host
/// process would ever consult. That holds on a hook that routes too: the
/// bypass leaves the configured hook as dead as an unconfigured one, so
/// the blocker is still said (and is then the whole of the note, no fact
/// being missing — a hook that routes is not a fact the note can lean on).
pub(crate) fn advisory_at(
    hook: &Hook,
    port: u16,
    interim: bool,
    range_present: Option<bool>,
    blocker: Option<&str>,
) -> Option<String> {
    // A hook routing this answerer's port is configured, but only on a
    // host whose lookups reach the resolver it points at. A blocker says
    // they do not, so it outranks the quiet arm: staying silent there
    // would tell the user their resolver is set up while no host process's
    // lookup consults it, and `*.{ZONE}` would not resolve — NET-122's
    // WHILE clause is about the resolver that works, not the one whose
    // configuration is on paper. The range beside them is the host's own
    // read, the verdict's read: a hook that routes over a loopback that
    // lacks the range is a host the verdict calls the proxy, and the
    // advisory says the range is what is missing there rather than
    // staying quiet on the daemon's interim flag, which on a VM-backed
    // host reads the guest's loopback — always present — and not the host
    // the names resolve on.
    if hook.routes(port) && !interim && !matches!(range_present, Some(false)) && blocker.is_none() {
        return None;
    }
    let mut facts = Vec::new();
    if interim {
        // The interim ends when the range is installed on the host — the
        // root-held boot step design §7.1 folds into the macOS advisory
        // command. That step is T76's to add to the command rendered here
        // (https://github.com/gominimal/minimal/issues/1817); until it does,
        // the fact names the range as what is missing and stops there:
        // it neither claims the command below ends the interim nor claims
        // nothing ever will.
        facts.push(format!(
            "this session publishes at the shared 127.0.0.1 interim: the \
             reserved local range {} is not installed on this host's loopback",
            range_text()
        ));
    } else if matches!(range_present, Some(false)) {
        // The same missing range without the interim behind it: the daemon
        // published this session from the range — its flag says no interim —
        // so the names that resolve answer with addresses from a range this
        // host's loopback does not carry, and the host cannot reach them.
        // The verdict says the proxy for exactly this fact (NET-018); the
        // advisory says the fact.
        facts.push(format!(
            "the reserved local range {} is not installed on this host's \
             loopback, so this session's box names resolve to addresses this \
             host cannot reach",
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
    match blocker {
        // The note is built from the parts that are there. A blocker can be
        // the whole of it — the hook routes, so no fact is missing — and a
        // missing fact must not print as a dangling `; ` after the colon.
        Some(blocker) if facts.is_empty() => Some(format!("note: {blocker}.")),
        Some(blocker) => Some(format!("note: {facts}; {blocker}.")),
        None => {
            let command = command(port);
            Some(format!(
                "note: {facts}. Configure the host's resolver for the zone with:\n  {command}"
            ))
        }
    }
}

/// The advisory to print at this session's start, given what the daemon
/// reported on its create response and a detection the caller already read
/// — the session-start path's form, so the advisory and the live-surface
/// verdict printed below it share one read of this host's resolver state
/// and cannot disagree about it.
///
/// `zone_answerer_port` is `None` while the daemon is still bringing its
/// answerer up (or from a daemon predating the field, which the create's
/// version gate already refuses); there is then no port to point a command
/// at, so the advisory stays quiet rather than naming a command that
/// cannot work. `interim_loopback` is the daemon's NET-123 verdict: its
/// session-start bind probe found the reserved range absent and it
/// published this session at the 127.0.0.1 interim. `range_present` is
/// *this* host's own read of the same range — the read the surface verdict
/// the same start decides, passed back here so both lines draw the one
/// fact from the one probe: the daemon's interim flag is not that fact on
/// a VM-backed host, where it reads the guest's loopback and always says
/// present, and a host whose own loopback lacks the range is one the
/// verdict calls the proxy, so the advisory must say the range is what is
/// missing there instead of going quiet. `None`, no read made, claims
/// nothing (see [`advisory_at`]). On a host whose `/etc/resolv.conf`
/// bypasses systemd-resolved's stub *and* whose `hosts:` lookups do not
/// consult `nss-resolve`, the advisory says so and names no command (see
/// [`session_detection`]): none would reach host lookups there.
///
/// Printed once per session start, to stderr; never prompts.
pub(crate) fn session_advisory_at(
    detection: &(Hook, Option<String>),
    zone_answerer_port: Option<u16>,
    interim_loopback: bool,
    range_present: Option<bool>,
) -> Option<String> {
    let port = zone_answerer_port?;
    let (hook, blocker) = detection;
    advisory_at(
        hook,
        port,
        interim_loopback,
        range_present,
        blocker.as_deref(),
    )
}

/// The surface a `*.{ZONE}` name resolves through on this host, as the two
/// verbs that can print it report it (NET-018). [`LiveSurface::Native`] is
/// native DNS: the host's own resolver answers the zone from the daemon's
/// answerer, no proxy settings involved. [`LiveSurface::Proxy`] is the
/// hostname proxy: names resolve only through the listener an
/// `HTTP(S)_PROXY` export points at.
///
/// It lives here, beside the detection and the advisory, because the
/// verdict is the *host's* — the one place it can be computed is the host
/// the names resolve on — so `min session activate` and `min ls` both
/// print from the one function that reads it and cannot disagree about
/// one host. T65's verbs inherit it unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveSurface {
    /// Native DNS: the host resolver answers `*.{ZONE}` from the answerer.
    Native,
    /// The hostname proxy: names resolve only through it.
    Proxy,
}

/// Design §7.1's supersession condition, as the three facts it is: this
/// host's resolver hook routes [`ZONE`] to the answerer on `answerer_port`
/// — with no [`stub_bypass_blocker`], because on a host whose lookups
/// bypass the resolver a routing-domain hook configures, the hook is
/// configuration no host process consults — the daemon's box-zone answerer
/// is bound in its own namespace, and the reserved local range whose
/// addresses the boxes publish from is present on this host's loopback.
/// Native DNS is live only when all three hold; any one of them missing
/// and the hostname proxy is the only surface that answers a box name.
/// Pure, so the table is unit-testable on every platform the suite runs
/// on, whatever that host's own files say.
pub(crate) fn native_surface_at(
    hook: &Hook,
    answerer_port: u16,
    answerer_bound: bool,
    range_present: bool,
    blocker: Option<&str>,
) -> bool {
    answerer_bound && hook.routes(answerer_port) && range_present && blocker.is_none()
}

/// The verdict [`live_name_surface_at`] decides, with the range fact of the
/// host's own read carried back beside it — the form `min session activate`
/// logs at session start (NET-018's host-side record): the daemon's line can
/// name only the answerer *it* binds, so the surface a host's names actually
/// resolve through is the host's to record, logged where the host read it.
/// [`Self::range_present`] is `None` when the two cheap facts settled the
/// proxy without a probe — the honest record: a range never read is not a
/// range reported present or absent.
pub(crate) struct LiveSurfaceVerdict {
    /// Which surface the three facts decided is live.
    pub surface: LiveSurface,
    /// Whether the reserved range read present on this host's loopback,
    /// when the verdict read it.
    pub range_present: Option<bool>,
}

/// The live surface for the facts one reply carries, from a detection the
/// caller already read, with the range fact of the host's own read beside
/// the verdict — `min session activate`'s form: the session start reads
/// this host's resolver state once (see [`session_advisory_at`]) and
/// decides the advisory, this verdict, and the log that records it from
/// that one read, carrying [`LiveSurfaceVerdict::range_present`] back to
/// the advisory so the two lines draw the range from the one probe and
/// cannot disagree about the host whose loopback it read.
///
/// `None` — nothing to print — when the daemon's answerer is not bound in
/// its own namespace (`answerer_bound` false, or the reply carrying no
/// port): there is then no native surface to name, the proxy is the only
/// surface and the port lines and the advisory already tell its story, and
/// — the same read — a daemon old enough to predate the field is not
/// evidence its answerer serves, so silence is the arm that cannot
/// misreport (see the field's doc in `minimald-rpc`). Otherwise the
/// verdict is the three facts': native when they all hold, the proxy when
/// any one of them does not.
///
/// The published-range fact is read last, and only behind the two cheap
/// ones: a host whose resolver does not route the zone to the answerer —
/// or one whose lookups bypass the resolver a hook would configure —
/// cannot read native whatever the range says, so it pays no bind probe.
pub(crate) async fn live_name_surface_with_range_at(
    detection: &(Hook, Option<String>),
    zone_answerer_port: Option<u16>,
    answerer_bound: bool,
) -> Option<LiveSurfaceVerdict> {
    let port = zone_answerer_port?;
    if !answerer_bound {
        return None;
    }
    let (hook, blocker) = detection;
    // The two cheap facts first: a host whose resolver does not route the
    // zone to the answerer — or one whose lookups bypass the resolver a
    // hook would configure — cannot read native whatever the range says,
    // so it settles on the proxy without paying the bind probe below.
    if !hook.routes(port) || blocker.is_some() {
        return Some(LiveSurfaceVerdict {
            surface: LiveSurface::Proxy,
            range_present: None,
        });
    }
    let range_present = range_present_on_host().await;
    Some(LiveSurfaceVerdict {
        surface: if native_surface_at(hook, port, true, range_present, blocker.as_deref()) {
            LiveSurface::Native
        } else {
            LiveSurface::Proxy
        },
        range_present: Some(range_present),
    })
}

/// [`live_name_surface_with_range_at`] as the printed verdict alone — the
/// form `min ls` reads and the table tests assert: just the surface, the
/// facts it was decided from staying where the caller that holds them (the
/// detection, the reply) can log them.
pub(crate) async fn live_name_surface_at(
    detection: &(Hook, Option<String>),
    zone_answerer_port: Option<u16>,
    answerer_bound: bool,
) -> Option<LiveSurface> {
    live_name_surface_with_range_at(detection, zone_answerer_port, answerer_bound)
        .await
        .map(|verdict| verdict.surface)
}

/// [`live_name_surface_at`] with the detection this verb reads itself —
/// `min ls`'s form: the list has no session-start advisory to share a
/// read with, so the same bounded, read-only detection runs here — at
/// [`ls_detection`]'s [`LIST_RESOLVECTL_BOUND`], the list's deadline, not
/// the session start's, because the list is the most frequently-invoked
/// verb and its read must stay a status read — and only when the daemon's
/// answerer is bound (the cheap half the reply carries). The answerer is
/// bound on every current daemon, so this read is not one only rare hosts
/// pay: `cmd_ls` runs it in the modes that print the verdict alone, which
/// is where the read belongs.
pub(crate) async fn live_name_surface(
    zone_answerer_port: Option<u16>,
    answerer_bound: bool,
) -> Option<LiveSurface> {
    if zone_answerer_port.is_none() || !answerer_bound {
        return None;
    }
    let detection = ls_detection().await;
    live_name_surface_at(&detection, zone_answerer_port, answerer_bound).await
}

/// The host answerer's state as the two verbs consume it on a VM-backed
/// host (NET-138): the port the VM host daemon's status read reported, the
/// liveness proof this CLI ran itself against that port, and the machine
/// fact that says this VM's names are not answered on the host at all.
///
/// The status read says *where to look and who holds the port*; the query
/// proves the answerer is live — the pair the directive's condition (b)
/// names, and the reason [`Self::answerer_bound`] is this CLI's own read
/// and not the status's word: a holder that has since died still reports
/// itself held, so the verdict pays one bounded query before it says
/// native. [`Self::port`] is `None` while the acquisition loop has not run
/// its first pass — the pre-acquisition state, which the verbs treat as
/// "nothing to say yet" rather than a verdict, exactly as a daemon still
/// bringing its answerer up is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostAnswererRead {
    /// The port the VM host daemon reported, when its acquisition loop has
    /// decided one.
    pub port: Option<u16>,
    /// Whether this CLI's own A query for [`minvmd::net::answerer::HOST_NAME`]
    /// answered 127.0.0.1 from that port — the answerer-live proof.
    pub answerer_bound: bool,
    /// Whether the port is held by a process no zone-answerer channel
    /// reaches: this VM's table is not in any daemon's answers, so this
    /// VM's names are not answered on the host and the proxy is the
    /// surface. The liveness query is not run in this arm — the status
    /// already says the port is no daemon's answerer, so a reply from it
    /// would be some other process's behaviour, not this zone's.
    pub held_no_channel: bool,
}

/// [`HostAnswererRead`] from the status the VM host daemon's control
/// socket answered: `Holder` and `Registered` name their port and earn the
/// one bounded liveness query that proves it answers; `PortHeldNoChannel`
/// names its port with no query to run; `Starting` claims nothing.
pub(crate) async fn host_answerer_read(status: ZoneAnswererStatus) -> HostAnswererRead {
    match status {
        ZoneAnswererStatus::Starting => HostAnswererRead {
            port: None,
            answerer_bound: false,
            held_no_channel: false,
        },
        ZoneAnswererStatus::PortHeldNoChannel { port } => HostAnswererRead {
            port: Some(port),
            answerer_bound: false,
            held_no_channel: true,
        },
        ZoneAnswererStatus::Holder { port } | ZoneAnswererStatus::Registered { port } => {
            HostAnswererRead {
                port: Some(port),
                answerer_bound: answerer_bound_at(port).await,
                held_no_channel: false,
            }
        }
    }
}

/// The liveness proof behind `answerer_bound` on a VM-backed host: this
/// CLI's own bounded A query for the host's row —
/// [`minvmd::net::answerer::HOST_NAME`], the name the answerer itself holds
/// at 127.0.0.1 (NET-003's host half) — expecting the answer 127.0.0.1, in
/// the same wire codec the answerer answers with, so the question and the
/// answer agree by construction instead of by copy. `false` on anything
/// else — no reply inside the window, a reply that does not decode, or one
/// answering any other name or address — because every verb reading this
/// may not say native without the proof.
///
/// One UDP datagram to the machine's own loopback, under
/// [`ANSWERER_PROBE_BOUND`]: a status read, paid only on a VM-backed host
/// whose status read named a holder, so `min ls` stays the status read it
/// is. Blocking, so on a blocking thread; a task that panics or is lost
/// reads as not bound.
pub(crate) async fn answerer_bound_at(port: u16) -> bool {
    tokio::task::spawn_blocking(move || answerer_bound_blocking(port))
        .await
        .unwrap_or_else(|join| {
            tracing::warn!(
                error = %join,
                "the answerer liveness query did not run; treating the \
                 answerer as not bound"
            );
            false
        })
}

/// The bound on the answerer liveness query's reply window: generous for a
/// loopback datagram — the answerer answers in well under the round trip —
/// and short enough that a wedged holder costs the verb a fraction of its
/// own detection budget ([`LIST_RESOLVECTL_BOUND`], the tighter of the two
/// the verbs read under), never a wait of its own.
const ANSWERER_PROBE_BOUND: Duration = Duration::from_millis(250);

/// [`answerer_bound_at`]'s blocking half: one query datagram out, one
/// bounded reply window, the answer decoded and judged.
fn answerer_bound_blocking(port: u16) -> bool {
    let Ok(socket) = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)) else {
        return false;
    };
    if socket.set_read_timeout(Some(ANSWERER_PROBE_BOUND)).is_err() {
        return false;
    }
    let query = host_row_query();
    if socket
        .send_to(&query, (std::net::Ipv4Addr::LOCALHOST, port))
        .is_err()
    {
        return false;
    }
    let mut buf = vec![0u8; MAX_ANSWERER_DATAGRAM];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => Message::from_vec(&buf[..len])
            .map(|reply| reply_answers_host_row(&reply))
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// The largest reply the liveness query reads: the answer it wants is one A
/// record, and a reply that does not fit here is not one it would accept
/// either — larger than the classic minimal UDP datagram, so no real
/// single-record answer is lost to it.
const MAX_ANSWERER_DATAGRAM: usize = 512;

/// The A query for the host's row, on the wire: the same scaffolding the
/// answerer's own tests drive, so the query proves the same wire the
/// answers are given by.
fn host_row_query() -> Vec<u8> {
    let name = Name::from_utf8(minvmd::net::answerer::HOST_NAME).expect("the host row name parses");
    let mut query = Message::query();
    query.add_query(Query::query(name, RecordType::A));
    query.to_vec().expect("the liveness query encodes")
}

/// Whether `reply` is the proof the query was after: NoError, answering
/// the host's row with 127.0.0.1. Anything else — a negative response, a
/// different name, a different address — is not a live answerer, whatever
/// the status said.
fn reply_answers_host_row(reply: &Message) -> bool {
    reply.metadata.response_code == ResponseCode::NoError
        && reply.answers.iter().any(|record| {
            record.record_type() == RecordType::A
                && matches!(
                    &record.data,
                    RData::A(A(address)) if *address == std::net::Ipv4Addr::LOCALHOST
                )
        })
}

/// `min ls`'s ZONE ANSWERER line on a VM-backed host (NET-138): the line
/// that says the zone is answered by the VM host daemon — the
/// single-operator interim the answerer is — and names the holder the
/// status read reported: this VM's minvmd when it holds the port, another
/// VM host daemon when this one's table is registered with it. The third
/// arm is the one that must not claim an answer: a port held by a process
/// no channel reaches means this VM's names are not answered on the host,
/// and the line says that instead. `None` for the pre-acquisition state —
/// nothing to name yet, and the verb prints nothing for a listener still
/// coming up, exactly as a native daemon's absent port does.
#[must_use]
pub fn vm_host_answerer_line(status: ZoneAnswererStatus) -> Option<String> {
    match status {
        ZoneAnswererStatus::Starting => None,
        ZoneAnswererStatus::Holder { port } => Some(format!(
            "answered by the VM host daemon (single-operator interim) · this \
             VM's minvmd holds it on 127.0.0.1:{port} (UDP) · point the host's \
             resolver at it for *.{ZONE}"
        )),
        ZoneAnswererStatus::Registered { port } => Some(format!(
            "answered by the VM host daemon (single-operator interim) · \
             another VM host daemon holds it on 127.0.0.1:{port} (UDP); this \
             VM's table is registered with it · point the host's resolver at \
             it for *.{ZONE}"
        )),
        ZoneAnswererStatus::PortHeldNoChannel { port } => Some(format!(
            "not answered on the host · a process no zone-answerer channel \
             reaches holds 127.0.0.1:{port}, so this VM's minvmd answers \
             nothing and its names are not answered on the host"
        )),
    }
}

/// The live surface on a VM-backed host, from the status the VM host
/// daemon's control socket answered — `min ls`'s form. The no-channel state
/// settles the proxy by the status's own word, without paying the
/// detection or the liveness query: the port is no daemon's answerer, so
/// the two reads could only misreport native. The two decided states read
/// the list's own bounded detection and this CLI's liveness query at the
/// port the status named — the same facts the session start reads, at the
/// list's own deadline, as [`live_name_surface`] does for a native host.
/// The pre-acquisition state claims nothing: no port named, no verdict to
/// print, exactly as a native daemon's absent port is.
pub(crate) async fn vm_host_name_surface(status: ZoneAnswererStatus) -> Option<LiveSurface> {
    match status {
        ZoneAnswererStatus::Starting => None,
        ZoneAnswererStatus::PortHeldNoChannel { .. } => Some(LiveSurface::Proxy),
        ZoneAnswererStatus::Holder { port } | ZoneAnswererStatus::Registered { port } => {
            let detection = ls_detection().await;
            let answerer_bound = answerer_bound_at(port).await;
            live_name_surface_at(&detection, Some(port), answerer_bound).await
        }
    }
}

/// The warning every session start on a VM-backed host prints when the
/// answerer's port is held by a process no channel reaches (NET-138): this
/// VM's names are not answered on the host, and the proxy remains the
/// surface. Printed to stderr unconditionally — the directive's "at every
/// session start, TTY and non-TTY" — because the fact it names is the one
/// a user relying on the names needs before the first lookup fails; the
/// verdict printed below it says which surface the names do route
/// through. Pure, so tests assert the wording without capturing stderr.
#[must_use]
pub fn port_held_no_channel_warning(port: u16) -> String {
    format!(
        "warning: this VM's box names are not answered on the host: a \
         process no zone-answerer channel reaches holds the zone answerer's \
         port 127.0.0.1:{port}. The hostname proxy remains the surface the \
         names route through."
    )
}

/// Whether the reserved local range is present on *this* host's loopback:
/// the same bind probe the daemon runs at session start (`switch::loopback`,
/// one definition next to the range it probes), run where the verdict is
/// decided — the CLI's own host, which is the host whose processes resolve
/// the names, on a VM-backed one and a native one alike. Blocking, so on a
/// blocking thread; a probe task that panics or is lost reads as absent,
/// because without a verdict the verbs may not say native.
async fn range_present_on_host() -> bool {
    tokio::task::spawn_blocking(switch::loopback::probe)
        .await
        .map(|probe| probe.present())
        .unwrap_or_else(|join| {
            tracing::warn!(
                error = %join,
                "the live-surface bind probe did not run; treating the \
                 reserved local range as absent"
            );
            false
        })
}

/// NET-018's report: the line `min ls` and `min session activate` print,
/// naming the surface [`live_name_surface`] decided is live. `proxy_port`
/// is the port the same reply carries, when the proxy came up: NET-019
/// keeps it serving beside native DNS, and the line says so, because a
/// client that captured `HTTP(S)_PROXY` at activation keeps routing
/// through it — the export does not go stale when the surface changes.
/// With no port the proxy is down, and the line says that in the daemon's
/// own words rather than claiming it still serves. Pure, so both verbs
/// print the same words and tests assert them without capturing output.
#[must_use]
pub fn name_surface_line(surface: LiveSurface, proxy_port: Option<u16>) -> String {
    let proxy_half = match proxy_port {
        Some(port) => format!("; the hostname proxy still serves on 127.0.0.1:{port}"),
        None => "; the hostname proxy is not serving".to_string(),
    };
    match surface {
        LiveSurface::Native => format!(
            "native DNS is the live name surface · <name>.min.internal answers from \
             the zone answerer and each box's own reserved-range address{proxy_half}"
        ),
        LiveSurface::Proxy => match proxy_port {
            Some(port) => format!(
                "the hostname proxy is the live name surface · <name>.min.internal \
                 routes through it on 127.0.0.1:{port}"
            ),
            None => "the hostname proxy is the live name surface; it is not serving".to_string(),
        },
    }
}

/// The reserved range as `network/prefix`, the form the advisory and the
/// bundle print.
fn range_text() -> String {
    let (network, prefix) = RESERVED_LOCAL_RANGE;
    format!("{network}/{prefix}")
}

/// The bind probe's result as the bundle records it: the same probe the
/// daemon runs at session start (`switch::loopback`, one definition next to
/// the range it probes), with its refusal spelled out for a JSON reader.
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

impl From<&RangeProbe> for BindProbe {
    fn from(probe: &RangeProbe) -> Self {
        BindProbe {
            bound: probe.bound,
            probed: probe.probed,
            first_refusal: probe
                .first_failure
                .map(|(address, kind)| (address.to_string(), kind.to_string())),
        }
    }
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
    let (hook, _) = session_detection().await;
    // The daemon's session-start probe, run here on the CLI's own host:
    // blocking, so on a blocking thread.
    let probe = tokio::task::spawn_blocking(switch::loopback::probe)
        .await
        .unwrap_or_else(|join| {
            tracing::warn!(
                error = %join,
                "the naming-surface bind probe did not run; treating the \
                 reserved local range as absent"
            );
            RangeProbe::failed_to_run()
        });
    NamingSurface {
        zone: ZONE,
        reserved_range: range_text(),
        loopback_aliases_present: probe.present(),
        interim_loopback: probe.interim(),
        resolver_hook: hook,
        bind_probe: BindProbe::from(&probe),
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
            "sudo".into(),
            format!("ip addr replace {ZONE_LINK_ADDR}/32 dev {ZONE_LINK}"),
            format!("resolvectl dns {ZONE_LINK} 127.0.0.1:{port}"),
            format!("resolvectl domain {ZONE_LINK} '~{ZONE}'"),
            format!("resolvectl default-route {ZONE_LINK} false"),
        ]
    }

    // NET-138: the VM-backed host's answerer lines. The state the VM host
    // daemon's control socket answers is the fact both verbs surface, and
    // the wording is pinned here because the session e2e greps `min ls`
    // for exactly this line.
    #[test]
    fn vm_host_answerer_line_names_the_holder() {
        // The lone-holder shape: this VM's minvmd holds the port.
        let line = vm_host_answerer_line(ZoneAnswererStatus::Holder { port: 7_656 })
            .expect("the holder state prints its line");
        assert_eq!(
            line,
            "answered by the VM host daemon (single-operator interim) · this \
             VM's minvmd holds it on 127.0.0.1:7656 (UDP) · point the host's \
             resolver at it for *.min.internal"
        );
        // The co-resident shape: another daemon holds, this one registered.
        let line = vm_host_answerer_line(ZoneAnswererStatus::Registered { port: 7_656 })
            .expect("the registered state prints its line");
        assert_eq!(
            line,
            "answered by the VM host daemon (single-operator interim) · \
             another VM host daemon holds it on 127.0.0.1:7656 (UDP); this \
             VM's table is registered with it · point the host's resolver at \
             it for *.min.internal"
        );
        // The arm that must not claim an answer: a port held by a process
        // no channel reaches means this VM's names are not answered on the
        // host, and saying "answered by" there would be the lie.
        let line = vm_host_answerer_line(ZoneAnswererStatus::PortHeldNoChannel { port: 7_656 })
            .expect("the no-channel state prints its line");
        assert_eq!(
            line,
            "not answered on the host · a process no zone-answerer channel \
             reaches holds 127.0.0.1:7656, so this VM's minvmd answers \
             nothing and its names are not answered on the host"
        );
        assert!(
            !line.contains("answered by the VM host daemon"),
            "a port with no daemon behind it is not an answered zone: {line}"
        );
        // The pre-acquisition state prints nothing, like a daemon still
        // bringing a listener up.
        assert_eq!(vm_host_answerer_line(ZoneAnswererStatus::Starting), None);
    }

    /// NET-138's session-start warning: the fact and the surface, the exact
    /// text every session start prints when the port is held by a process
    /// no channel reaches — pinned because the warning rides stderr at
    /// every start, TTY and non-TTY, and a wrong fact there strands the
    /// user at the first failed lookup.
    #[test]
    fn port_held_no_channel_warning_says_the_fact_and_the_surface() {
        assert_eq!(
            port_held_no_channel_warning(7_656),
            "warning: this VM's box names are not answered on the host: a \
             process no zone-answerer channel reaches holds the zone \
             answerer's port 127.0.0.1:7656. The hostname proxy remains the \
             surface the names route through."
        );
    }

    /// The verdict the status decides on its own, without reading this
    /// host's files: the no-channel state settles the proxy by the status's
    /// word (the port is no daemon's answerer, so no hook or range could
    /// make it native), and the pre-acquisition state claims nothing. The
    /// two decided states' arms read this host's own resolver state, so
    /// they are the e2e's to prove on a real VM host, not a unit test's to
    /// pin against whatever machine runs it.
    #[tokio::test]
    async fn vm_host_name_surface_decides_the_status_settled_arms_alone() {
        assert_eq!(
            vm_host_name_surface(ZoneAnswererStatus::Starting).await,
            None,
            "the pre-acquisition state names no surface"
        );
        assert_eq!(
            vm_host_name_surface(ZoneAnswererStatus::PortHeldNoChannel { port: 7_656 }).await,
            Some(LiveSurface::Proxy),
            "a port held by a process no channel reaches is the proxy's verdict"
        );
    }

    /// The liveness query's negative arms, the ones a unit test can pin
    /// without the answerer: a port nothing answers — held by a silent
    /// process, or free — is not a bound answerer, whatever the status
    /// read said, because the query is the proof and the status only the
    /// pointer. The positive arm (the answerer answering this exact query)
    /// is the minvmd answerer tests' wire and the session e2e's dig.
    #[tokio::test]
    async fn answerer_bound_at_reads_silent_and_closed_ports_as_not_bound() {
        // A silent holder: a socket bound on loopback that never answers.
        let silent = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .expect("the silent stand-in binds");
        let port = silent.local_addr().expect("the port is named").port();
        assert!(
            !answerer_bound_at(port).await,
            "a silent port is not a bound answerer"
        );
        // A free port: the query's datagram has nothing to reach.
        let probe =
            std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("the probe binds");
        let free = probe.local_addr().expect("the port is named").port();
        drop(probe);
        assert!(
            !answerer_bound_at(free).await,
            "a port nothing holds is not a bound answerer"
        );
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
        let advisory = advisory_at(&unconfigured, port, false, None, None)
            .expect("an unconfigured host must be advised");
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

        // A hook already routing this answerer is not advised again — on a
        // host whose own loopback carries the range, the quiet arm's every
        // fact holds.
        let configured = Hook::configured("test", Some(port), "routes the zone");
        assert!(
            advisory_at(&configured, port, false, Some(true), None).is_none(),
            "a configured host must not be re-advised"
        );

        // A hook routing a *stale* port is advised: the command points the
        // resolver at this daemon's answerer, not the old one's.
        let stale = Hook::configured("test", Some(port - 1), "routes the zone elsewhere");
        let advisory = advisory_at(&stale, port, false, None, None)
            .expect("a stale hook must be re-advised for this answerer's port");
        for marker in command_markers(port) {
            assert!(
                advisory.contains(&marker),
                "the re-advice must name the exact command ({marker}): {advisory}"
            );
        }

        // NET-123's interim arm: a session published at the 127.0.0.1
        // interim re-surfaces the advisory even when the hook routes.
        let interim = advisory_at(&configured, port, true, None, None)
            .expect("the interim must re-surface the advisory");
        assert!(
            interim.contains("127.0.0.1 interim"),
            "the interim advisory must name the interim: {interim}"
        );
        assert!(interim.contains(&range_text()));
        // The interim fact names what is missing — the range on the host's
        // loopback — and does not claim the command below ends it: the
        // command rendered today configures the resolver only, and the
        // range step is not yet part of it (design §7.1 makes it so).
        assert!(
            interim.contains("is not installed on this host's loopback"),
            "the interim advisory must name the missing range: {interim}"
        );
        assert!(
            !interim.contains("nothing is needed"),
            "the interim advisory must not claim nothing ends it: {interim}"
        );
        for marker in command_markers(port) {
            assert!(
                interim.contains(&marker),
                "the interim advisory must name the exact command ({marker}): {interim}"
            );
        }
    }

    // The full path on this host: whatever `detect` finds, the advisory
    // either stays quiet because the hook already routes the port and
    // nothing blocks the command, or says what the host needs — this
    // platform's exact command, or the blocker that makes it dead. Either
    // arm is a pass; only the mismatch — advised without anything to say,
    // or quiet while the host cannot resolve the zone — fails.
    #[tokio::test]
    async fn session_advisory_agrees_with_the_hook_it_detected() {
        let port = 15353;
        let detection = session_detection().await;
        let advisory = session_advisory_at(&detection, Some(port), false, None);
        let (hook, blocker) = &detection;
        if hook.routes(port) && blocker.is_none() {
            assert!(advisory.is_none(), "configured host must not be advised");
        } else if let Some(blocker) = blocker {
            let advisory = advisory.expect("a host the command cannot reach must be told why");
            assert!(
                advisory.contains(blocker),
                "the advisory says why no command is named: {advisory}"
            );
            assert!(
                !advisory.contains("sudo"),
                "a command that does nothing is not named: {advisory}"
            );
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
        let detection = session_detection().await;
        assert!(session_advisory_at(&detection, None, false, None).is_none());
    }

    /// A routing hook for the answerer's port, the state a host is in once
    /// the advisory's command has run.
    fn routing_hook() -> Hook {
        Hook::configured("test", Some(15353), "test hook routes the zone")
    }

    #[test]
    fn native_surface_needs_all_three_facts() {
        let port = 15353;
        let routes = routing_hook();
        let blocker: Option<&str> = None;
        // All three facts: native DNS is live.
        assert!(
            native_surface_at(&routes, port, true, true, blocker),
            "a routing hook on a bound answerer over a present range is native DNS"
        );
        // Each fact on its own is the difference between native and the
        // proxy, so each missing one must drop the verdict.
        assert!(
            !native_surface_at(&routes, port, false, true, blocker),
            "an unbound answerer cannot answer the zone natively"
        );
        assert!(
            !native_surface_at(&Hook::absent("test", "no hook"), port, true, true, blocker),
            "a host whose resolver does not route the zone reads the proxy"
        );
        assert!(
            !native_surface_at(&routes, port, true, false, blocker),
            "a host without the reserved range has no published addresses to resolve"
        );
        // A dead hook: the routing-domain hook is
        // configured — it routes — but the stub-bypass blocker says no host
        // process's lookups consult what it configures, so it is dead
        // configuration and the verdict must not be native on its word.
        assert!(
            !native_surface_at(&routes, port, true, true, Some("lookups bypass resolved")),
            "a hook no host process consults does not make native DNS live"
        );
    }

    #[tokio::test]
    async fn live_surface_prints_nothing_until_the_answerer_binds() {
        // No port on the reply — the daemon still bringing its answerer up
        // — and no bound report are both the read that changes nothing:
        // nothing prints, and an old daemon's silence is never mistaken
        // for an answerer that serves.
        let detection = (routing_hook(), None);
        assert!(live_name_surface_at(&detection, None, true).await.is_none());
        assert!(
            live_name_surface_at(&detection, Some(15353), false)
                .await
                .is_none()
        );
        assert!(live_name_surface(None, false).await.is_none());
    }

    #[tokio::test]
    async fn live_surface_is_the_proxy_when_either_cheap_fact_is_missing() {
        let port = 15353;
        // A hook that does not route: proxy, settled without a probe.
        let absent = (Hook::absent("test", "no hook"), None);
        assert_eq!(
            live_name_surface_at(&absent, Some(port), true).await,
            Some(LiveSurface::Proxy),
            "a host whose resolver does not route the zone prints the proxy as live"
        );
        // A dead hook: a routing hook whose stub-bypass blocker
        // makes it configuration no host process consults — the proxy, and
        // both verbs must read it, never native on the hook's word alone.
        let blocked = (routing_hook(), Some("lookups bypass resolved".to_string()));
        assert_eq!(
            live_name_surface_at(&blocked, Some(port), true).await,
            Some(LiveSurface::Proxy),
            "a hook no host process consults is the proxy's story, on both verbs"
        );
    }

    /// NET-018's positive arm on the real host, on NET-018's verify line:
    /// the routing hook and the bound answerer are the two facts a table
    /// can spell, but the third — the reserved range on this host's own
    /// loopback — is a fact about a real loopback, so this arm runs the
    /// verdict's own bind probe against the host the suite runs on. Linux
    /// only: the whole `127/8` is local to `lo` there, so the probe always
    /// reads the range present and the arm takes the real path both verbs
    /// take to a native verdict — the same probe the daemon's
    /// session-start one mirrors (NET-123).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn activate_and_ls_report_native_surface_verdict_on_host() {
        let port = 15353;
        assert_eq!(
            live_name_surface_at(&(routing_hook(), None), Some(port), true).await,
            Some(LiveSurface::Native),
            "a routing hook on a bound answerer over this host's present range is \
             native DNS, and both verbs print it"
        );
    }

    #[tokio::test]
    async fn native_verdict_and_advisory_cannot_disagree() {
        let port = 15353;
        // The two lines share one read, so the states they print from are
        // the same: a host the verdict calls native is a host the advisory
        // has nothing to say about, and a host the advisory must warn is
        // one the verdict calls the proxy.
        let detection = (routing_hook(), None);
        let advisory = session_advisory_at(&detection, Some(port), false, Some(true));
        assert!(
            advisory.is_none(),
            "a native verdict has no advisory: {advisory:?}"
        );
        let blocked = (routing_hook(), Some("lookups bypass resolved".to_string()));
        assert!(
            session_advisory_at(&blocked, Some(port), false, Some(true)).is_some(),
            "the blocked hook is still the advisory's to say"
        );
        assert!(
            !native_surface_at(&blocked.0, port, true, true, blocked.1.as_deref()),
            "and it is the proxy the verdict names for the same read"
        );
        // The range-absent arm, the one state the daemon's interim flag
        // cannot vouch for: on a VM-backed host that flag reads the guest's
        // loopback, which always carries the range, so a host whose own
        // loopback lacks it is one only this host's read can name — and the
        // two lines must read it the one way. The verdict calls the proxy
        // for exactly this fact, so the advisory says the range is what is
        // missing rather than staying quiet on the daemon's `false`.
        let absent = session_advisory_at(&detection, Some(port), false, Some(false))
            .expect("a host whose own loopback lacks the range is the advisory's to say");
        assert!(
            absent.contains("is not installed on this host's loopback"),
            "the advisory names the missing range: {absent}"
        );
        assert!(
            !native_surface_at(&detection.0, port, true, false, None),
            "and the verdict for the same read is the proxy's, not native"
        );
    }

    #[test]
    fn name_surface_line_says_which_surface_and_where_the_proxy_serves() {
        let native = name_surface_line(LiveSurface::Native, Some(15390));
        assert!(
            native.contains("native DNS is the live name surface"),
            "the native arm names the surface: {native}"
        );
        assert!(
            native.contains("the hostname proxy still serves on 127.0.0.1:15390"),
            "the native arm says the proxy keeps serving beside it (NET-019): {native}"
        );
        let not_serving = name_surface_line(LiveSurface::Native, None);
        assert!(
            not_serving.contains("the hostname proxy is not serving"),
            "a daemon with no proxy port is one whose proxy is not serving: {not_serving}"
        );
        assert!(
            !not_serving.contains("still serves"),
            "with no port to name, the line must not claim the proxy serves: {not_serving}"
        );
        let proxy = name_surface_line(LiveSurface::Proxy, Some(15390));
        assert!(
            proxy.contains("the hostname proxy is the live name surface"),
            "the proxy arm names the surface: {proxy}"
        );
        assert!(
            proxy.contains("routes through it on 127.0.0.1:15390"),
            "the proxy arm names where it serves: {proxy}"
        );
        assert!(
            !proxy.contains("native DNS is the live name surface"),
            "the proxy arm must not say the native words: {proxy}"
        );
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
    fn linux_command_targets_a_dedicated_link_off_the_default_route() {
        let command = linux_command(15353);
        // The hook rides a link dedicated to the zone, never the host's
        // general-purpose DNS link: `resolvectl dns` and `resolvectl
        // domain` replace a link's lists, so on the general-purpose link
        // this command would wipe the host's upstream resolvers and search
        // domains.
        assert!(
            command.contains(&format!("ip link add {ZONE_LINK} type dummy")),
            "{command}"
        );
        assert!(
            command.contains(&format!("resolvectl dns {ZONE_LINK} 127.0.0.1:15353")),
            "{command}"
        );
        assert!(
            command.contains(&format!("resolvectl domain {ZONE_LINK} '~{ZONE}'")),
            "{command}"
        );
        // The link carries an address of global scope — the fact that makes
        // systemd-resolved treat it as relevant and ever consult its routing
        // domain. A bare dummy link has no address, is not relevant to
        // resolved, and its routing domain is configuration nothing consults:
        // the state the native lane's resolution check failed on. `replace`,
        // not `add`: a re-run on a host that still has the link must re-apply
        // the servers, not die on `File exists` before it reaches them.
        let address = format!("ip addr replace {ZONE_LINK_ADDR}/32 dev {ZONE_LINK}");
        assert!(command.contains(&address), "{command}");
        assert!(
            !command.contains("ip addr add "),
            "the address step must re-apply, not fail a re-run: {command}"
        );
        let up_at = command
            .find(&format!("ip link set {ZONE_LINK} up"))
            .expect("the link-up step is named");
        let address_at = command.find(&address).expect("the address step is named");
        assert!(
            up_at < address_at,
            "the link must be up before it carries the address: {command}"
        );
        // The dedicated link never carries non-zone queries: it is
        // explicitly off the default route, and that flag is set before
        // its server, so not even a partially-run command leaves it a
        // default-route link (a link with servers and no routing domain is
        // one implicitly).
        let isolate = format!("resolvectl default-route {ZONE_LINK} false");
        let isolate_at = command
            .find(&isolate)
            .expect("the default-route step is named");
        let serve_at = command
            .find(&format!("resolvectl dns {ZONE_LINK}"))
            .expect("the dns step is named");
        assert!(
            isolate_at < serve_at,
            "default-route false must precede the server: {command}"
        );
        assert!(
            address_at < serve_at,
            "the routable address must precede the server it routes: {command}"
        );
        // A host that already has the link — a re-run after
        // `resolvectl revert`, which undoes the DNS configuration but not
        // the link — can run the command again: creation is guarded, the
        // rest re-applies.
        assert!(
            command.contains(&format!("[ -e /sys/class/net/{ZONE_LINK} ] || ")),
            "{command}"
        );
        // And it is one privileged step the user runs, not the session
        // start (NET-122: no privilege prompt — the prompt, if any, is the
        // paste's).
        assert!(command.starts_with("sudo "), "{command}");
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn a_stub_bypassing_host_is_advised_without_a_dead_command() {
        let domain = "Global Domains: ~.\nLink 2 (enp3s0): lab.example.com\n";
        // A resolv.conf naming anything but resolved's stub, on a host whose
        // resolved answered and whose lookups walk a chain with no `resolve`
        // source in it: host lookups bypass resolved, and the routing-domain
        // command would configure nothing they consult.
        let resolv_conf = "search example.com\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n";
        let nsswitch = "hosts: files dns myhostname\n";
        let blocker = stub_bypass_blocker(Some(domain), Some(resolv_conf), Some(nsswitch), false)
            .expect("a stub-bypassing host must block the command");
        assert!(blocker.contains("bypass systemd-resolved"), "{blocker}");
        assert!(blocker.contains("192.168.1.1 1.1.1.1"), "{blocker}");
        assert!(blocker.contains(RESOLVED_STUB), "{blocker}");

        let hook = Hook::absent("test", "no link carries a routing domain for the zone");
        let advisory = advisory_at(&hook, 15353, false, None, Some(&blocker))
            .expect("a stub-bypassing host is still advised");
        assert!(
            advisory.contains(&blocker),
            "the advisory says why no command is named: {advisory}"
        );
        assert!(
            !advisory.contains("sudo"),
            "a command that does nothing is not named, and no prompt is asked \
             for it: {advisory}"
        );
        assert!(
            !advisory.contains('?'),
            "an advisory never asks a question — it says what is wrong: {advisory}"
        );

        // The same host whose hook already routes this answerer's port —
        // `minzone0` configured earlier, `/etc/resolv.conf` since rewritten
        // to bypass the stub — is advised too, and by the blocker alone:
        // nothing is missing there, so the note carries no dangling `; `
        // where a fact would sit and no dead command either.
        let routed = Hook::configured("test", Some(15353), "the routing domain routes the zone");
        let advisory = advisory_at(&routed, 15353, false, None, Some(&blocker))
            .expect("a bypassing host is advised even when its hook routes");
        assert_eq!(
            advisory,
            format!("note: {blocker}."),
            "the note is the blocker alone, with no empty facts to separate: {advisory}"
        );

        // The stub named — alone or beside foreign servers — is a host the
        // command works on: no blocker, the command is named.
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some("nameserver 127.0.0.53\n"),
                Some(nsswitch),
                false
            )
            .is_none()
        );
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some("nameserver 192.168.1.1\nnameserver 127.0.0.53\n"),
                Some(nsswitch),
                false
            )
            .is_none()
        );

        // No resolved to configure — `resolvectl domain` did not run — no
        // routing-domain command to withhold, however foreign the file: the
        // advisory's mechanism question does not arise on that host.
        assert!(stub_bypass_blocker(None, Some(resolv_conf), Some(nsswitch), false).is_none());

        // An unreadable or empty resolv.conf is no evidence against the stub:
        // the command is named rather than withheld for no reason.
        assert!(stub_bypass_blocker(Some(domain), None, Some(nsswitch), false).is_none());
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some("search example.com\n"),
                Some(nsswitch),
                false
            )
            .is_none(),
            "a file naming no resolver blocks nothing"
        );
    }

    // A host whose `hosts:` lookups consult `nss-resolve` is a host the
    // routing-domain command reaches however its `/etc/resolv.conf` is
    // written: the `resolve` source asks resolved directly, never the file's
    // servers. The blocker clears on that chain only, never on a bare
    // `resolve` token — the finding this answers: the token alone used to
    // read as a bypass and withheld a command the host's lookups could use.
    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn nss_resolved_lookups_clear_the_stub_bypass_blocker() {
        let domain = "Global Domains: ~.\n";
        let resolv_conf = "search example.com\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n";
        // systemd's own recommended chain: `files` first, `resolve` before
        // `dns`, with `!UNAVAIL=return` so a resolved that is down falls
        // through to `dns` — a hit still ends the walk, and `files`'s miss
        // walks on. The negated rule is lower-case on purpose: the statuses
        // and actions are matched case-insensitively, as they are written.
        let resolved_host =
            "passwd: files systemd\nhosts: files resolve [!unavail=Return] dns myhostname\n";
        assert!(
            stub_bypass_blocker(Some(domain), Some(resolv_conf), Some(resolved_host), true)
                .is_none(),
            "a chain whose lookups reach resolved is not a bypassing host"
        );

        // Which is the whole point: that host's advisory names the command.
        let hook = Hook::absent("test", "no link carries a routing domain for the zone");
        let advisory = advisory_at(&hook, 15353, false, None, None)
            .expect("an nss-resolve host is advised the command");
        assert!(
            advisory.contains("sudo"),
            "the command is named, not withheld: {advisory}"
        );

        // A bare `resolve` token clears nothing without the module behind
        // it: glibc reads a missing module as UNAVAIL and walks on to `dns`,
        // the file's foreign servers.
        assert!(
            stub_bypass_blocker(Some(domain), Some(resolv_conf), Some(resolved_host), false)
                .is_some(),
            "a `resolve` token without libnss_resolve is a bypassing host"
        );
        // Nor does a chain that names no `resolve` source at all.
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some(resolv_conf),
                Some("hosts: files mdns4_minimal dns\n"),
                true
            )
            .is_some()
        );
        // Nor one whose earlier rule ends the walk on a miss before it: for
        // the zone's names `mdns4_minimal` passes by, but the rule cannot be
        // read as passing them, and the blocker is the arm that withholds
        // what this cannot prove works.
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some(resolv_conf),
                Some("hosts: files mdns4_minimal [NOTFOUND=return] resolve dns\n"),
                true
            )
            .is_some()
        );
        // Nor one that asks the file's servers before it.
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some(resolv_conf),
                Some("hosts: files dns resolve [!UNAVAIL=return]\n"),
                true
            )
            .is_some()
        );
        // Nor one whose rules walk past resolved's own answer.
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some(resolv_conf),
                Some("hosts: files resolve [SUCCESS=continue] dns\n"),
                true
            )
            .is_some()
        );
        // Nor a chain this cannot read at all.
        assert!(
            stub_bypass_blocker(Some(domain), Some(resolv_conf), None, true).is_some(),
            "no `hosts:` chain to read proves nothing about where lookups go"
        );
        assert!(
            stub_bypass_blocker(
                Some(domain),
                Some(resolv_conf),
                Some("hosts: files resolve [a rule this cannot read]\n"),
                true
            )
            .is_some(),
            "a chain with an unreadable rule proves nothing either"
        );
    }

    // glibc dlopen's an NSS source's module by the exact name
    // `libnss_<source>.so.2`, out of the directories it searches, so the
    // paths this probes are load-bearing: a wrong name or a relative
    // directory is a host whose blocker never clears.
    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn the_resolve_module_is_looked_up_under_glibcs_module_name() {
        let candidates: Vec<String> = resolve_module_candidates().collect();
        assert!(!candidates.is_empty());
        assert!(
            candidates
                .iter()
                .all(|path| path.starts_with('/') && path.ends_with("/libnss_resolve.so.2")),
            "every candidate is the module's name under an absolute directory: {candidates:?}"
        );
    }

    /// The bundle's record of the probe carries the same counts and the
    /// refusal spelled out, so the record and the daemon's verdict cannot
    /// disagree about one host.
    #[test]
    fn the_bundle_record_mirrors_the_probe() {
        let refused = RangeProbe {
            bound: 3,
            probed: 254,
            first_failure: Some((
                Ipv4Addr::new(127, 0, 64, 4),
                std::io::ErrorKind::AddrNotAvailable,
            )),
        };
        let record = BindProbe::from(&refused);
        assert_eq!(record.bound, 3);
        assert_eq!(record.probed, 254);
        assert_eq!(
            record.first_refusal,
            Some((
                "127.0.64.4".to_string(),
                "address not available".to_string()
            ))
        );
        assert_eq!(
            BindProbe::from(&RangeProbe::failed_to_run()).first_refusal,
            None
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
        assert!(json.contains("127.0.64.0/24"), "{json}");
        assert!(json.contains("\"interim_loopback\": false"), "{json}");
        assert!(json.contains("\"port\": 15353"), "{json}");
    }

    // The mechanism under the detection's deadlines: a wedged
    // systemd-resolved — or its D-Bus bus — blocks the call indefinitely,
    // and no verb that reads it may hang (NET-123). A call past its bound
    // reads as absent, the arm the advisory is safe under.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn a_query_outliving_its_bound_reads_absent_instead_of_hanging() {
        let started = std::time::Instant::now();
        let read = bounded_query("sleep", &["30"], Duration::from_millis(50)).await;
        assert_eq!(read, None, "a call past its bound must read as absent");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the bound must give up on the call, not wait it out: {:?}",
            started.elapsed()
        );
    }

    // The arms besides the bound: a query that answers within it reads as
    // its stdout, and a binary that does not exist reads as absent — the
    // call a host with no systemd-resolved at all makes.
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn a_query_within_its_bound_reads_and_a_missing_one_reads_absent() {
        let read = bounded_query("printf", &["resolvectl answered"], RESOLVECTL_BOUND)
            .await
            .expect("a call within its bound must be read");
        assert_eq!(read.trim(), "resolvectl answered");
        assert!(
            bounded_query("minimal-no-such-binary", &[], RESOLVECTL_BOUND)
                .await
                .is_none(),
            "a missing binary must read as absent"
        );
    }

    // NET-018's list read, and the deadline it carries, sized for the
    // list's frequency: `min ls`
    // is the most frequently-invoked verb, run in loops and from shell
    // prompts, and the session start's generous deadline was never a choice
    // a list made. The two halves of the answer, each made testable by the
    // query stand-in: a wedged resolver costs the list one deadline, not a
    // hang, and the deadline is the pair's — paid once by the two queries
    // that run under it together, not once per query.
    //
    /// Serializes the window in which a query stand-in is installed: the
    /// stand-in is process-global (`query_program`), so under libtest —
    /// where every test in this binary shares one process — a detection
    /// driven by another test would read it too. Nextest runs each test
    /// in its own process; the mutex keeps the in-process runner as safe.
    #[cfg(not(target_os = "macos"))]
    static QUERY_STANDIN_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// One stand-in `resolvectl`: `script` written executable into a fresh
    /// tempdir and installed as the detection's query program. Dropping the
    /// guard clears the install and the script together; hold the stand-in
    /// mutex for the whole install→assert window, because the slot is
    /// process-global.
    #[cfg(not(target_os = "macos"))]
    struct QueryStandin {
        _script: tempfile::TempDir,
    }

    #[cfg(not(target_os = "macos"))]
    impl Drop for QueryStandin {
        fn drop(&mut self) {
            *QUERY_STANDIN.lock().unwrap() = None;
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn install_query_standin(script: &str) -> QueryStandin {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("a dir for the stand-in script");
        let path = dir.path().join("resolvectl");
        std::fs::write(&path, script).expect("the stand-in script to write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the stand-in script to be made executable");
        *QUERY_STANDIN.lock().unwrap() = Some(path.to_string_lossy().into_owned());
        QueryStandin { _script: dir }
    }

    /// A wedged resolver: a systemd-resolved wedged hard
    /// enough that both queries hang — the exact case the deadline exists
    /// for. The list still answers, inside its own one-second deadline and
    /// not the session start's five, and the verdict it prints is the
    /// proxy's — the arm a wedged resolver genuinely leaves, and the one
    /// that cannot strand the user, because the proxy keeps serving
    /// (NET-019).
    // The window is held across the awaited read on purpose: the stand-in
    // it installs is the point of the test.
    #[expect(
        clippy::await_holding_lock,
        reason = "the stand-in window must span the awaited read it stands in for"
    )]
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn a_wedged_resolver_costs_the_list_one_deadline_not_a_hang() {
        let _standin_window = QUERY_STANDIN_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let standin = install_query_standin("#!/bin/sh\nsleep 30\n");
        let started = std::time::Instant::now();
        let surface = live_name_surface(Some(15353), true).await;
        assert_eq!(
            surface,
            Some(LiveSurface::Proxy),
            "a wedged resolver leaves the proxy's arm — after {:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < LIST_RESOLVECTL_BOUND * 3,
            "the list's read must give up at its own deadline, not the session \
             start's: {:?} against the deadline {:?}",
            started.elapsed(),
            LIST_RESOLVECTL_BOUND
        );
        drop(standin);
    }

    /// The deadline is the pair's, paid once: two queries that each answer
    /// in 600 ms — slow but healthy, faster than the deadline — read whole
    /// under the one second the list allows, because they run together. A
    /// pair run one after the other instead would lose the second query to
    /// the same deadline (it starts at 600 ms and the deadline fires at
    /// 1 s), and a hook that reads takes both queries' facts together —
    /// the routing domain from `domain`, the 127.0.0.1:<port> server from
    /// `dns` — so the hook that routes is the proof both landed.
    // The window is held across the awaited read on purpose: the stand-in
    // it installs is the point of the test.
    #[expect(
        clippy::await_holding_lock,
        reason = "the stand-in window must span the awaited read it stands in for"
    )]
    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn the_lists_two_queries_run_under_one_deadline() {
        let _standin_window = QUERY_STANDIN_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let standin = install_query_standin(
            "#!/bin/sh\nsleep 0.6\n\
             if [ \"$1\" = domain ]; then \
             printf 'Global Domains: ~.\\nLink 2 (enp3s0): ~min.internal\\n'\nelse \
             printf 'Global: 10.0.0.1\\nLink 2 (enp3s0): 127.0.0.1:15353\\n'\nfi\n",
        );
        let (hook, _) = ls_detection().await;
        assert!(
            hook.routes(15353),
            "both queries must read within the one deadline — run together, not \
             one after the other: {hook:?}"
        );
        drop(standin);
    }
}
