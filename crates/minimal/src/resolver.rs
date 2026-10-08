//! The host-resolver side of in-zone name resolution (NET-122, NET-123).
//!
//! A daemon answers `*.{ZONE}` lookups from a UDP answerer it holds on the
//! host's loopback; the host's *native* resolver has to be pointed at that
//! answerer before any process on the host can resolve a box name with no
//! proxy settings (NET-009). The hook that points it is per-OS: a resolver
//! file under `/etc/resolver/` on macOS, a systemd-resolved routing domain
//! on a link dedicated to the zone on Linux. This module detects the hook,
//! renders the exact command that installs it — and, on macOS, the boot
//! step that reserves the local range in the same one `sudo` (design §7.1,
//! NET-123) — reads the reserved range's loopback state for the diagnostic
//! bundle, and, where the OS installs a range unit, checks its custody
//! beside the hook it detected.
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
use minimald_rpc::{ProxyDownCause, ZoneAnswererStatus};
use serde::Serialize;
use std::net::Ipv4Addr;
use std::time::Duration;
use switch::loopback::RangeProbe;

/// The zone the daemon's answerer holds: the sessions zone's apex, the one
/// spelling the daemons' registries read too.
pub(crate) const ZONE: &str = sessions::core::zone_answer::ZONE_APEX;

/// The link dedicated to [`ZONE`]'s DNS hook on Linux: a dummy interface
/// the advisory's command creates, whose only job is to carry the routing
/// domain that scopes the zone to the answerer (NET-122: the design's
/// "dedicated link of routable scope"). The host's general-purpose DNS
/// link keeps its servers, domains and default-route flag untouched — a
/// link that exists for the zone alone is what keeps `resolvectl dns`'s
/// replace-semantics from ever reaching the host's upstream resolution.
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

/// The label of the LaunchDaemon unit the macOS advisory command installs
/// beside the resolver file: the boot-time service that re-applies the
/// reserved local range at every boot (design §7.1's privileged step,
/// NET-123's macOS half). The unit's plist, its program, the command that
/// installs both, and the custody checks over them, all name these three
/// constants — one definition beside the command that writes them, so the
/// installed unit, the advisory that reinstalls it, and the bundle that
/// reads it cannot drift apart.
pub(crate) const RANGE_UNIT_LABEL: &str = "dev.minimal.local-range";

/// The root-owned path the unit's program is installed at, inside the
/// system-managed helper directory — a path no user can write: `/Library`
/// and every directory under it is root's, and the custody check
/// ([`range_step_over`]) walks every directory component of both this
/// path and the plist's, from `/` down, so a unit under `$HOME` or a
/// user-owned Homebrew prefix fails custody whatever its files' own owner
/// reads.
pub(crate) const RANGE_PROGRAM_PATH: &str =
    "/Library/PrivilegedHelperTools/dev.minimal.local-range";

/// The root-owned path the unit's plist is installed at: the plist launchd
/// scans at boot, which is what makes the range re-apply at every one.
pub(crate) const RANGE_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.minimal.local-range.plist";

/// The directories the two files live in, which the command makes before it
/// writes them: `mkdir -p`, because a stock host has no
/// `/Library/PrivilegedHelperTools` and the command must not die on its
/// first range step.
#[cfg(any(test, target_os = "macos"))]
const RANGE_PROGRAM_DIR: &str = "/Library/PrivilegedHelperTools";
#[cfg(any(test, target_os = "macos"))]
const RANGE_PLIST_DIR: &str = "/Library/LaunchDaemons";

/// The range program's template
/// ([`reserve-local-range.sh`](resolver/reserve-local-range.sh)): a `/bin/sh`
/// script whose [`RANGE_ADDRESS_PLACEHOLDER`] list is replaced at command
/// time with every usable host address of [`RESERVED_LOCAL_RANGE`]. The
/// rendered program reads no argument, no environment variable and no file,
/// and neither template carries an apostrophe — the command that carries
/// them wraps its whole payload in single quotes, and one inside a body
/// would close them (see [`macos_command`]).
#[cfg(any(test, target_os = "macos"))]
const RANGE_PROGRAM_TEMPLATE: &str = include_str!("resolver/reserve-local-range.sh");

/// The line of [`RANGE_PROGRAM_TEMPLATE`] the render replaces.
#[cfg(any(test, target_os = "macos"))]
const RANGE_ADDRESS_PLACEHOLDER: &str = "@RANGE_ADDRESSES@";

/// The unit's plist, as the command writes it: label [`RANGE_UNIT_LABEL`],
/// ProgramArguments the root-owned program path alone, `RunAtLoad` true, no
/// `KeepAlive`, no `UserName` (it runs as root), no environment variables.
#[cfg(any(test, target_os = "macos"))]
const RANGE_UNIT_PLIST: &str = include_str!("resolver/dev.minimal.local-range.plist");

/// The heredoc delimiters the command carries the two files' bytes under.
/// Distinctive enough that no rendered byte can close one early: the
/// program's lines are `ifconfig` aliases and the plist's are XML, and
/// neither can spell these. The leading `\` in the command quotes the
/// delimiter, so the body's lines are written byte for byte, never expanded.
#[cfg(any(test, target_os = "macos"))]
const RANGE_PROGRAM_HEREDOC: &str = "MINIMAL_RANGE_PROGRAM_EOF";
#[cfg(any(test, target_os = "macos"))]
const RANGE_PLIST_HEREDOC: &str = "MINIMAL_RANGE_PLIST_EOF";

/// Whether the command the advisory names also reserves the local range:
/// on macOS the one `sudo sh -c` writes the resolver file *and* installs
/// the range unit (design §7.1's privileged step), so the advisory's lead
/// sentence and its interim fact say so; on Linux the whole `127/8` is
/// local to `lo`, the command configures the routing-domain link alone,
/// and it takes no range step.
///
/// A constant of the platform, never of the render: the advisory is pure
/// over the [`RangeStep`] it is handed (see [`advisory_at`]), so the suite
/// unit-tests both arms' text on every platform it runs on, and this
/// constant decides only what the *detection* reads on the host it runs
/// against ([`read_range_step`]).
#[cfg(target_os = "macos")]
const COMMAND_RESERVES_THE_RANGE: bool = true;
#[cfg(not(target_os = "macos"))]
const COMMAND_RESERVES_THE_RANGE: bool = false;

/// The label of the box-zone answerer service the advisory command
/// installs (NET-122's host service): launchd's job label on macOS,
/// systemd's unit name on Linux — the one service the machine's service
/// manager holds the answerer's two sockets under and runs as the
/// operator, so the zone keeps answering between sessions and across
/// them, from a program no user can write to. The unit files, the
/// command that installs them, and the custody checks over them all name
/// this one label beside [`RANGE_UNIT_LABEL`]'s step — one definition, so
/// the service the command installs, the step the advisory re-surfaces
/// until it holds, and the unit the bundle records cannot drift apart:
/// [`ANSWERER_LAUNCHD_LABEL`] on macOS, [`ANSWERER_SYSTEMD_UNIT`] elsewhere.
#[cfg(target_os = "macos")]
pub(crate) const ANSWERER_UNIT_LABEL: &str = ANSWERER_LAUNCHD_LABEL;
#[cfg(not(target_os = "macos"))]
pub(crate) const ANSWERER_UNIT_LABEL: &str = ANSWERER_SYSTEMD_UNIT;

/// launchd's job label for the answerer service (see
/// [`ANSWERER_UNIT_LABEL`]); the plist file is named after it.
#[cfg(any(test, target_os = "macos"))]
const ANSWERER_LAUNCHD_LABEL: &str = "dev.gominimal.zone";

/// systemd's unit name stem for the answerer service (see
/// [`ANSWERER_UNIT_LABEL`]): `minzoned.socket` and `minzoned.service`,
/// named after the program they run.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_SYSTEMD_UNIT: &str = "minzoned";

/// The root-owned path the answerer program is copied to — never a
/// user-writable binary: `/Library/PrivilegedHelperTools` beside the range
/// program, every component of it root's, so a user can neither replace
/// the copy the service runs nor read what the step wrote before the
/// ownership converged ([`answerer_step_over`] walks every component).
#[cfg(any(test, target_os = "macos"))]
const MACOS_ANSWERER_PROGRAM_PATH: &str = "/Library/PrivilegedHelperTools/minzoned";

/// The plist the answerer step installs: the file launchd scans at boot,
/// which is what makes the service hold the sockets at every one.
#[cfg(any(test, target_os = "macos"))]
const ANSWERER_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.gominimal.zone.plist";

/// The root-owned path the answerer program is copied to on Linux — never
/// a user-writable binary, the same rule as [`MACOS_ANSWERER_PROGRAM_PATH`]'s
/// macOS arm: `/usr/local/lib/minimal` is root's alone, and the walk over
/// it is what custody means here.
#[cfg(any(test, not(target_os = "macos")))]
const LINUX_ANSWERER_PROGRAM_PATH: &str = "/usr/local/lib/minimal/minzoned";

/// The root-owned program copy this host's step installs and its checks
/// read back: [`MACOS_ANSWERER_PROGRAM_PATH`] on macOS,
/// [`LINUX_ANSWERER_PROGRAM_PATH`] elsewhere. Both renders compile under
/// test on either platform, each with its own platform's path.
#[cfg(target_os = "macos")]
pub(crate) const ANSWERER_PROGRAM_PATH: &str = MACOS_ANSWERER_PROGRAM_PATH;
#[cfg(not(target_os = "macos"))]
pub(crate) const ANSWERER_PROGRAM_PATH: &str = LINUX_ANSWERER_PROGRAM_PATH;

/// The directory [`LINUX_ANSWERER_PROGRAM_PATH`] lives in, which the command
/// makes before it copies.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_PROGRAM_DIR: &str = "/usr/local/lib/minimal";

/// The systemd socket unit the answerer step installs: the unit that
/// holds both of the answerer's sockets for the machine — the datagram
/// listener at the answerer's port on the host loopback and the unix
/// stream channel at the channel's path — and hands them to the service
/// at socket activation.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_UNIT_SOCKET_PATH: &str = "/etc/systemd/system/minzoned.socket";

/// The systemd service unit the answerer step installs: the unit that
/// runs the root-owned program copy as the operator and receives the
/// sockets the socket unit holds.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_UNIT_SERVICE_PATH: &str = "/etc/systemd/system/minzoned.service";

/// The unit files the step installs — launchd's one plist on macOS,
/// systemd's socket+service pair on Linux — in the order the custody
/// facts carry them and the walk covers them.
#[cfg(target_os = "macos")]
const ANSWERER_UNIT_PATHS: &[&str] = &[ANSWERER_PLIST_PATH];
#[cfg(not(target_os = "macos"))]
const ANSWERER_UNIT_PATHS: &[&str] = &[ANSWERER_UNIT_SOCKET_PATH, ANSWERER_UNIT_SERVICE_PATH];

/// The launchd unit the answerer step installs, as the command writes
/// it: label [`ANSWERER_LAUNCHD_LABEL`], `ProgramArguments` the root-owned
/// `minzoned` copy and nothing else, `UserName` the operator
/// the service manager runs it as — never root: the channel's uid gate
/// serves the uid the unit names, so a root-run service is one no daemon
/// of this operator could ever publish to — and the two sockets launchd
/// itself holds and hands over at socket activation: the `Listener`
/// datagram at [`minvmd::net::answerer::DEFAULT_ANSWERER_PORT`] on the
/// host loopback (`SockType dgram`: launchd's default type is `stream`,
/// which it cannot pair with UDP, and the name then activates no socket;
/// `SockNodeName`, the key launchd binds by, else the port takes every
/// interface) and the `Channel` unix stream at the channel's path,
/// named exactly as [`minvmd::cmd::answerer::LISTENER_SOCKET_NAME`] and
/// [`minvmd::cmd::answerer::CHANNEL_SOCKET_NAME`] spell them in code, so
/// the names the service asks launchd for and the names this unit
/// carries cannot drift apart. `SockPathMode 0666`: every daemon the
/// operator runs must be able to connect and publish, and the
/// answerer's own gate — the peer uid check — decides who may, so the
/// socket's mode grants only the connect.
///
/// Like [`RANGE_UNIT_PLIST`], the body carries no apostrophe: the command
/// rides inside one pair of single quotes, and one inside a body closes
/// them.
#[cfg(any(test, target_os = "macos"))]
const ANSWERER_PLIST_TEMPLATE: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key>
\t<string>dev.gominimal.zone</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>__PROGRAM__</string>
\t</array>
\t<key>UserName</key>
\t<string>__OPERATOR__</string>
\t<key>Sockets</key>
\t<dict>
\t\t<key>Listener</key>
\t\t<dict>
\t\t\t<key>SockFamily</key>
\t\t\t<string>IPv4</string>
\t\t\t<key>SockType</key>
\t\t\t<string>dgram</string>
\t\t\t<key>SockProtocol</key>
\t\t\t<string>UDP</string>
\t\t\t<key>SockNodeName</key>
\t\t\t<string>127.0.0.1</string>
\t\t\t<key>SockServiceName</key>
\t\t\t<string>7656</string>
\t\t</dict>
\t\t<key>Channel</key>
\t\t<dict>
\t\t\t<key>SockFamily</key>
\t\t\t<string>Unix</string>
\t\t\t<key>SockPathName</key>
\t\t\t<string>__CHANNEL__</string>
\t\t\t<key>SockPathMode</key>
\t\t\t<integer>438</integer>
\t\t</dict>
\t</dict>
\t<key>RunAtLoad</key>
\t<true/>
\t<key>KeepAlive</key>
\t<true/>
</dict>
</plist>
";

/// The systemd socket unit the answerer step installs, as the command
/// writes it: both sockets held by the machine's service manager — the
/// datagram listener at [`minvmd::net::answerer::DEFAULT_ANSWERER_PORT`]
/// on the host loopback, the unix stream channel at the machine-global
/// path — with `SocketMode 0666` for the channel (the connect is what every
/// daemon of the operator needs; the answerer's uid gate decides who may
/// publish), and the channel's directory the unit's own `RuntimeDirectory`
/// (`/run/minimal`, root's, made when the sockets are bound and removed
/// with them). `WantedBy=sockets.target` is what makes `enable` hold the
/// sockets at every boot after the step runs.
///
/// The body carries no `$`, no backtick and no double quote: the Linux
/// command rides inside one pair of double quotes, and any of the three
/// would leave it before the root shell reads it.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_SOCKET_TEMPLATE: &str = "\
[Unit]
Description=The Minimal box-zone answerer sockets

[Socket]
ListenDatagram=127.0.0.1:7656
ListenStream=__CHANNEL__
SocketMode=0666
__RUNTIME_DIRECTORY__Service=minzoned.service

[Install]
WantedBy=sockets.target
";

/// The systemd service unit the answerer step installs, as the command
/// writes it: the root-owned `minzoned` copy, run as the operator — `User=` is the uid the channel's
/// gate serves, the one whose daemons may publish — and restarted when
/// it dies, because the sockets it serves belong to the socket unit, not
/// the process: a service that comes back serves from the same
/// manager-held sockets without a session's action.
///
/// The same body ban as [`ANSWERER_SOCKET_TEMPLATE`]'s: no `$`, no
/// backtick, no double quote.
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_SERVICE_TEMPLATE: &str = "\
[Unit]
Description=The Minimal box-zone answerer, run by the operator

[Service]
Type=simple
ExecStart=__PROGRAM__
User=__OPERATOR__
Restart=on-failure
";

/// The heredoc delimiters the command carries the unit files' bytes
/// under, beside [`RANGE_PROGRAM_HEREDOC`]'s pair: quoted delimiters, so
/// the bodies write byte for byte — the plist is XML and the unit files
/// are INI, and neither can spell these.
#[cfg(any(test, target_os = "macos"))]
const ANSWERER_PLIST_HEREDOC: &str = "MINIMAL_ANSWERER_PLIST_EOF";
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_SOCKET_HEREDOC: &str = "MINIMAL_ANSWERER_SOCKET_EOF";
#[cfg(any(test, not(target_os = "macos")))]
const ANSWERER_SERVICE_HEREDOC: &str = "MINIMAL_ANSWERER_SERVICE_EOF";

/// The range program, rendered from [`RANGE_PROGRAM_TEMPLATE`] with every
/// usable host address of the reserved range
/// ([`switch::loopback::range_hosts`], host parts 1 to 254 — the addresses
/// the bind probe reads) filled in at render time, one literal address per
/// word of the list the program walks. The rendered script reads no
/// argument, no environment variable and no file — its one read is the
/// interface's own state, reported by the same absolute-path system tool
/// the aliases are added with, so nothing user-writable can change what it
/// applies — and it applies exactly the reserved range and nothing else:
/// each address is one `/32` lo0 alias by the two-address `ifconfig` form
/// the loopback-alias spike verified against lo0, and an address `lo0`
/// already carries is skipped rather than re-added, so a re-run over a
/// fully- or partially-applied range adds only what is missing (the spike
/// never measured a re-add, so the program does not rely on one exiting
/// zero).
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn range_program() -> String {
    let addresses = switch::loopback::range_hosts()
        .map(|addr| addr.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    RANGE_PROGRAM_TEMPLATE.replace(RANGE_ADDRESS_PLACEHOLDER, &addresses)
}

/// One path's custody facts, as the range unit's checks read them: the
/// owner uid and the permission bits of a file or a directory component.
/// `mode` is what `stat` reports, `st_mode & 0o7777`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct FileCustody {
    /// The owning uid.
    pub owner: u32,
    /// The permission bits, base 8 (`0644` reads `420`).
    pub mode: u32,
}

impl FileCustody {
    /// Whether this is root's file, with no group or other write: the
    /// custody every component of the unit's paths and both its files must
    /// hold — uid 0 owning, and nobody but root able to change what sits
    /// there.
    pub(crate) fn root_owned(&self) -> bool {
        self.owner == 0 && self.mode & 0o022 == 0
    }
}

/// The state of the range step on this host, as the advisory, the
/// session-start log line, and the bundle print it: the one-line view of
/// [`RangeStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub(crate) enum RangeStepState {
    /// This host's OS installs no range unit: the whole `127/8` is local
    /// to its loopback (Linux), the advisory's command configures the
    /// resolver alone, and no custody question arises.
    #[default]
    NotNeeded,
    /// macOS: nothing is installed at the unit's paths.
    Absent,
    /// macOS: the unit is installed and every custody check holds over
    /// its path, its files, its plist and its loaded job.
    Installed,
    /// macOS: a custody check failed — [`RangeStep::failed_check`] names it.
    CustodyFailed,
}

/// The range step on this host, as the detection reads it beside the hook:
/// the macOS range unit's state, the custody check that failed when one
/// did, and the facts the `min bug` bundle records — whether the unit is
/// installed, the owner and mode of its plist and its program, the
/// program path the plist runs, and the program path the loaded job runs.
/// On a host whose OS needs no step, the state alone says so.
///
/// The advisory, the log and the bundle are pure over this: the tests hand
/// the render functions either arm's step and assert its text, so the
/// suite covers both platforms' behaviour on every platform it runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RangeStep {
    /// The one-line view.
    pub state: RangeStepState,
    /// The custody check that failed, spelled out for the advisory and the
    /// bundle, when one did.
    pub failed_check: Option<String>,
    /// The program file's owner and mode, when it exists.
    pub program: Option<FileCustody>,
    /// The plist file's owner and mode, when it exists.
    pub plist: Option<FileCustody>,
    /// The program path the plist's `ProgramArguments` names, when it
    /// names one.
    pub plist_program: Option<String>,
    /// The program path the loaded job's `Program`/`ProgramArguments`
    /// names, when a job is loaded under the unit's label.
    pub loaded_program: Option<String>,
}

impl RangeStep {
    /// The step a host whose OS installs no range unit carries: no state
    /// to read, no custody to check, nothing for the bundle to record —
    /// Linux's `lo` is the whole `127/8`, so the command the advisory
    /// names configures the resolver and nothing else.
    pub(crate) fn not_needed() -> Self {
        RangeStep {
            state: RangeStepState::NotNeeded,
            failed_check: None,
            program: None,
            plist: None,
            plist_program: None,
            loaded_program: None,
        }
    }

    /// Whether the step's custody holds — the fact the advisory's quiet
    /// arm needs beside the probe's present (NET-123: the advisory stops
    /// re-surfacing for the range once the probe reads present *and*
    /// custody holds). A host that needs no step holds vacuously; an
    /// absent unit does not — a range with no unit behind it is a range
    /// the next boot removes.
    pub(crate) fn custody_holds(&self) -> bool {
        matches!(
            self.state,
            RangeStepState::NotNeeded | RangeStepState::Installed
        )
    }
}

/// The facts the range unit's custody checks decide on, as the macOS
/// detection gathers them and [`range_step_over`] reads them. Pure data,
/// so the checks over it — the path walk, the file ownership, the plist's
/// and the loaded job's program paths — are unit-tested on every platform
/// the suite runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub(crate) struct RangeFacts {
    /// The owner and mode of every directory component of both the unit's
    /// paths, from `/` down, as the walk read them. A component with no
    /// entry here did not read; the verdict treats it as unverified, never
    /// as passing.
    pub components: Vec<(String, FileCustody)>,
    /// The program file's owner and mode, when it exists.
    pub program: Option<FileCustody>,
    /// The plist file's owner and mode, when it exists.
    pub plist: Option<FileCustody>,
    /// The program path the plist's `ProgramArguments` names, when it
    /// names one.
    pub plist_program: Option<String>,
    /// The program path the loaded job's `Program`/`ProgramArguments`
    /// names, when a job is loaded under the unit's label.
    pub loaded_program: Option<String>,
}

/// Every directory component of `path`, from `/` down: the walk the
/// custody check makes, so a path under `$HOME` or a user-owned Homebrew
/// prefix fails on the component that makes it user-writable, never on the
/// files' own owner alone. The path's last component — the file — is not a
/// directory and is not walked here; its custody is checked beside the
/// walk. Pure, so the walk is unit-tested on every platform the suite runs
/// on.
pub(crate) fn path_components(path: &str) -> Vec<String> {
    let mut components = vec!["/".to_string()];
    let mut prefix = String::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        prefix.push('/');
        prefix.push_str(component);
        components.push(prefix.clone());
    }
    components.pop();
    components
}

/// The custody wording for a path that is not root's, with what it read.
fn not_root_owned(what: &str, path: &str, custody: &FileCustody) -> String {
    format!(
        "{what} {path} is owned by uid {} with mode {:o}, not root with \
         no group or other write",
        custody.owner, custody.mode
    )
}

/// The range step the custody facts decide (NET-123's privileged step's
/// custody, checked where the hook is detected): absent when neither of
/// the unit's files is installed; installed when every check holds — every
/// directory component of both paths root-owned with no group or other
/// write, both files root-owned with no group or other write, the plist's
/// `ProgramArguments` naming the root-owned program path, and the loaded
/// job's `Program`/`ProgramArguments` in `launchctl print` naming that
/// same path, so a job loaded from elsewhere under the label fails
/// custody; custody failed, naming the first check that did not hold.
///
/// Pure over the facts, so every check is unit-tested on every platform
/// the suite runs on; the macOS detection is the reader that gathers them
/// ([`range_unit_state`]).
pub(crate) fn range_step_over(facts: &RangeFacts) -> RangeStep {
    let mut step = RangeStep {
        state: RangeStepState::CustodyFailed,
        failed_check: None,
        program: facts.program,
        plist: facts.plist,
        plist_program: facts.plist_program.clone(),
        loaded_program: facts.loaded_program.clone(),
    };
    // Nothing at either path: the unit is not installed, the interim's
    // and the missing-range facts' state, and no custody question arises.
    if facts.program.is_none() && facts.plist.is_none() {
        step.state = RangeStepState::Absent;
        return step;
    }
    // The walk, from `/` down over both paths, in the order the checks are
    // stated: a directory a user can write is a unit a user can replace,
    // whatever the files' own owner reads.
    let mut walked = Vec::new();
    for path in [RANGE_PROGRAM_PATH, RANGE_PLIST_PATH] {
        for component in path_components(path) {
            if !walked.contains(&component) {
                walked.push(component);
            }
        }
    }
    let mut checks = Vec::new();
    for component in &walked {
        let Some(custody) = facts
            .components
            .iter()
            .find(|(path, _)| path == component)
            .map(|(_, custody)| custody)
        else {
            checks.push(format!("its directory {component} did not read"));
            continue;
        };
        if !custody.root_owned() {
            checks.push(not_root_owned("its directory", component, custody));
        }
    }
    // Both files, then what each of them points at.
    for (what, path, custody) in [
        ("its program", RANGE_PROGRAM_PATH, facts.program),
        ("its plist", RANGE_PLIST_PATH, facts.plist),
    ] {
        match custody {
            None => checks.push(format!("{what} {path} is missing")),
            Some(custody) if !custody.root_owned() => {
                checks.push(not_root_owned(what, path, &custody));
            }
            Some(_) => {}
        }
    }
    match facts.plist_program.as_deref() {
        None => checks.push(format!(
            "its plist's ProgramArguments names no program, not the \
             root-owned {RANGE_PROGRAM_PATH}"
        )),
        Some(RANGE_PROGRAM_PATH) => {}
        Some(other) => checks.push(format!(
            "its plist's ProgramArguments names {other}, not the \
             root-owned {RANGE_PROGRAM_PATH}"
        )),
    }
    match facts.loaded_program.as_deref() {
        None => checks.push(format!(
            "no job is loaded under the label {RANGE_UNIT_LABEL}, so the \
             installed files are not the unit that runs"
        )),
        Some(RANGE_PROGRAM_PATH) => {}
        Some(other) => checks.push(format!(
            "the loaded job under the label {RANGE_UNIT_LABEL} runs {other}, \
             not the root-owned {RANGE_PROGRAM_PATH}"
        )),
    }
    match checks.first() {
        None => step.state = RangeStepState::Installed,
        Some(check) => step.failed_check = Some(check.clone()),
    }
    step
}

/// The program path the plist's `ProgramArguments` names: the first
/// `<string>` after the `ProgramArguments` key, as launchd reads it.
/// `None` when the key or its argument is not there. Pure over the file's
/// bytes, so the parse is unit-tested on every platform the suite runs on.
pub(crate) fn plist_program_argument(text: &str) -> Option<&str> {
    let key = text.find("<key>ProgramArguments</key>")?;
    let argument = text[key..].find("<string>")? + key;
    let end = text[argument..].find("</string>")? + argument;
    Some(text[argument + "<string>".len()..end].trim())
}

/// The program path a `launchctl print` names for the unit: its `program`
/// line, else the first argument of its `program arguments` block — the
/// two fields a loaded job's program reaches the reader through.
/// `None` when neither reads (an output of a job that is not loaded, or
/// one whose arguments carry nothing). Pure, so the parse is unit-tested
/// on every platform the suite runs on.
pub(crate) fn launchctl_program_path(output: &str) -> Option<&str> {
    for line in output.lines() {
        if let Some(program) = line.trim().strip_prefix("program = ") {
            return Some(program.trim());
        }
    }
    let block = output.find("program arguments = {")?;
    let after = &output[block..];
    for line in after.lines().skip(1) {
        let line = line.trim();
        if line == "}" {
            return None;
        }
        if !line.is_empty() {
            return Some(line.trim_matches('"'));
        }
    }
    None
}

/// The owner and mode of `path`, when it exists.
async fn file_custody(path: &str) -> Option<FileCustody> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = tokio::fs::metadata(path).await.ok()?;
    Some(FileCustody {
        owner: metadata.uid(),
        mode: metadata.permissions().mode() & 0o7777,
    })
}

/// The owner and mode of every directory component of `paths`, from `/`
/// down, in walk order. A component that did not read simply carries no
/// facts; the verdict treats that as unverified, never as passing.
async fn path_component_custody(paths: &[&str]) -> Vec<(String, FileCustody)> {
    let mut components = Vec::new();
    for path in paths {
        for component in path_components(path) {
            if let Some(custody) = file_custody(&component).await {
                components.push((component, custody));
            }
        }
    }
    components
}

/// The program path the loaded job under [`RANGE_UNIT_LABEL`] names, from
/// `launchctl print`'s output: `None` when no job is loaded under the
/// label, or the print could not be read within [`LAUNCHCTL_BOUND`]. One
/// read-only call of the system's own service manager; nothing it does can
/// prompt, and a wedged launchd reads as unread — custody unverified, so
/// the advisory re-surfaces — rather than hanging the activate or `min ls`.
async fn launchctl_print_program() -> Option<String> {
    let output = tokio::time::timeout(
        LAUNCHCTL_BOUND,
        tokio::process::Command::new("launchctl")
            .arg("print")
            .arg(format!("system/{RANGE_UNIT_LABEL}"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    launchctl_program_path(&String::from_utf8(output.stdout).ok()?).map(str::to_string)
}

/// The range unit's state on this host, read where the hook is detected:
/// both files' presence, owner and mode; every directory component of both
/// their paths, from `/` down; the program path the plist's
/// `ProgramArguments` names; and the program path the loaded job's
/// `Program`/`ProgramArguments` names in `launchctl print` — the facts
/// [`range_step_over`] decides custody over. Read-only, and nothing
/// prompts: the same discipline as the hook detection it sits beside, and
/// the command that fixes what it finds is the user's to run, never the
/// session start's (NET-122).
pub(crate) async fn range_unit_state() -> RangeStep {
    let facts = RangeFacts {
        components: path_component_custody(&[RANGE_PROGRAM_PATH, RANGE_PLIST_PATH]).await,
        program: file_custody(RANGE_PROGRAM_PATH).await,
        plist: file_custody(RANGE_PLIST_PATH).await,
        plist_program: tokio::fs::read_to_string(RANGE_PLIST_PATH)
            .await
            .ok()
            .and_then(|text| plist_program_argument(&text).map(str::to_string)),
        loaded_program: launchctl_print_program().await,
    };
    range_step_over(&facts)
}

/// The range step this host's detection reads beside its hook, for the
/// advisory, the session-start log line, and the bundle: the unit's state
/// and custody where the host's OS installs one
/// ([`COMMAND_RESERVES_THE_RANGE`] — macOS, whose one advisory command
/// configures the resolver *and* reserves the range); the no-step state
/// everywhere else, where the loopback already carries the whole `127/8`.
async fn read_range_step() -> RangeStep {
    if COMMAND_RESERVES_THE_RANGE {
        range_unit_state().await
    } else {
        RangeStep::not_needed()
    }
}

/// The box-zone answerer's step on this host, as the detection reads it
/// beside the hook and the advisory, the session-start note, and the
/// bundle print it: the one-line view of the service NET-122's privileged
/// step installs — a host service whose two sockets the machine's service
/// manager holds, running as the operator, from a root-owned program copy
/// ([`ANSWERER_PROGRAM_PATH`]).
///
/// The states are the range step's ([`RangeStepState`]) with one the
/// range never carries: the installed copy can *fall behind* — speak a
/// channel protocol this daemon no longer understands — and that state
/// re-surfaces the advisory exactly like a custody failure, so an
/// upgrade that changes the wire re-runs the step and re-copies the
/// program the new daemon speaks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) enum AnswererStep {
    /// The service is installed and holds: root-owned program copy and
    /// unit files, the unit naming the copy, and the copy answering the
    /// channel protocol probe with this daemon's version.
    Installed,
    /// Nothing at the service's paths: no host service, so the zone
    /// answers only while a session's daemon holds it.
    Absent,
    /// A custody check failed — `failed_check` names the first one, in
    /// the range step's wording.
    CustodyFailed {
        /// The first check that did not hold.
        failed_check: String,
    },
    /// The installed copy speaks another channel protocol than this
    /// daemon — or did not answer the probe at all (`installed` `None`:
    /// a program from before the probe existed). The step re-runs to
    /// re-copy the program this daemon ships.
    ProtocolMismatch {
        /// The protocol version the installed copy answered with, when
        /// it answered.
        installed: Option<u32>,
        /// The protocol version this daemon speaks.
        daemon: u32,
    },
    /// The step's copy source — this machine's `minzoned` — passed the
    /// identity check the advisory runs before offering the privileged step
    /// ([`answerer_step_with_source`]), and its bytes are pinned: the
    /// command carries the step, copying exactly those bytes or nothing.
    /// `service` is the service state the detection read underneath.
    SourceVerified {
        /// The service state the checks read: what the host is missing.
        service: Box<AnswererStep>,
        /// The verified source and its pin.
        source: VerifiedSource,
    },
    /// The step's copy source failed the identity check the advisory runs
    /// before offering the privileged step ([`answerer_step_with_source`]):
    /// on macOS, the Developer ID requirement. The command then carries no
    /// answerer step at all. `service` is the service state the detection
    /// read underneath it, so the fact that names what the host is missing
    /// survives; `reason` names the check that failed.
    SourceRefused {
        /// The service state the checks read: what the host is missing
        /// while the source cannot be copied.
        service: Box<AnswererStep>,
        /// The named check that failed on the copy source.
        reason: String,
    },
    /// The step cannot be offered at all, for a named reason no check could
    /// change: this release ships no `minzoned`, or this build carries
    /// no signing identity to verify one by. The step is said to be
    /// unavailable — never silently dropped — and the command carries none.
    SourceUnavailable {
        /// The service state the checks read: what the host is missing.
        service: Box<AnswererStep>,
        /// Why the step is unavailable.
        reason: String,
    },
}

impl AnswererStep {
    /// Whether the step is done — the service is there, root-owned, and
    /// speaks this daemon's channel protocol. This is the fact the
    /// advisory's quiet arm needs beside the hook and the range: the
    /// advisory re-surfaces until the host service exists, and
    /// re-surfaces again the moment the installed copy falls behind.
    pub(crate) fn holds(&self) -> bool {
        matches!(self, AnswererStep::Installed)
    }
}

/// The facts the answerer service's checks decide on, as the detection
/// gathers them and [`answerer_step_over`] reads them — the answerer's
/// counterpart of [`RangeFacts`]. Pure data, so the checks over it are
/// unit-tested on every platform the suite runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub(crate) struct AnswererFacts {
    /// The owner and mode of every directory component of the program
    /// copy's path and every unit's, from `/` down, in walk order. A
    /// component with no entry here did not read; the verdict treats it
    /// as unverified, never as passing.
    pub components: Vec<(String, FileCustody)>,
    /// The program copy's owner and mode, when it exists.
    pub program: Option<FileCustody>,
    /// The unit files' owner and mode, in [`ANSWERER_UNIT_PATHS`] order,
    /// each when it exists.
    pub units: Vec<Option<FileCustody>>,
    /// The program path the unit that runs the program names — the
    /// plist's `ProgramArguments` on macOS, the service unit's
    /// `ExecStart` on Linux — when it names one.
    pub unit_program: Option<String>,
    /// The channel protocol version the installed copy answered the
    /// probe with, when it exists, runs, and answers a number.
    pub installed_version: Option<u32>,
}

/// The program path a systemd service unit's `ExecStart=` names: the
/// first word of the first such line, as systemd reads it. `None` when
/// no `ExecStart=` line is there. Pure over the file's bytes, so the
/// parse is unit-tested on every platform the suite runs on.
pub(crate) fn service_exec_start(text: &str) -> Option<&str> {
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("ExecStart="))?;
    let start = line.trim_start().strip_prefix("ExecStart=")?;
    start.split_whitespace().next()
}

/// The program path the unit that runs the answerer names: the plist's
/// `ProgramArguments` on macOS, the service unit's `ExecStart` on Linux —
/// the one fact that says the installed service runs the root-owned
/// copy, not some other program.
#[cfg(target_os = "macos")]
fn unit_program_argument(text: &str) -> Option<&str> {
    plist_program_argument(text)
}

#[cfg(not(target_os = "macos"))]
fn unit_program_argument(text: &str) -> Option<&str> {
    service_exec_start(text)
}

/// The answerer step the facts decide (`daemon` is the channel protocol
/// version this daemon speaks — [`minvmd::net::answerer::CHANNEL_PROTOCOL_VERSION`],
/// the version of the daemon this CLI links and spawns): absent when
/// neither the program copy nor any unit file is installed; installed
/// when every check holds — every directory component of every path
/// root-owned with no group or other write, the copy and every unit
/// file root-owned the same, the unit naming the copy — *and* the copy
/// answers the probe with this daemon's version; custody failed, naming
/// the first check that did not hold; protocol mismatch when the copy
/// answers anything else, or nothing at all.
///
/// Pure over the facts, so every check is unit-tested on every platform
/// the suite runs on; the detection is the reader that gathers them
/// ([`read_answerer_step`]).
pub(crate) fn answerer_step_over(facts: &AnswererFacts, daemon: u32) -> AnswererStep {
    // Nothing at any path: the service is not installed, and no custody
    // question arises.
    if facts.program.is_none() && facts.units.iter().all(Option::is_none) {
        return AnswererStep::Absent;
    }
    let mut walked = Vec::new();
    for path in std::iter::once(ANSWERER_PROGRAM_PATH).chain(ANSWERER_UNIT_PATHS.iter().copied()) {
        for component in path_components(path) {
            if !walked.contains(&component) {
                walked.push(component);
            }
        }
    }
    let mut checks = Vec::new();
    for component in &walked {
        let Some(custody) = facts
            .components
            .iter()
            .find(|(path, _)| path == component)
            .map(|(_, custody)| custody)
        else {
            checks.push(format!("its directory {component} did not read"));
            continue;
        };
        if !custody.root_owned() {
            checks.push(not_root_owned("its directory", component, custody));
        }
    }
    match facts.program {
        None => checks.push(format!("its program {ANSWERER_PROGRAM_PATH} is missing")),
        Some(custody) if !custody.root_owned() => {
            checks.push(not_root_owned(
                "its program",
                ANSWERER_PROGRAM_PATH,
                &custody,
            ));
        }
        Some(_) => {}
    }
    for (what, path, custody) in ANSWERER_UNIT_PATHS
        .iter()
        .copied()
        .zip(&facts.units)
        .map(|(path, custody)| ("its unit", path, *custody))
    {
        match custody {
            None => checks.push(format!("{what} {path} is missing")),
            Some(custody) if !custody.root_owned() => {
                checks.push(not_root_owned(what, path, &custody));
            }
            Some(_) => {}
        }
    }
    match facts.unit_program.as_deref() {
        None => checks.push(format!(
            "its unit names no program, not the root-owned {ANSWERER_PROGRAM_PATH}"
        )),
        Some(ANSWERER_PROGRAM_PATH) => {}
        Some(other) => checks.push(format!(
            "its unit names {other}, not the root-owned {ANSWERER_PROGRAM_PATH}"
        )),
    }
    match checks.first() {
        None => match facts.installed_version {
            Some(installed) if installed == daemon => AnswererStep::Installed,
            installed => AnswererStep::ProtocolMismatch { installed, daemon },
        },
        Some(check) => AnswererStep::CustodyFailed {
            failed_check: check.clone(),
        },
    }
}

/// The inputs the answerer install renders from that only the running
/// machine knows, gathered once per render: the operator the unit runs
/// the service as, the machine-global channel the unit holds, the
/// `minzoned` program on this machine the step copies, and the control
/// sockets of the VM host daemons the step asks to release the hook port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswererInstall {
    /// The user the unit runs the service as.
    pub operator: String,
    /// The channel socket's path, absolute.
    pub channel: String,
    /// The channel socket's directory.
    pub channel_dir: String,
    /// The `minzoned` program the step copies — beside this `min`, or
    /// on `PATH`; never a bare name the shell might resolve to anything.
    pub source: String,
    /// The SHA-256 of the source bytes verified at render time: the
    /// privileged step refuses a root-owned copy that hashes otherwise.
    pub sha256: String,
    /// The designated requirement the privileged step re-verifies its copy
    /// with on macOS ([`VerifiedSource::requirement`]); `None` renders no
    /// signature re-check.
    pub requirement: Option<String>,
    /// The control sockets of the daemons the step asks to release the hook
    /// port: this CLI's own state dir's — its VM host daemons, the default
    /// VM and its named VMs, or its native daemon. Empty when none is known
    /// — the step then starts the unit directly.
    pub controls: Vec<String>,
}

/// The program the answerer step copies: `minzoned`, the dedicated
/// answerer binary — never `minvmd`, and never a bare name.
pub(crate) const ANSWERER_PROGRAM_NAME: &str = "minzoned";

/// The operator the answerer unit runs the service as: the user this CLI
/// runs as, read the way launchd and every login shell record it
/// (`USER`, then `LOGNAME`), falling back to the password database for
/// the uid the process carries — never root by choice, and empty only
/// when no name reads at all, a unit the manager refuses to load rather
/// than a service run as the wrong user.
fn operator_name() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
        .or_else(|| {
            nix::unistd::User::from_uid(nix::unistd::getuid())
                .ok()
                .flatten()
                .map(|user| user.name.to_string())
        })
        .unwrap_or_default()
}

/// Where the answerer program is on this machine, pure over where to look:
/// beside the running `min` first (a release ships the two together; a dev
/// build puts them in one target dir), then each directory of `path`. Only
/// `minzoned` is ever named — never `minvmd`, whatever sits beside it —
/// and `None` when no such file exists, so the advisory names no program
/// it cannot find.
pub(crate) fn answerer_source_in(
    exe_dir: Option<&std::path::Path>,
    path: Option<&std::ffi::OsStr>,
) -> Option<String> {
    let beside = exe_dir.map(|dir| dir.join(ANSWERER_PROGRAM_NAME));
    let on_path = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .map(|dir| dir.join(ANSWERER_PROGRAM_NAME));
    beside
        .into_iter()
        .chain(on_path)
        .find(|candidate| candidate.is_file())
        .map(|found| found.display().to_string())
}

/// The answerer program this machine's step copies ([`answerer_source_in`]
/// over this `min`'s directory and `PATH`); the not-found arm is asserted
/// on the pure half.
fn answerer_source() -> Option<String> {
    let exe = std::env::current_exe().ok();
    answerer_source_in(
        exe.as_deref().and_then(std::path::Path::parent),
        std::env::var_os("PATH").as_deref(),
    )
}

/// The stand-in program path the suite's fixed installs carry.
#[cfg(test)]
pub(crate) const TEST_ANSWERER_SOURCE: &str = "/opt/minimal-test/bin/minzoned";

/// The control sockets the answerer step asks to release the hook port,
/// set by the session start that renders the advisory (its own state dir's
/// daemons: the VM host daemons, default VM and named VMs alike, or the
/// native daemon).
static HANDOVER_CONTROLS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Records the control sockets the next render's answerer step releases.
pub(crate) fn set_handover_controls(controls: Vec<String>) {
    *HANDOVER_CONTROLS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = controls;
}

/// [`AnswererInstall`] for this machine and the copy source the advisory
/// verified — `None` when a value it would carry cannot be quoted.
/// The channel path is the daemon's own resolution —
/// [`minvmd::net::answerer::resolve_channel_sock`], the machine-global path
/// every node connects to — so the socket the unit holds and the socket
/// the daemons connect to are one path by one definition.
pub(crate) fn answerer_install(verified: &VerifiedSource) -> Option<AnswererInstall> {
    let channel = minvmd::net::answerer::resolve_channel_sock();
    let install = AnswererInstall {
        operator: operator_name(),
        channel_dir: channel.parent().unwrap_or(&channel).display().to_string(),
        channel: channel.display().to_string(),
        source: verified.path.clone(),
        sha256: verified.sha256.clone(),
        requirement: verified.requirement.clone(),
        controls: HANDOVER_CONTROLS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
    };
    if let Some(value) = unquotable_value(&install) {
        tracing::warn!(
            value,
            "the answerer service step is left out of the advisory: a path it would carry \
             holds a quote, `$`, a backtick, a backslash or a line break, which the privileged \
             command cannot quote safely; the daemon hosting the session keeps the interim \
             answerer"
        );
        return None;
    }
    Some(install)
}

/// The first value of `install` the privileged command could not carry
/// inside its nested quotes — the payload is single-quoted inside double
/// quotes on Linux and double-quoted inside single quotes on macOS, so any
/// quote, `$`, backtick, backslash or line break in an interpolated path
/// would end a quoting context in a root-run command. `None` when every
/// value is safe to render.
fn unquotable_value(install: &AnswererInstall) -> Option<&str> {
    let unsafe_char = |c: char| matches!(c, '\'' | '"' | '$' | '`' | '\\' | '\n' | '\r' | '\0');
    [
        &install.operator,
        &install.channel_dir,
        &install.channel,
        &install.source,
    ]
    .into_iter()
    .chain(install.controls.iter())
    .map(String::as_str)
    .find(|value| value.chars().any(unsafe_char))
}

/// The Developer ID team the release signs `minzoned` with, compiled in
/// from `MINIMAL_ZONED_TEAMID` by the release build of this CLI — the
/// `<TEAMID>` of [`answerer_requirement`]. A release build without it
/// carries no signing identity and offers no answerer step on macOS (see
/// [`macos_answerer_requirement`]); there is no fallback to a bare
/// `codesign --strict`, which any ad-hoc signature passes.
#[cfg(all(target_os = "macos", not(any(test, debug_assertions))))]
const ANSWERER_SIGNING_TEAMID: Option<&str> = option_env!("MINIMAL_ZONED_TEAMID");

/// The code-signing identifier the release signs `minzoned` under
/// (`codesign --identifier`), compiled in from `MINIMAL_ZONED_IDENTIFIER`
/// beside [`ANSWERER_SIGNING_TEAMID`] and required the same way.
#[cfg(all(target_os = "macos", not(any(test, debug_assertions))))]
const ANSWERER_SIGNING_IDENTIFIER: Option<&str> = option_env!("MINIMAL_ZONED_IDENTIFIER");

/// The reason the step is unavailable when this machine has no
/// `minzoned` to copy: the release this `min` came from shipped none
/// beside it, and none is on `PATH`.
const ANSWERER_NOT_SHIPPED: &str = "this release ships no minzoned";

/// The reason the step is unavailable on a macOS release build that was
/// compiled without [`ANSWERER_SIGNING_TEAMID`] or
/// [`ANSWERER_SIGNING_IDENTIFIER`]: there is no requirement to verify the
/// copy source against, so nothing is offered.
#[cfg(any(test, all(target_os = "macos", not(debug_assertions))))]
const ANSWERER_NO_SIGNING_IDENTITY: &str = "this build carries no signing identity";

/// The designated requirement `minzoned` must satisfy on macOS: signed
/// by Apple's Developer ID chain (the intermediate's Developer ID marker,
/// the leaf's Developer ID Application marker), by this team, under this
/// identifier. `None` when either value holds anything but ASCII letters,
/// digits, `.`, `-` or `_`: the requirement rides inside the privileged
/// command's quotes, so a value that could end them is never rendered.
#[cfg(any(test, all(target_os = "macos", not(debug_assertions))))]
fn answerer_requirement(teamid: &str, identifier: &str) -> Option<String> {
    let safe = |value: &str| {
        !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    (safe(teamid) && safe(identifier)).then(|| {
        format!(
            "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and \
             certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate \
             leaf[subject.OU] = \"{teamid}\" and identifier \"{identifier}\""
        )
    })
}

/// The requirement a macOS release build checks the copy source against,
/// from the signing identity compiled into it — or, when none is, the
/// named reason the step is unavailable. Pure over the two compiled-in
/// values, so the no-identity arm is asserted in the suite.
#[cfg(any(test, all(target_os = "macos", not(debug_assertions))))]
fn macos_answerer_requirement(
    teamid: Option<&str>,
    identifier: Option<&str>,
) -> Result<String, SourceProblem> {
    teamid
        .zip(identifier)
        .and_then(|(teamid, identifier)| answerer_requirement(teamid, identifier))
        .ok_or_else(|| SourceProblem::Unavailable(ANSWERER_NO_SIGNING_IDENTITY.to_string()))
}

/// The copy source the advisory verified, as the step renders it: the path,
/// the SHA-256 of the bytes the verification read — the pin the privileged
/// step re-hashes its root-owned copy against — and, on a macOS release
/// build, the designated requirement the privileged step re-verifies the
/// copy with ([`answerer_requirement`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct VerifiedSource {
    /// The `minzoned` the step copies.
    pub path: String,
    /// Lowercase hex SHA-256 of the bytes verified at render time.
    pub sha256: String,
    /// The designated requirement the root step re-checks the copy with;
    /// `None` on Linux, where the hash pin is the identity, and in debug
    /// and test builds.
    pub requirement: Option<String>,
}

/// Why the copy source cannot be offered: refused, with the named check it
/// failed, or unavailable, with the named reason no check could run. The
/// identity check's `Ok` is the requirement the root step re-checks the
/// copy with, where there is one ([`VerifiedSource::requirement`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceProblem {
    /// The source failed the identity check; the reason names it.
    Refused(String),
    /// No identity check can run, or there is no source to check; the
    /// reason names why.
    Unavailable(String),
}

/// The bound on the user-side `codesign` run: a verification that wedges
/// costs the read that ran it a few seconds, never the verb.
#[cfg(all(target_os = "macos", not(any(test, debug_assertions))))]
const ANSWERER_IDENTITY_BOUND: Duration = Duration::from_secs(5);

/// The identity check on the copy source, run unprivileged before the step
/// is offered. It is a pre-check only: the source sits beside `min` in a
/// prefix its user can write, so the check that counts is the privileged
/// step's own, on the root-owned copy (design §7.1, post-install custody).
///
/// On a macOS release build: `codesign --verify --strict -R` against the
/// Developer ID requirement this build carries ([`answerer_requirement`]),
/// or unavailable when it carries none. On Linux the identity is the
/// SHA-256 pin alone ([`answerer_step_with_source`]); link-cleanliness is
/// proven at release (`scripts/check-zoned-links.sh`), not here.
///
/// Skipped for debug and test builds under the same gate as the
/// channel-path override (`debug_path_override` in minvmd's answerer
/// module): a dev tree's binaries carry no Developer ID signature.
#[cfg(any(test, debug_assertions))]
async fn answerer_source_identity(_source: String) -> Result<Option<String>, SourceProblem> {
    Ok(None)
}

/// The macOS release half of [`answerer_source_identity`].
#[cfg(all(target_os = "macos", not(any(test, debug_assertions))))]
async fn answerer_source_identity(source: String) -> Result<Option<String>, SourceProblem> {
    let requirement =
        macos_answerer_requirement(ANSWERER_SIGNING_TEAMID, ANSWERER_SIGNING_IDENTIFIER)?;
    let run = tokio::process::Command::new("codesign")
        .args(["--verify", "--strict", "-R"])
        .arg(format!("={requirement}"))
        .arg(&source)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(ANSWERER_IDENTITY_BOUND, run).await {
        Ok(Ok(output)) if output.status.success() => Ok(Some(requirement)),
        Ok(Ok(output)) => Err(SourceProblem::Refused(format!(
            "failed its Developer ID check: codesign --verify --strict -R did not accept it ({})",
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("no reason given")
                .trim()
        ))),
        _ => Err(SourceProblem::Refused(
            "failed its Developer ID check: codesign did not run, or did not answer within 5 s"
                .to_string(),
        )),
    }
}

/// The Linux release half of [`answerer_source_identity`]: no signature to
/// check, so the source is verified by the SHA-256 pin alone.
#[cfg(all(not(target_os = "macos"), not(any(test, debug_assertions))))]
async fn answerer_source_identity(_source: String) -> Result<Option<String>, SourceProblem> {
    Ok(None)
}

/// The lowercase hex SHA-256 of `path`'s bytes.
async fn sha256_of(path: &str) -> std::io::Result<String> {
    use sha2::Digest as _;
    let bytes = tokio::fs::read(path).await?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

/// The answerer step with its copy source's verdict folded in — the half of
/// [`read_answerer_step`] that runs after the service state is read, with
/// the identity check injected so the suite drives it without a real
/// `codesign`. Only a step that would carry the copy is touched: a held or
/// not-offered step comes back as it went in. Otherwise the source is
/// unavailable (none shipped, or no identity to check it by), refused (it
/// failed the check), or verified — and only a verified source is pinned:
/// its bytes are hashed after the check passes, and the privileged step
/// refuses a copy whose hash differs.
pub(crate) async fn answerer_step_with_source<F, Fut>(
    step: AnswererStep,
    source: Option<String>,
    identity: F,
) -> AnswererStep
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<Option<String>, SourceProblem>>,
{
    if step.holds() {
        return step;
    }
    let pinned = match source {
        None => Err(SourceProblem::Unavailable(ANSWERER_NOT_SHIPPED.to_string())),
        Some(path) => match identity(path.clone()).await {
            Ok(requirement) => sha256_of(&path)
                .await
                .map(|sha256| VerifiedSource {
                    path,
                    sha256,
                    requirement,
                })
                .map_err(|error| {
                    SourceProblem::Refused(format!("could not be read to pin its SHA-256: {error}"))
                }),
            Err(problem) => Err(problem),
        },
    };
    let service = Box::new(step);
    match pinned {
        Ok(source) => AnswererStep::SourceVerified { service, source },
        Err(SourceProblem::Refused(reason)) => AnswererStep::SourceRefused { service, reason },
        Err(SourceProblem::Unavailable(reason)) => {
            AnswererStep::SourceUnavailable { service, reason }
        }
    }
}

/// The deadline on the installed copy's one protocol probe: the second
/// the detection's other bounded reads carry, so a copy that wedges —
/// or a program from before the probe, one that starts serving instead
/// of answering — costs one second of the verb that read it, never the
/// verb itself.
const ANSWERER_VERSION_PROBE_BOUND: Duration = Duration::from_secs(1);

/// The channel protocol version the installed copy speaks, asked of the
/// copy itself: `{ANSWERER_PROGRAM_PATH} --protocol-version`,
/// which prints the version and exits — never serving, never binding.
/// `None` when the copy is missing, does not answer within
/// [`ANSWERER_VERSION_PROBE_BOUND`], or does not name a number: a program from
/// before the probe reads the same as one that speaks no protocol, and
/// the advisory re-runs the step for both.
async fn installed_protocol_version() -> Option<u32> {
    let output = tokio::time::timeout(
        ANSWERER_VERSION_PROBE_BOUND,
        tokio::process::Command::new(ANSWERER_PROGRAM_PATH)
            .arg("--protocol-version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}

/// The answerer service's step on this host, read where the hook is
/// detected (NET-122's host service): the program copy's and the unit
/// files' presence, owner and mode; every directory component of their
/// paths, from `/` down; the program the unit names; and the channel
/// protocol version the installed copy speaks, asked of the copy itself.
/// Read-only, bounded, and nothing prompts: the same discipline as the
/// range step it sits beside, and the command that fixes what it finds
/// is the user's to run, never the session start's.
pub(crate) async fn read_answerer_step() -> AnswererStep {
    let mut paths = vec![ANSWERER_PROGRAM_PATH];
    paths.extend(ANSWERER_UNIT_PATHS.iter().copied());
    let mut units = Vec::new();
    for path in ANSWERER_UNIT_PATHS {
        units.push(file_custody(path).await);
    }
    let unit_text = tokio::fs::read_to_string(ANSWERER_UNIT_PATHS[ANSWERER_UNIT_PATHS.len() - 1])
        .await
        .ok();
    let facts = AnswererFacts {
        components: path_component_custody(&paths).await,
        program: file_custody(ANSWERER_PROGRAM_PATH).await,
        units,
        unit_program: unit_text
            .as_deref()
            .and_then(unit_program_argument)
            .map(str::to_string),
        installed_version: installed_protocol_version().await,
    };
    let step = answerer_step_over(&facts, minvmd::net::answerer::CHANNEL_PROTOCOL_VERSION);
    // The copy source's identity, only when the step would carry the copy
    // (NET-122's privileged step copies this program as root): checked
    // unprivileged before the step is ever offered, and pinned by hash for
    // the privileged step to re-check ([`answerer_step_with_source`]).
    answerer_step_with_source(step, answerer_source(), answerer_source_identity).await
}

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

/// Reads the host's current hook state (NET-122's detection proper), the
/// reason no zone command would reach this host's lookups, when there is
/// one, and the range step this host's OS carries — its unit's state and
/// custody where it installs one, the no-step state where it does not
/// (NET-123's privileged step, checked where the hook is detected). The
/// three facts are one read of one host: the advisory, the verdict, the
/// session-start log line and the bundle all draw from it and cannot
/// disagree about the host. Detection is read-only and never prompts: on
/// Linux, two `resolvectl` queries under one [`RESOLVECTL_BOUND`] deadline
/// — run together, so the deadline is paid once, and a wedged
/// systemd-resolved reads as absent rather than hanging the activate —
/// and three file reads; on macOS, one file read and the range unit's
/// custody facts.
pub(crate) async fn session_detection() -> (Hook, Option<String>, RangeStep) {
    host_detection(RESOLVECTL_BOUND).await
}

/// The deadline on the macOS range-unit read's one `launchctl print`: the
/// list's second, on both verbs, since the call is the same and a wedged
/// launchd must cost neither a wait.
const LAUNCHCTL_BOUND: Duration = Duration::from_secs(1);

/// [`session_detection`] at [`LIST_RESOLVECTL_BOUND`], the deadline the
/// list's read carries: `min ls` is the most frequently-invoked verb, so
/// the same host state it reads must not make it a wait — the verdict a
/// wedged systemd-resolved leaves is decided inside this one second, and
/// it is the proxy's arm, the one that cannot strand the user, so the
/// worst a wedged resolver costs a list is a second, never the session
/// start's five.
async fn ls_detection() -> (Hook, Option<String>, RangeStep) {
    host_detection(LIST_RESOLVECTL_BOUND).await
}

#[cfg(target_os = "macos")]
async fn host_detection(_bound: Duration) -> (Hook, Option<String>, RangeStep) {
    // macOS's resolver consults the resolver file directly — there is no
    // stub for host lookups to bypass, so nothing can block the command;
    // the range unit's one `launchctl print` carries its own
    // [`LAUNCHCTL_BOUND`], so this read never waits on launchd.
    (
        host_hook().await,
        None,
        // The range unit's state and custody, read beside the hook: the
        // same read-only detection, no prompt, and the facts the advisory
        // and the bundle draw on. The range's own presence stays the bind
        // probe's fact (see [`live_name_surface_with_range_at`]).
        read_range_step().await,
    )
}

#[cfg(not(target_os = "macos"))]
async fn host_detection(bound: Duration) -> (Hook, Option<String>, RangeStep) {
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
        // No range step on this host: `lo` carries the whole `127/8`, so
        // the command's job ends at the resolver. Read through
        // [`read_range_step`] — the one place the platform's step is
        // decided — so the state the detection reports is the same fact
        // the advisory and the render parameterize on.
        read_range_step().await,
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

/// The exact command that points macOS's resolver at the answerer *and*
/// installs the range unit that reserves the local range at boot — the one
/// `sudo` NET-122's advisory names, carrying the range step NET-123's
/// interim ends with (design §7.1: one command, one privilege elevation,
/// for one host's configuration).
///
/// The steps, in the order they run: `set -e;` first, and every step its own
/// statement — separated by `;`, or by the newline a heredoc ends — never by
/// `&&`: POSIX ignores `-e` for every command of an `&&` list except its
/// last, so a `mkdir` or `printf` that failed inside one would short-circuit
/// its list silently and the script would run on — the plist landing beside
/// a resolver file that did not, `launchctl bootstrap` loading the stale
/// program, and the command exiting 0 over a host it half-configured. As
/// statements, the first step that fails stops the script itself. Then make
/// the three directories the files live in (`mkdir -p` because a stock host
/// has no `/etc/resolver` until the first hook and no [`RANGE_PROGRAM_DIR`]
/// either, and a re-run must not die on `File exists`), write the resolver
/// file, then write the unit's program and its plist **from the bytes this
/// command itself carries** — the heredoc bodies are the rendered
/// [`range_program`] and [`RANGE_UNIT_PLIST`], quoted delimiters
/// (`<<\\…`) so nothing inside expands — so no staged copy, no `$PATH`
/// lookup, no argument and no environment feeds either file.
/// `chown root:wheel` and the `0755`/`0644` modes then converge both files
/// to the exact state the custody checks ([`range_step_over`]) verify,
/// whatever a previous attempt or a tampered host left there. The boot step
/// loads last: `launchctl bootout` of the old unit first — guarded, because
/// a first run has nothing to boot out — then `bootstrap` loads the new unit
/// into the system domain, where launchd starts it at once, asynchronously,
/// so the range appears on the loopback within about a second of the
/// command returning, and [`RANGE_UNIT_PLIST`]'s `RunAtLoad` re-applies it
/// at every boot after. A re-run replaces the unit and re-runs the program
/// rather than dying on a label collision.
///
/// The whole payload rides inside the one pair of single quotes that
/// `sh -c` takes it under, so neither body the heredocs write may carry an
/// apostrophe of its own: one inside a body closes the quote, the paste
/// hangs at a continuation prompt, and `sh -n` rejects the rendered line —
/// which is why the suite parses both halves of the command and asserts
/// the bodies carry none (see `advisory_command_reserves_the_range_on_macos`).
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn macos_command(port: u16, install: Option<&AnswererInstall>) -> String {
    let program = range_program();
    let mut command = format!(
        "sudo sh -c 'set -e; mkdir -p /etc/resolver {RANGE_PROGRAM_DIR} {RANGE_PLIST_DIR} \
         ; printf \"nameserver 127.0.0.1\\nport {port}\\n\" > {RESOLVER_FILE} \
         ; cat > {RANGE_PROGRAM_PATH} <<\\{RANGE_PROGRAM_HEREDOC}\n\
{program}\
{RANGE_PROGRAM_HEREDOC}\n\
cat > {RANGE_PLIST_PATH} <<\\{RANGE_PLIST_HEREDOC}\n\
{RANGE_UNIT_PLIST}\
{RANGE_PLIST_HEREDOC}\n\
chown root:wheel {RANGE_PROGRAM_PATH} {RANGE_PLIST_PATH} \
         ; chmod 0755 {RANGE_PROGRAM_PATH} ; chmod 0644 {RANGE_PLIST_PATH} \
         ; (launchctl bootout system/{RANGE_UNIT_LABEL} 2>/dev/null || true) \
         ; launchctl bootstrap system {RANGE_PLIST_PATH}"
    );
    if let Some(install) = install {
        command.push_str(&macos_answerer_steps(install));
    }
    command.push('\'');
    command
}

/// How many quarter-second polls the step waits for the service's channel
/// to come up once it starts the unit: 20, five seconds.
const UNIT_UP_POLLS: &str = "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20";

/// The `--control` arguments the handover verbs carry, each path quoted
/// with `quote` (the platform payload's inner quote).
fn control_args(install: &AnswererInstall, quote: char) -> String {
    install
        .controls
        .iter()
        .map(|control| format!(" --control {quote}{control}{quote}"))
        .collect()
}

/// The privileged step's verified copy of the answerer program (design
/// §7.1, post-install custody): the user-side checks ran on a source in a
/// prefix its user can write, so these are the checks that count, run as
/// root on the root-owned copy before anything names it. In order:
///
/// 1. `dir` and every ancestor of it, up to `/`, must be a root-owned,
///    non-sticky directory with no group or other write. Otherwise someone
///    else could swap the copy, or rename a directory on its path away,
///    between the check and the rename. The step names the first offender
///    and refuses before it copies anything.
/// 2. `install` copies the source, root's and mode 0755, to an exclusive
///    `mktemp` name inside `dir`.
/// 3. The temp copy is hashed (`shasum -a 256` on macOS, `sha256sum` on
///    Linux) and compared with the SHA-256 the advisory pinned when it
///    verified the source; a mismatch removes the temp copy and exits
///    non-zero naming both hashes.
/// 4. On macOS, when the install carries a requirement, `codesign --verify
///    --strict -R` re-verifies the temp copy against it.
/// 5. The copy is renamed into `dest` atomically; the caller writes and
///    loads the unit or plist only after this, naming only `dest`.
///
/// Nothing here touches the running service or the units, so a refusal
/// leaves the host as it was. Every interpolated path rides in the
/// payload's inner quote, and [`unquotable_value`] has already refused any
/// that could end it. The Linux payload is double-quoted whole, so its `$`
/// is escaped for the outer shell (`\$`) and reaches the inner one as `$`.
fn verified_copy_steps(install: &AnswererInstall, dir: &str, dest: &str, macos: bool) -> String {
    // `dq` is a double quote the inner shell sees: bare in the macOS
    // payload's single quotes, escaped in the Linux payload's double ones.
    let (q, d, dq, group, hash) = if macos {
        ('"', "$", "\"", "wheel", "shasum -a 256")
    } else {
        ('\'', "\\$", "\\\"", "root", "sha256sum")
    };
    let source = &install.source;
    let sha = &install.sha256;
    let refuse = |reason: &str| {
        format!(
            "{{ rm -f {d}t ; echo {q}minimal: {reason}; the answerer service was not \
             installed{q} >&2 ; exit 1 ; }}"
        )
    };
    let codesign = match (&install.requirement, macos) {
        (Some(requirement), true) => format!(
            " ; codesign --verify --strict -R \"={}\" {d}t || {}",
            requirement.replace('"', "\\\""),
            refuse("the copied answerer failed its Developer ID check (codesign -R)")
        ),
        _ => String::new(),
    };
    format!(
        " ; [ -d {q}{dir}{q} ] || install -d -m 0755 -o root -g {group} {q}{dir}{q} \
         || {{ echo {q}minimal: {dir} could not be created root-owned; the answerer service \
         was not installed{q} >&2 ; exit 1 ; }} \
         ; p={q}{dir}{q} ; while : ; do find {dq}{d}p{dq} -maxdepth 0 -type d -user root \
         -not -perm -g+w -not -perm -o+w -not -perm -1000 | grep -q . || {{ echo {q}minimal:{q} \
         {dq}{d}p{dq}{q}, on the path to {dir}, is not a root-owned, non-sticky directory closed \
         to group and other writes; the answerer service was not installed{q} >&2 ; exit 1 ; }} \
         ; if [ {dq}{d}p{dq} = / ] ; then break ; fi ; p={d}(dirname {dq}{d}p{dq}) ; done \
         ; t={d}(mktemp {q}{dir}/.{ANSWERER_PROGRAM_NAME}.XXXXXX{q}) \
         ; install -m 0755 -o root -g {group} {q}{source}{q} {d}t || {copy_failed} \
         ; h={d}({hash} < {d}t || true) ; h={d}{{h%% *}} \
         ; case {d}h in {sha}) ;; *) rm -f {d}t ; echo {q}minimal: the answerer copy hashes{q} \
         {d}h{q}, not the {sha} the advisory verified: the source changed after it was checked; \
         the answerer service was not installed{q} >&2 ; exit 1 ;; esac{codesign} \
         ; mv -f {d}t {q}{dest}{q}",
        copy_failed = refuse("the answerer program could not be copied"),
    )
}

/// The macOS answerer steps of the privileged command (NET-122's host
/// service), after the range's: boot out a running service, copy
/// `minzoned` to the root-owned path and write the plist naming it,
/// root's both; ask this CLI's VM host daemons to release the hook port
/// (the copy's `release` verb, which waits up to 2 s for the port to be
/// free); then load the plist and wait up to 5 s for the channel. Either
/// wait running out boots the half-installed service out, removes its
/// files, asks the daemons to re-bind their interims (`release-cancel`)
/// and exits non-zero naming the reason, so the host is never left with
/// nobody answering. With no daemon known, the unit is loaded directly.
///
/// The copy comes first, verified as root before anything else runs
/// ([`verified_copy_steps`]): a copy that fails its hash pin or its
/// Developer ID re-check never reaches the root-owned path, and the running
/// service is left as it was.
#[cfg(any(test, target_os = "macos"))]
fn macos_answerer_steps(install: &AnswererInstall) -> String {
    let controls = control_args(install, '"');
    let copy = MACOS_ANSWERER_PROGRAM_PATH;
    let channel = &install.channel;
    let fail = |reason: &str| {
        let cancel = if controls.is_empty() {
            String::new()
        } else {
            format!("\"{copy}\" release-cancel{controls} ; ")
        };
        format!(
            "{{ (launchctl bootout system/{ANSWERER_LAUNCHD_LABEL} 2>/dev/null || true) ; \
             rm -f {ANSWERER_PLIST_PATH} \"{copy}\" \"{channel}\" ; {cancel}echo \"minimal: \
             {reason}; the answerer service was not installed\" >&2 ; exit 1 ; }}"
        )
    };
    let release = if controls.is_empty() {
        String::new()
    } else {
        format!(
            " ; \"{copy}\" release{controls} || {}",
            fail("the hook port did not come free for the answerer service (a collision)")
        )
    };
    format!(
        "{verified_copy} \
         ; (launchctl bootout system/{ANSWERER_LAUNCHD_LABEL} 2>/dev/null || true) \
         ; mkdir -p \"{channel_dir}\" \
         ; cat > {ANSWERER_PLIST_PATH} <<\\{ANSWERER_PLIST_HEREDOC}\n\
{answerer_plist}\
{ANSWERER_PLIST_HEREDOC}\n\
chown root:wheel {ANSWERER_PLIST_PATH} ; chmod 0644 {ANSWERER_PLIST_PATH}\
{release} \
         ; rm -f \"{channel}\" \
         ; launchctl bootstrap system {ANSWERER_PLIST_PATH} || {load_failed} \
         ; for poll in {UNIT_UP_POLLS} ; do if [ -S \"{channel}\" ] ; then break ; fi ; sleep 0.25 ; done \
         ; [ -S \"{channel}\" ] || {not_up}",
        verified_copy = verified_copy_steps(install, RANGE_PROGRAM_DIR, copy, true),
        channel_dir = install.channel_dir,
        answerer_plist = answerer_unit_plist(install),
        load_failed = fail("launchd did not load the answerer service"),
        not_up = fail("the answerer service channel did not come up within 5 s"),
    )
}

/// The answerer's launchd unit, rendered from [`ANSWERER_PLIST_TEMPLATE`]
/// for this host: the root-owned program copy the step installs, the
/// operator the unit runs it as, and the channel path the daemon this CLI
/// spawns publishes to — the same three facts the step's checks read back
/// ([`answerer_step_over`]).
#[cfg(any(test, target_os = "macos"))]
fn answerer_unit_plist(install: &AnswererInstall) -> String {
    ANSWERER_PLIST_TEMPLATE
        .replace("__PROGRAM__", MACOS_ANSWERER_PROGRAM_PATH)
        .replace("__OPERATOR__", &install.operator)
        .replace("__CHANNEL__", &install.channel)
}

/// The answerer's systemd socket unit, rendered from
/// [`ANSWERER_SOCKET_TEMPLATE`] for this host: the channel path and its
/// directory ([`answerer_unit_plist`]'s three facts, Linux's pair — the
/// program is a constant path on this platform too).
#[cfg(any(test, not(target_os = "macos")))]
fn answerer_socket_unit(install: &AnswererInstall) -> String {
    // The channel's directory is the unit's `RuntimeDirectory` when it sits
    // directly under `/run` — the machine-global path always does; a test
    // build's overridden path elsewhere carries none.
    let runtime = std::path::Path::new(&install.channel_dir)
        .strip_prefix("/run")
        .ok()
        .filter(|name| name.components().count() == 1)
        .map(|name| format!("RuntimeDirectory={}\n", name.display()))
        .unwrap_or_default();
    ANSWERER_SOCKET_TEMPLATE
        .replace("__CHANNEL__", &install.channel)
        .replace("__RUNTIME_DIRECTORY__", &runtime)
}

/// The answerer's systemd service unit, rendered from
/// [`ANSWERER_SERVICE_TEMPLATE`] for this host: the root-owned program copy
/// and the operator.
#[cfg(any(test, not(target_os = "macos")))]
fn answerer_service_unit(install: &AnswererInstall) -> String {
    ANSWERER_SERVICE_TEMPLATE
        .replace("__PROGRAM__", LINUX_ANSWERER_PROGRAM_PATH)
        .replace("__OPERATOR__", &install.operator)
}

/// The exact command that points systemd-resolved at the answerer *and*
/// installs the box-zone answerer as the host service the machine's
/// service manager holds (NET-122's privileged step): one `sudo`, one
/// payload, one privilege elevation, for one host's configuration.
///
/// The dedicated link exists because `resolvectl dns` and `resolvectl
/// domain` *replace* a link's server and domain lists: on the host's
/// general-purpose link they would wipe its upstream resolvers and search
/// domains, and a link whose only server is the answerer — which holds
/// just the zone and forwards nothing — must not carry the host's other
/// queries either.
///
/// The steps, in the order they run: `set -e;` first, and every step its
/// own statement — separated by `;` or by the newline a heredoc ends,
/// never by `&&`: POSIX ignores `-e` for every command of an `&&` list
/// except its last, so a step that failed inside one would short-circuit
/// its list silently and the script would run on, configuring a resolver
/// over a service that did not install, and the command exiting 0 over a
/// host it half-configured. As statements, the first step that fails
/// stops the script itself. Then create the dedicated link if this host
/// does not have it yet (a re-run after `resolvectl revert`, which undoes
/// the DNS configuration but not the link, must not die on `File exists`
/// — the guard covers the link, and `ip addr replace` covers its
/// address), bring it up, give it [`ZONE_LINK_ADDR`] — the fact that
/// makes resolved treat the link as routable and ever consult its routing
/// domain — take it off the default route, then give it the answerer as
/// its server and the zone as its routing domain. `default-route false`
/// comes *before* the server because a link with servers and no routing
/// domain is a default-route link implicitly — the flag first means no
/// partially-run command ever routes non-zone queries here.
///
/// Then the answerer service, beside the resolver it serves: make the
/// channel's directory and the program's, copy this machine's answerer
/// program to [`LINUX_ANSWERER_PROGRAM_PATH`] — the copy is the install, the
/// program is the daemon's own binary and cannot ride in a command the
/// way [`RANGE_PROGRAM_TEMPLATE`] does; the rule the range steps carry
/// (nothing copied in from anywhere, user-writable or not) is the
/// *destination's* custody here: root-owned at a path no user can write,
/// which is what [`answerer_step_over`] checks back. Write the two unit
/// files from the bytes the command carries, make root the owner of all
/// three before the manager ever reads them, reload the manager, enable
/// the socket unit at every boot after, and restart it — the one step
/// that both starts the service the first time and re-creates its
/// sockets from the new unit files on a re-run, handing the running
/// service back the same two manager-held sockets. A re-run over a
/// running service is the upgrade path: the unit files are re-written,
/// the copy re-copied, and the restart re-holds.
///
/// The whole payload rides inside one pair of double quotes, so no step
/// and no body it writes may carry `$`, a backtick or a double quote —
/// the outer shell would expand or end the payload at the first of
/// either. `~{ZONE}` is single-quoted so the inner shell does not
/// expand the tilde; the copy's paths are single-quoted the same way.
#[cfg(any(test, not(target_os = "macos")))]
pub(crate) fn linux_command(port: u16, install: Option<&AnswererInstall>) -> String {
    let mut command = format!(
        "sudo sh -c \"set -e; [ -e /sys/class/net/{ZONE_LINK} ] \
         || ip link add {ZONE_LINK} type dummy \
         ; ip link set {ZONE_LINK} up \
         ; ip addr replace {ZONE_LINK_ADDR}/32 dev {ZONE_LINK} \
         ; resolvectl default-route {ZONE_LINK} false \
         ; resolvectl dns {ZONE_LINK} 127.0.0.1:{port} \
         ; resolvectl domain {ZONE_LINK} '~{ZONE}'"
    );
    if let Some(install) = install {
        command.push_str(&linux_answerer_steps(install));
    }
    command.push('"');
    command
}

/// The Linux answerer steps of the privileged command (NET-122's host
/// service), after the resolver's: stop a running service, copy
/// `minzoned` to the root-owned path, write the socket and service
/// units naming it, root's all three, and enable the socket for every boot
/// without starting it; ask this CLI's VM host daemons to release the hook
/// port (the copy's `release` verb, which waits up to 2 s for the port to
/// be free); then start the socket unit and wait up to 5 s for it to be
/// active with its channel bound. Either wait running out disables and
/// removes what the step installed, asks the daemons to re-bind their
/// interims (`release-cancel`) and exits non-zero naming the reason, so the
/// host is never left with nobody answering. With no daemon known, the
/// unit is started directly.
///
/// The copy comes first, verified as root before anything else runs
/// ([`verified_copy_steps`]): a copy that fails its hash pin never reaches
/// the root-owned path, and the running service is left as it was.
#[cfg(any(test, not(target_os = "macos")))]
fn linux_answerer_steps(install: &AnswererInstall) -> String {
    let controls = control_args(install, '\'');
    let copy = LINUX_ANSWERER_PROGRAM_PATH;
    let channel = &install.channel;
    let unit = format!("{ANSWERER_SYSTEMD_UNIT}.socket");
    let fail = |reason: &str| {
        let cancel = if controls.is_empty() {
            String::new()
        } else {
            format!("'{copy}' release-cancel{controls} ; ")
        };
        format!(
            "{{ systemctl disable --now {unit} {ANSWERER_SYSTEMD_UNIT}.service 2>/dev/null \
             || true ; rm -f {ANSWERER_UNIT_SOCKET_PATH} {ANSWERER_UNIT_SERVICE_PATH} \
             '{copy}' ; systemctl daemon-reload || true ; {cancel}echo 'minimal: {reason}; \
             the answerer service was not installed' >&2 ; exit 1 ; }}"
        )
    };
    let release = if controls.is_empty() {
        String::new()
    } else {
        format!(
            " ; '{copy}' release{controls} || {}",
            fail("the hook port did not come free for the answerer service (a collision)")
        )
    };
    format!(
        "{verified_copy} \
         ; (systemctl stop {unit} {ANSWERER_SYSTEMD_UNIT}.service 2>/dev/null || true) \
         ; cat > {ANSWERER_UNIT_SOCKET_PATH} <<\\{ANSWERER_SOCKET_HEREDOC}\n\
{answerer_socket}\
{ANSWERER_SOCKET_HEREDOC}\n\
cat > {ANSWERER_UNIT_SERVICE_PATH} <<\\{ANSWERER_SERVICE_HEREDOC}\n\
{answerer_service}\
{ANSWERER_SERVICE_HEREDOC}\n\
chown root:root {ANSWERER_UNIT_SOCKET_PATH} {ANSWERER_UNIT_SERVICE_PATH} \
         ; chmod 0644 {ANSWERER_UNIT_SOCKET_PATH} {ANSWERER_UNIT_SERVICE_PATH} \
         ; systemctl daemon-reload \
         ; systemctl enable {unit}\
{release} \
         ; rm -f '{channel}' \
         ; systemctl start --no-block {unit} \
         ; for poll in {UNIT_UP_POLLS} ; do if systemctl is-active --quiet {unit} ; then if [ -S \
         '{channel}' ] ; then break ; fi ; fi ; sleep 0.25 ; done \
         ; systemctl is-active --quiet {unit} || {not_active} \
         ; [ -S '{channel}' ] || {not_up}",
        verified_copy = verified_copy_steps(install, ANSWERER_PROGRAM_DIR, copy, false),
        answerer_socket = answerer_socket_unit(install),
        answerer_service = answerer_service_unit(install),
        not_active = fail("the answerer service socket unit did not become active within 5 s"),
        not_up = fail("the answerer service channel did not come up within 5 s"),
    )
}

/// The exact command that configures this host's resolver for [`ZONE`] at
/// `port` — the command NET-122's advisory names.
/// `install` is the answerer step's inputs when the step is offered and
/// this machine has a `minzoned` to copy; `None` renders the resolver
/// (and, on macOS, the range) alone.
#[cfg(target_os = "macos")]
pub(crate) fn command(port: u16, install: Option<&AnswererInstall>) -> String {
    macos_command(port, install)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn command(port: u16, install: Option<&AnswererInstall>) -> String {
    linux_command(port, install)
}

/// The command [`command`] renders for this host with the answerer step
/// carried, from the same reads a session start's advisory makes — so a
/// test can run the exact privileged command without starting a daemon.
/// An error when the step cannot be carried (no `minzoned` beside this
/// `min` or on `PATH`, or a path the command cannot quote): a test must
/// not pass on a command without the service in it. Debug builds only,
/// where the identity check offers every source (see
/// [`answerer_source_identity`]).
#[cfg(debug_assertions)]
pub(crate) async fn answerer_command_for_this_host() -> anyhow::Result<String> {
    let step = read_answerer_step().await;
    let install = match &step {
        AnswererStep::SourceVerified { source, .. } => answerer_install(source),
        _ => None,
    }
    .ok_or_else(|| anyhow::anyhow!("the answerer service step cannot be carried: {step:?}"))?;
    Ok(command(
        minvmd::net::answerer::DEFAULT_ANSWERER_PORT,
        Some(&install),
    ))
}

/// The answerer service's own state as an advisory fact, beside the
/// range's. Every state but the first two is a fact the user has no other
/// way to see; `carried` is whether the command below carries the service
/// step, and only then does the fact say the command installs or reinstalls
/// it — a command rendered without the step must never claim it.
fn answerer_fact(answerer: &AnswererStep, carried: bool) -> Option<String> {
    let remedy = |verb: &str| {
        if carried {
            format!("; the command below {verb}")
        } else {
            String::new()
        }
    };
    match answerer {
        AnswererStep::Installed => None,
        AnswererStep::Absent => Some(format!(
            "the box-zone answerer is not installed as a host service, so the zone answers \
             only while a session holds it{}",
            remedy(
                "installs the service the service manager holds, run by the operator from a \
                 root-owned copy"
            )
        )),
        AnswererStep::CustodyFailed { failed_check } => Some(format!(
            "the installed box-zone answerer service {ANSWERER_UNIT_LABEL} fails custody: \
             {failed_check}{}",
            remedy("reinstalls it")
        )),
        AnswererStep::ProtocolMismatch {
            installed: None,
            daemon,
        } => Some(format!(
            "the installed box-zone answerer service does not answer this daemon's channel \
             protocol {daemon}{}",
            remedy("reinstalls it from this machine's own answerer program")
        )),
        AnswererStep::ProtocolMismatch {
            installed: Some(installed),
            daemon,
        } => Some(format!(
            "the installed box-zone answerer service speaks channel protocol {installed}, not \
             this daemon's {daemon}{}",
            remedy("reinstalls it from this machine's own answerer program")
        )),
        // The refusal itself is said beside this one (see [`advisory_at`]):
        // what the host is missing is still a fact, and the service state
        // underneath the refusal is the one the detection read.
        AnswererStep::SourceVerified { service, .. }
        | AnswererStep::SourceRefused { service, .. }
        | AnswererStep::SourceUnavailable { service, .. } => answerer_fact(service, carried),
    }
}

/// The advisory for one session start, as a function of the hook state, the
/// daemon's interim verdict, whether the reserved local range read present
/// on this host's own loopback, the range step and the answerer step this
/// host's detection read beside the hook, and whether anything blocks the
/// command (NET-122, NET-123). Pure.
///
/// `None` — nothing to say — when the hook already routes the zone to this
/// answerer, the daemon did not publish at the interim, the range read
/// present on this host's own loopback, the range step holds custody, the
/// answerer service is installed and speaks this daemon's channel
/// protocol, *and* nothing blocks the command. Otherwise the advisory says
/// what is missing and names the exact command. The interim re-surfaces
/// the advisory even when the hook routes (NET-123: "re-surface the
/// advisory of NET-122"): a session on the interim is a fact the user has
/// no other way to see. The interim fact names the step that ends it —
/// installing the range on the host — and whose job that step is is the
/// platform's: on macOS the same advisory command does it
/// ([`COMMAND_RESERVES_THE_RANGE`]'s platform — [`macos_command`]'s one
/// `sudo sh -c` installs the range unit beside the resolver file it
/// writes), so the fact says the command below installs the range and
/// ends the interim; on Linux the whole `127/8` is local to `lo`, no
/// install is needed, and the fact names the range as what is missing
/// and stops there.
///
/// `answerer` is the box-zone answerer service's step (see
/// [`AnswererStep`]) — NET-122's host service, installed by the same
/// privileged step the command carries. Its holding is part of the quiet
/// arm, so the advisory re-surfaces until the service exists and again
/// the moment the installed copy falls behind this daemon's channel
/// protocol: an upgrade that changes the wire re-runs the step and
/// re-copies the program. The Absent fact says what the service is for —
/// the zone answers only while a session's daemon holds it, and the
/// command below installs the one service that answers between sessions
/// and across them — and the CustodyFailed and ProtocolMismatch facts
/// name their check and their versions the way the range's do. Either way
/// the command the advisory names is the whole of the host's missing
/// configuration: the lead-in says what it does — on macOS "configure
/// the host's resolver, reserve the local range, and install the
/// Minimal box-name service (DNS and addresses for boxes)", on Linux
/// "configure the host's resolver and install the Minimal box-name service
/// (DNS and addresses for boxes)" — and nothing the note
/// asks for stands beside that command unprovided. String assembly only.
///
/// `range_step` is what the detection read beside the hook: the range
/// unit's state and custody where the host's OS installs one, the no-step
/// state where none is needed (see [`read_range_step`]). Its custody is
/// part of the quiet arm — NET-123 stops the advisory re-surfacing for the
/// range "once the probe reads present and custody holds", and custody
/// holding is [`RangeStep::custody_holds`]: a probe that reads present over
/// a unit whose files are not root's, or whose plist points at another
/// program, is a range the next boot does not re-apply, so the advisory
/// says the check that failed and names the command that reinstalls both
/// files. A unit whose files read absent on a probe that reads present —
/// the aliases without the boot step behind them — is said too, for the
/// same reason: the range would not survive the next boot.
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
    range_step: &RangeStep,
    answerer: &AnswererStep,
    blocker: Option<&str>,
) -> Option<String> {
    // A hook routing this answerer's port is configured, but only on a
    // host whose lookups reach the resolver it points at. A blocker says
    // they do not, so it outranks the quiet arm: staying silent there
    // would tell the user their resolver is set up while no host process's
    // lookup consults it, and `*.{ZONE}` would not resolve — NET-122's
    // WHILE clause is about the resolver that works, not the one whose
    // configuration is on paper. The range beside them is the host's own
    // read, the verdict's read — and custody is the second half of the
    // range's own quiet condition (NET-123), so a unit whose files are not
    // root's does not let the note fall quiet on a probe that reads
    // present: that is a range the next boot does not re-apply, not a
    // host whose missing configuration has nothing left to name. The
    // answerer service is the same half of its own condition (NET-122's
    // host service): a host without it is one whose zone answers only
    // while a session holds it, which is a fact the note says, not one
    // it hides.
    if hook.routes(port)
        && !interim
        && !matches!(range_present, Some(false))
        && blocker.is_none()
        && range_step.custody_holds()
        && answerer.holds()
    {
        return None;
    }
    let mut facts = Vec::new();
    if interim {
        // The interim ends when the range is installed on the host, and
        // whose job that install is is the platform's: on macOS the same
        // advisory command installs the range unit (design §7.1 folds the
        // privileged step into the one `sudo sh -c` the note names), so the
        // fact says the command below ends the interim; on Linux the whole
        // `127/8` is local to `lo` and the fact names the range as what is
        // missing and stops there — there is no step the command could
        // claim to run.
        let installs_the_range = if range_step.state == RangeStepState::NotNeeded {
            ""
        } else {
            "; the command below installs the range and ends the interim"
        };
        facts.push(format!(
            "this session publishes at the shared 127.0.0.1 interim: the \
             reserved local range {} is not installed on this host's loopback{installs_the_range}",
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
    if !range_step.custody_holds() {
        // The range step's own state, beside the probe's. A failed custody
        // check is said whenever it reads, over an interim or a missing
        // range or neither: it is the one fact that says *which* step of
        // the unit is not root's, and the command below is the one that
        // reinstalls both files. An absent unit is said only when no other
        // fact already names the range as missing — under the interim, or
        // on a probe that reads absent, the missing range is the fact and
        // the command already ends it.
        match range_step.state {
            RangeStepState::CustodyFailed => {
                let check = range_step
                    .failed_check
                    .as_deref()
                    .unwrap_or("its state did not read");
                facts.push(format!(
                    "the range unit {RANGE_UNIT_LABEL} fails custody: {check}"
                ));
            }
            RangeStepState::Absent if !interim && !matches!(range_present, Some(false)) => {
                facts.push(format!(
                    "the boot-time range unit {RANGE_UNIT_LABEL} is not \
                     installed, so the reserved local range {} would not be \
                     re-applied at the next boot",
                    range_text()
                ));
            }
            _ => {}
        }
    }
    // The step's inputs, when the advisory verified and pinned the copy
    // source: only then does the command carry the step. Every other state
    // of a step the host still needs is said, never silently dropped.
    let install = match answerer {
        AnswererStep::SourceVerified { source, .. } => answerer_install(source),
        _ => None,
    };
    if !answerer.holds() && install.is_none() {
        facts.push(match answerer {
            // The identity check refused the copy source: the reason names
            // the check that failed.
            AnswererStep::SourceRefused { reason, .. } => format!(
                "this machine's box-zone answerer program {ANSWERER_PROGRAM_NAME} failed the \
                 check the advisory runs before offering to copy it ({reason}), so the command \
                 below leaves the answerer service out"
            ),
            AnswererStep::SourceUnavailable { reason, .. } => format!(
                "{reason}; the answerer service step is unavailable, so the command below \
                 leaves it out"
            ),
            AnswererStep::SourceVerified { .. } => "a path the answerer service step would \
                 carry holds a quote, `$`, a backtick, a backslash or a line break, which the \
                 privileged command cannot quote safely, so the command below leaves the \
                 answerer service out"
                .to_string(),
            // A state no source verdict was folded into: nothing vouches for
            // the bytes the step would copy, so it is not carried.
            _ => format!(
                "this machine's box-zone answerer program {ANSWERER_PROGRAM_NAME} was not \
                 verified, so the command below leaves the answerer service out"
            ),
        });
    }
    if let Some(fact) = answerer_fact(answerer, install.is_some()) {
        facts.push(fact);
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
            let command = command(port, install.as_ref());
            // The lead-in says what the command does on this platform:
            // reserves the local range beside the resolver file where the
            // OS needs a step for it, the resolver alone where it does not
            // — and installs the box-zone answerer service where the
            // command carries that step.
            let lead_in = match (
                range_step.state == RangeStepState::NotNeeded,
                install.is_some(),
            ) {
                (true, true) => {
                    "Configure the host's resolver and install the Minimal box-name \
                     service (DNS and addresses for boxes) with:"
                }
                (true, false) => "Configure the host's resolver for the zone with:",
                (false, true) => {
                    "Configure the host's resolver, reserve the local range, and \
                     install the Minimal box-name service (DNS and addresses for boxes) with:"
                }
                (false, false) => "Configure the host's resolver and reserve the local range with:",
            };
            Some(format!("note: {facts}. {lead_in}\n  {command}"))
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
/// `answerer` is this host's answerer service step
/// ([`read_answerer_step`]), read beside the detection: the advisory
/// re-surfaces until the service is installed and speaks this daemon's
/// channel protocol (see [`advisory_at`]).
///
/// Printed once per session start, to stderr; never prompts.
pub(crate) fn session_advisory_at(
    detection: &(Hook, Option<String>, RangeStep),
    zone_answerer_port: Option<u16>,
    interim_loopback: bool,
    range_present: Option<bool>,
    answerer: &AnswererStep,
) -> Option<String> {
    let port = zone_answerer_port?;
    let (hook, blocker, range_step) = detection;
    advisory_at(
        hook,
        port,
        interim_loopback,
        range_present,
        range_step,
        answerer,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveSurface {
    /// Native DNS: the host resolver answers `*.{ZONE}` from the answerer.
    Native,
    /// The hostname proxy: names resolve only through it.
    Proxy,
    /// The hostname proxy, with the named cause for its *not serving* —
    /// the terminal publish outcome the VM host daemon reports (T93): the
    /// port another process on the host holds, or the redraws that ran
    /// out — or that its publish is unconfirmed (the VM is up, the publish
    /// is not one the host saw land). Carries its own port because the
    /// status that reported it named the port the failure is about, which
    /// is not the serving port a reply's discovery field would carry — and
    /// names the cause because "not serving" alone does not tell a user
    /// which thing to free.
    ProxyNotServing { port: u16, cause: ProxyDownCause },
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
    detection: &(Hook, Option<String>, RangeStep),
    zone_answerer_port: Option<u16>,
    answerer_bound: bool,
) -> Option<LiveSurfaceVerdict> {
    let port = zone_answerer_port?;
    if !answerer_bound {
        return None;
    }
    let (hook, blocker, _) = detection;
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
    detection: &(Hook, Option<String>, RangeStep),
    zone_answerer_port: Option<u16>,
    answerer_bound: bool,
) -> Option<LiveSurface> {
    live_name_surface_with_range_at(detection, zone_answerer_port, answerer_bound)
        .await
        .map(|verdict| verdict.surface)
}

/// [`live_name_surface_at`] with the detection this verb reads itself —
/// `min ls`'s form, one verdict per VM the list spans: the list has no
/// session-start advisory to share a read with, so the same bounded,
/// read-only detection runs here — at [`ls_detection`]'s
/// [`LIST_RESOLVECTL_BOUND`], the list's deadline, not the session
/// start's, because the list is the most frequently-invoked verb and its
/// read must stay a status read — and only when some VM's daemon reports
/// its answerer bound (the cheap half each reply carries). The answerer
/// is bound on every current daemon, so this read is not one only rare
/// hosts pay: `cmd_ls` runs it in the modes that print the verdict alone,
/// which is where the read belongs.
///
/// The list spans every VM on the host (NET-057), and the verdict is the
/// VM's, not the host's alone: each VM's daemon publishes its answerer on
/// a host port of its own (NET-059), so the host's resolver hook routes
/// the zone to one VM's answerer and a sibling VM's names answer through
/// its proxy. One detection read decides every VM's verdict — the pair of
/// queries it runs is paid once for the whole list, never once per VM,
/// and at most one VM's verdict reaches the bind probe behind the two
/// cheap facts — so a wedged systemd-resolved costs the list the same one
/// second however many VMs it lists. A VM whose daemon reports no bound
/// answerer contributes `None`, the arm that cannot misreport (see the
/// field's doc in `minimald-rpc`).
pub(crate) async fn live_name_surfaces(
    vms: impl Iterator<Item = (Option<u16>, bool)>,
) -> Vec<Option<LiveSurface>> {
    let vms: Vec<(Option<u16>, bool)> = vms.collect();
    let any_bound = vms.iter().any(|(port, bound)| port.is_some() && *bound);
    let detection = if any_bound {
        Some(ls_detection().await)
    } else {
        None
    };
    let mut surfaces = Vec::with_capacity(vms.len());
    for (port, bound) in vms {
        let surface = match &detection {
            Some(detection) => live_name_surface_at(detection, port, bound).await,
            None => None,
        };
        surfaces.push(surface);
    }
    surfaces
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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The terminal hostname-proxy publish outcome the VM host daemon
    /// reported (T93): the port the failure is about and its named cause —
    /// another process on the host holds the port, or the redraws ran out.
    /// `None` in every other state, where the status says nothing about
    /// the proxy. In this arm nothing else is read: the status is the VM
    /// host daemon's own verdict on the proxy's publication, and no host
    /// probe can move it.
    pub proxy_down: Option<(u16, ProxyDownCause)>,
}

/// [`HostAnswererRead`] from the status the VM host daemon's control
/// socket answered: `Holder` and `Registered` name their port and earn the
/// one bounded liveness query that proves it answers; `PortHeldNoChannel`
/// names its port with no query to run; `ProxyNotServing` carries the
/// terminal hostname-proxy failure's port and cause for the session start
/// to name, claiming no answerer facts; `Starting` claims nothing.
pub(crate) async fn host_answerer_read(status: ZoneAnswererStatus) -> HostAnswererRead {
    match status {
        ZoneAnswererStatus::Starting => HostAnswererRead {
            port: None,
            answerer_bound: false,
            held_no_channel: false,
            proxy_down: None,
        },
        ZoneAnswererStatus::PortHeldNoChannel { port } => HostAnswererRead {
            port: Some(port),
            answerer_bound: false,
            held_no_channel: true,
            proxy_down: None,
        },
        ZoneAnswererStatus::Holder { port }
        | ZoneAnswererStatus::Registered { port }
        | ZoneAnswererStatus::ManagerHeld { port } => HostAnswererRead {
            port: Some(port),
            answerer_bound: answerer_bound_at(port).await,
            held_no_channel: false,
            proxy_down: None,
        },
        ZoneAnswererStatus::ProxyNotServing { port, cause } => HostAnswererRead {
            port: None,
            answerer_bound: false,
            held_no_channel: false,
            proxy_down: Some((port, cause)),
        },
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
#[expect(
    clippy::indexing_slicing,
    reason = "recv_from's length is bounded by the buffer it filled, so the \
              slice is the reply and no more"
)]
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
///
/// When the installed answerer host service holds the port (NET-122's host
/// service), the line says the zone is manager-held and names the channel
/// this VM's table publishes over — the hook probe's manager-held answer,
/// as against the session-held interim the other two answered arms name.
#[must_use]
pub fn vm_host_answerer_line(status: ZoneAnswererStatus) -> Option<String> {
    vm_host_answerer_line_at(status, &minvmd::net::answerer::resolve_channel_sock())
}

/// [`vm_host_answerer_line`] over a given machine-global channel path, so
/// tests pin the wording without the host's path.
#[must_use]
pub(crate) fn vm_host_answerer_line_at(
    status: ZoneAnswererStatus,
    channel: &std::path::Path,
) -> Option<String> {
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
        ZoneAnswererStatus::ManagerHeld { port } => Some(format!(
            "manager-held: answered by the answerer host service · the \
             service manager holds it on 127.0.0.1:{port} (UDP); this VM's \
             table publishes to it over {} · point the host's resolver at it \
             for *.{ZONE}",
            channel.display()
        )),
        ZoneAnswererStatus::PortHeldNoChannel { port } => Some(format!(
            "not answered on the host · a process no zone-answerer channel \
             reaches holds 127.0.0.1:{port}, so this VM's minvmd answers \
             nothing and its names are not answered on the host"
        )),
        // The status that carries the hostname proxy's terminal publish
        // failure says nothing about the zone answerer, so the answerer
        // row claims nothing for it — the same silence the
        // pre-acquisition state keeps. The proxy's own named cause
        // prints in the NAME SURFACE row below, which is where the
        // directive puts it.
        ZoneAnswererStatus::ProxyNotServing { .. } => None,
    }
}

/// The live surface on a VM-backed host, from the status the VM host
/// daemon's control socket answered — `min ls`'s form. The no-channel state
/// settles the proxy by the status's own word, without paying the
/// detection or the liveness query: the port is no daemon's answerer, so
/// the two reads could only misreport native. The two decided states read
/// the list's own bounded detection and this CLI's liveness query at the
/// port the status named — the same facts the session start reads, at the
/// list's own deadline, as [`live_name_surfaces`] does for a native host.
/// The pre-acquisition state claims nothing: no port named, no verdict to
/// print, exactly as a native daemon's absent port is. The terminal
/// hostname-proxy failure settles the proxy with its named cause carried
/// whole — no detection or liveness query runs, because the VM host
/// daemon's verdict on the proxy's publication is the fact, and the row
/// below must name why the proxy is not serving, not re-derive that it
/// is not (T93).
pub(crate) async fn vm_host_name_surface(status: ZoneAnswererStatus) -> Option<LiveSurface> {
    match status {
        ZoneAnswererStatus::Starting => None,
        ZoneAnswererStatus::PortHeldNoChannel { .. } => Some(LiveSurface::Proxy),
        ZoneAnswererStatus::ProxyNotServing { port, cause } => {
            Some(LiveSurface::ProxyNotServing { port, cause })
        }
        ZoneAnswererStatus::Holder { port }
        | ZoneAnswererStatus::Registered { port }
        | ZoneAnswererStatus::ManagerHeld { port } => {
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
/// naming the surface [`live_name_surfaces`] decided is live. `proxy_port`
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
        // The named cause replaces the bare "not serving": the port the
        // failure is about and the thing to free — another process on the
        // host, or a redraw that ran out of tries — because a user who
        // cannot resolve a name needs which port to check, not the fact
        // that something failed (T93). The port comes from the verdict,
        // not `proxy_port`: a reply whose proxy never published carries
        // no serving port to name.
        LiveSurface::ProxyNotServing { port, cause } => match cause {
            ProxyDownCause::PortHeld => format!(
                "the hostname proxy is the live name surface; it is not serving — \
                 another process on the host holds 127.0.0.1:{port}"
            ),
            ProxyDownCause::RedrawsRanOut => format!(
                "the hostname proxy is the live name surface; it is not serving — \
                 its publication was redrawn and the redraws ran out; the last \
                 port was 127.0.0.1:{port}"
            ),
            // The VM is up, but the VM host daemon never saw the publish
            // land: no report from the guest, and no listener on the port
            // it could attribute to this VM. Said as unconfirmed, never as
            // serving, until the guest's report clears it.
            ProxyDownCause::PublishUnconfirmed => format!(
                "hostname proxy publish unconfirmed · the VM is up, but the VM \
                 host daemon has not seen the hostname proxy publish on \
                 127.0.0.1:{port}; names may not route through it until the \
                 guest reports the publish"
            ),
            // The guest's late report refused the port after the VM came
            // up: the VM keeps running with no hostname proxy, so this is
            // said as a running VM's state, never in the start failure's
            // words — the port, who holds it, and that the VM is up.
            ProxyDownCause::PortHeldAfterStart { holder } => {
                let holder = holder.as_deref().unwrap_or("another process on the host");
                format!(
                    "the hostname proxy is not serving · the VM is up without a hostname \
                     proxy: {holder} holds 127.0.0.1:{port}; free the port and restart \
                     the VM to publish it"
                )
            }
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
/// loopback aliases the bind probe found, the probe's result, whether the
/// host is on the 127.0.0.1 interim, and the range step the detection read
/// beside the hook — on macOS, whether the range unit is installed, the
/// owner and mode of its plist and its program, the program path the plist
/// runs, and the custody verdict over all of it (NET-122, NET-123).
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
    /// The range step this host carries: on macOS the range unit's state
    /// and custody — whether it is installed, the owner and mode of its
    /// plist and its program, the program path the plist runs, and the
    /// custody verdict — else the no-step state of a host whose OS needs
    /// none. Beside the bind probe's result, so a macOS host still on the
    /// interim, or holding a unit whose custody fails, reads why.
    pub range_step: RangeStep,
}

/// Reads everything [`NamingSurface`] holds, for `min bug` to record.
pub(crate) async fn naming_surface() -> NamingSurface {
    let (hook, _, range_step) = session_detection().await;
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
        range_step,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI's zone spellings are the sessions zone's, byte for byte: the
    /// hook's zone is the apex, and the macOS resolver file is named for it.
    #[test]
    fn zone_spellings_are_the_sessions_zone() {
        assert_eq!(ZONE, "min.internal");
        assert_eq!(ZONE, sessions::core::zone_answer::ZONE_APEX);
        assert_eq!(RESOLVER_FILE, format!("/etc/resolver/{ZONE}"));
    }

    /// The answerer step's inputs as a test renders them: the stand-in
    /// program, the operator, the machine-global channel, and two control
    /// sockets for the handover's verbs.
    fn test_install() -> AnswererInstall {
        let channel = minvmd::net::answerer::resolve_channel_sock();
        AnswererInstall {
            operator: "operator".to_string(),
            channel_dir: channel.parent().unwrap_or(&channel).display().to_string(),
            channel: channel.display().to_string(),
            source: TEST_ANSWERER_SOURCE.to_string(),
            sha256: TEST_ANSWERER_SHA256.to_string(),
            requirement: None,
            controls: vec![
                "/state/minimal/providers/local-minvmd0/control.sock".to_string(),
                "/state/minimal/providers/local-minvmd0/alpha/control.sock".to_string(),
            ],
        }
    }

    /// The pin [`test_install`] carries: the SHA-256 of the empty input.
    const TEST_ANSWERER_SHA256: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// `step` with a verified, pinned copy source folded in — what
    /// [`read_answerer_step`] returns for a host that still needs the step
    /// and has a `minzoned` that passed its identity check.
    fn verified(step: AnswererStep) -> AnswererStep {
        AnswererStep::SourceVerified {
            service: Box::new(step),
            source: VerifiedSource {
                path: TEST_ANSWERER_SOURCE.to_string(),
                sha256: TEST_ANSWERER_SHA256.to_string(),
                requirement: None,
            },
        }
    }

    /// [`answerer_install`] over the verified source [`verified`] folds in.
    fn verified_install() -> Option<AnswererInstall> {
        answerer_install(&VerifiedSource {
            path: TEST_ANSWERER_SOURCE.to_string(),
            sha256: TEST_ANSWERER_SHA256.to_string(),
            requirement: None,
        })
    }

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
    fn answerer_fact_claims_the_step_only_when_the_command_carries_it() {
        let states = [
            AnswererStep::Absent,
            AnswererStep::CustodyFailed {
                failed_check: "the plist is group-writable".to_string(),
            },
            AnswererStep::ProtocolMismatch {
                installed: None,
                daemon: 2,
            },
            AnswererStep::ProtocolMismatch {
                installed: Some(1),
                daemon: 2,
            },
        ];
        for state in &states {
            let carried = answerer_fact(state, true).expect("the state is a fact");
            assert!(
                carried.contains("the command below"),
                "a carried step names its remedy: {carried}"
            );
            let left_out = answerer_fact(state, false).expect("the state is still a fact");
            assert!(
                !left_out.contains("the command below"),
                "a command without the step never claims it: {left_out}"
            );
        }
        assert_eq!(answerer_fact(&AnswererStep::Installed, true), None);
    }

    #[test]
    fn answerer_install_refuses_unquotable_paths() {
        let base = AnswererInstall {
            operator: "operator".to_string(),
            channel_dir: "/run/minimal".to_string(),
            channel: "/run/minimal/answerer.sock".to_string(),
            source: "/home/operator/.local/bin/minzoned".to_string(),
            sha256: TEST_ANSWERER_SHA256.to_string(),
            requirement: None,
            controls: vec!["/home/operator/.minimal/vm/control.sock".to_string()],
        };
        assert_eq!(unquotable_value(&base), None, "plain paths render");
        let spaced = AnswererInstall {
            source: "/Users/an operator/Application Support/minzoned".to_string(),
            ..base.clone()
        };
        assert_eq!(
            unquotable_value(&spaced),
            None,
            "a space is quoted, not refused"
        );
        for bad in ["'", "\"", "$", "`", "\\", "\n", "\r"] {
            let source = AnswererInstall {
                source: format!("/home/o{bad}brien/minzoned"),
                ..base.clone()
            };
            assert!(
                unquotable_value(&source).is_some(),
                "source carrying {bad:?} is refused"
            );
            let control = AnswererInstall {
                controls: vec![format!("/home/o{bad}brien/control.sock")],
                ..base.clone()
            };
            assert!(
                unquotable_value(&control).is_some(),
                "control carrying {bad:?} is refused"
            );
        }
    }

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

    /// The hook probe's two answers about who holds the zone: manager-held
    /// when the answerer host service holds the port (the line names the
    /// channel this VM's table publishes over), session-held when a VM host
    /// daemon hosts the single-operator interim. Pinned because the session
    /// e2e greps the manager-held wording after the handover.
    #[test]
    fn vm_host_answerer_line_says_manager_held_or_session_held() {
        let channel = std::path::Path::new("/run/minimal/answerer.sock");
        let line =
            vm_host_answerer_line_at(ZoneAnswererStatus::ManagerHeld { port: 7_656 }, channel)
                .expect("the manager-held state prints its line");
        assert_eq!(
            line,
            "manager-held: answered by the answerer host service · the service \
             manager holds it on 127.0.0.1:7656 (UDP); this VM's table publishes \
             to it over /run/minimal/answerer.sock · point the host's resolver \
             at it for *.min.internal"
        );
        assert!(
            !line.contains("single-operator interim"),
            "a manager-held zone is not the session-held interim: {line}"
        );
        for status in [
            ZoneAnswererStatus::Holder { port: 7_656 },
            ZoneAnswererStatus::Registered { port: 7_656 },
        ] {
            let line = vm_host_answerer_line_at(status, channel)
                .expect("the session-held states print their lines");
            assert!(
                line.starts_with("answered by the VM host daemon (single-operator interim)"),
                "the interim is session-held: {line}"
            );
            assert!(
                !line.contains("manager-held"),
                "the session-held interim never claims the service: {line}"
            );
        }
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

    /// Whether `/bin/sh` parses `script`: the shell a user pastes the whole
    /// command into, and the shell `sudo sh -c` hands its payload to. Parse
    /// only — nothing runs, so no privilege is ever asked for — and a shell
    /// that could not be spawned reads as a command that does not parse,
    /// never as one that does.
    fn sh_parses(script: &str) -> bool {
        std::process::Command::new("/bin/sh")
            .args(["-n", "-c"])
            .arg(script)
            .stdin(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Root's custody facts, the state [`macos_command`] installs: every
    /// directory component of both the unit's paths root-owned with no
    /// group or other write, both files root-owned at their modes, and the
    /// plist and the loaded job both naming the root-owned program path.
    /// The pure verdict over these facts ([`range_step_over`]) is the
    /// installed state the advisory's quiet arm needs beside the probe's
    /// present.
    fn root_owned_facts() -> RangeFacts {
        let mut components = Vec::new();
        for path in [RANGE_PROGRAM_PATH, RANGE_PLIST_PATH] {
            for component in path_components(path) {
                components.push((
                    component,
                    FileCustody {
                        owner: 0,
                        mode: 0o755,
                    },
                ));
            }
        }
        RangeFacts {
            components,
            program: Some(FileCustody {
                owner: 0,
                mode: 0o755,
            }),
            plist: Some(FileCustody {
                owner: 0,
                mode: 0o644,
            }),
            plist_program: Some(RANGE_PROGRAM_PATH.to_string()),
            loaded_program: Some(RANGE_PROGRAM_PATH.to_string()),
        }
    }

    /// The installed range step: the verdict over root's facts, the state
    /// every custody check holds in.
    fn installed_range_step() -> RangeStep {
        range_step_over(&root_owned_facts())
    }

    /// The range step this platform's advisory renders over — the step its
    /// own detection reads on a healthy host: an installed unit on macOS,
    /// the no-step state on Linux. The render's *other* arm is passed
    /// explicitly by the tests that assert its text (NET-123's
    /// platform-parameterized tests below): the platform is a parameter of
    /// the render ([`advisory_at`] takes [`RangeStep`]), never a cfg the
    /// tests read.
    #[cfg(target_os = "macos")]
    fn range_step_on_this_os() -> RangeStep {
        installed_range_step()
    }

    #[cfg(not(target_os = "macos"))]
    fn range_step_on_this_os() -> RangeStep {
        RangeStep::not_needed()
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
        let advisory = advisory_at(
            &unconfigured,
            port,
            false,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            None,
        )
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
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &range_step_on_this_os(),
                &AnswererStep::Installed,
                None
            )
            .is_none(),
            "a configured host must not be re-advised"
        );

        // A hook routing a *stale* port is advised: the command points the
        // resolver at this daemon's answerer, not the old one's.
        let stale = Hook::configured("test", Some(port - 1), "routes the zone elsewhere");
        let advisory = advisory_at(
            &stale,
            port,
            false,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            None,
        )
        .expect("a stale hook must be re-advised for this answerer's port");
        for marker in command_markers(port) {
            assert!(
                advisory.contains(&marker),
                "the re-advice must name the exact command ({marker}): {advisory}"
            );
        }

        // NET-123's interim arm: a session published at the 127.0.0.1
        // interim re-surfaces the advisory even when the hook routes.
        let interim = advisory_at(
            &configured,
            port,
            true,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            None,
        )
        .expect("the interim must re-surface the advisory");
        assert!(
            interim.contains("127.0.0.1 interim"),
            "the interim advisory must name the interim: {interim}"
        );
        assert!(interim.contains(&range_text()));
        // The interim fact names what is missing — the range on the host's
        // loopback — and whose step ends it is this platform's: the fact's
        // platform arms (does the command below end the interim, or is
        // nothing left for it to install?) are pinned by
        // `interim_advisory_says_the_command_ends_it_on_macos`, on both
        // arms' steps.
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
        let advisory = session_advisory_at(
            &detection,
            Some(port),
            false,
            None,
            &AnswererStep::Installed,
        );
        let (hook, blocker, _) = &detection;
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
        assert!(
            session_advisory_at(&detection, None, false, None, &AnswererStep::Installed).is_none()
        );
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
        // for an answerer that serves. The list's form reads the host not
        // at all until some VM's daemon reports a bound answerer, and a
        // VM that reports none keeps the arm that cannot misreport even
        // when a sibling VM's report paid for the read.
        let detection = (routing_hook(), None, RangeStep::not_needed());
        assert!(live_name_surface_at(&detection, None, true).await.is_none());
        assert!(
            live_name_surface_at(&detection, Some(15353), false)
                .await
                .is_none()
        );
        // And the list's form: no VM reporting a bound answerer means no
        // verdict for any of them — the read that changes nothing, however
        // many VMs carry it.
        let list = live_name_surfaces([(None, true), (Some(15353), false)].into_iter()).await;
        assert_eq!(
            list,
            [None, None],
            "no VM reporting a bound answerer leaves every verdict the read that \
             changes nothing"
        );
    }

    #[tokio::test]
    async fn live_surface_is_the_proxy_when_either_cheap_fact_is_missing() {
        let port = 15353;
        // A hook that does not route: proxy, settled without a probe.
        let absent = (
            Hook::absent("test", "no hook"),
            None,
            RangeStep::not_needed(),
        );
        assert_eq!(
            live_name_surface_at(&absent, Some(port), true).await,
            Some(LiveSurface::Proxy),
            "a host whose resolver does not route the zone prints the proxy as live"
        );
        // A dead hook: a routing hook whose stub-bypass blocker
        // makes it configuration no host process consults — the proxy, and
        // both verbs must read it, never native on the hook's word alone.
        let blocked = (
            routing_hook(),
            Some("lookups bypass resolved".to_string()),
            RangeStep::not_needed(),
        );
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
            live_name_surface_at(
                &(routing_hook(), None, RangeStep::not_needed()),
                Some(port),
                true
            )
            .await,
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
        let detection = (routing_hook(), None, RangeStep::not_needed());
        let advisory = session_advisory_at(
            &detection,
            Some(port),
            false,
            Some(true),
            &AnswererStep::Installed,
        );
        assert!(
            advisory.is_none(),
            "a native verdict has no advisory: {advisory:?}"
        );
        let blocked = (
            routing_hook(),
            Some("lookups bypass resolved".to_string()),
            RangeStep::not_needed(),
        );
        assert!(
            session_advisory_at(
                &blocked,
                Some(port),
                false,
                Some(true),
                &AnswererStep::Installed
            )
            .is_some(),
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
        let absent = session_advisory_at(
            &detection,
            Some(port),
            false,
            Some(false),
            &AnswererStep::Installed,
        )
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

    /// T93: the NAME SURFACE row and the session-start message name *why*
    /// the hostname proxy is not serving — the port the failure is about
    /// and the cause the VM host daemon reported — instead of a bare "not
    /// serving". The two named causes are the two terminal publish
    /// outcomes: a port another process on the host holds, and a redraw
    /// that ran out of tries. The answerer row beside them claims nothing
    /// the status did not say, and the session start's read carries the
    /// cause whole, claiming no answerer facts of its own.
    #[tokio::test]
    async fn name_surface_names_why_the_proxy_is_not_serving() {
        let held = ZoneAnswererStatus::ProxyNotServing {
            port: 7_654,
            cause: ProxyDownCause::PortHeld,
        };
        let line = name_surface_line(
            vm_host_name_surface(held)
                .await
                .expect("the terminal proxy failure settles a surface"),
            None,
        );
        assert!(
            line.contains("it is not serving — another process on the host holds 127.0.0.1:7654"),
            "the held port is named with its cause: {line}"
        );

        let redrawn = ZoneAnswererStatus::ProxyNotServing {
            port: 19_911,
            cause: ProxyDownCause::RedrawsRanOut,
        };
        let line = name_surface_line(
            vm_host_name_surface(redrawn.clone())
                .await
                .expect("the terminal proxy failure settles a surface"),
            None,
        );
        assert!(
            line.contains("the redraws ran out; the last port was 127.0.0.1:19911"),
            "the exhausted redraw is named with its last port: {line}"
        );
        assert!(
            !line.contains("still serves"),
            "a proxy the VM host daemon reported down must not be said to serve: {line}"
        );

        // The session start's read of the same status: the named cause is
        // the machine fact, and no answerer fact is claimed beside it.
        let read = host_answerer_read(redrawn.clone()).await;
        assert_eq!(
            read.proxy_down,
            Some((19_911, ProxyDownCause::RedrawsRanOut)),
            "the cause rides the session start's read whole"
        );
        assert_eq!(read.port, None, "a proxy failure carries no answerer port");
        assert!(!read.answerer_bound, "and no liveness proof is claimed");
        assert!(!read.held_no_channel, "it is not the no-channel arm");
        assert_eq!(
            vm_host_answerer_line(redrawn),
            None,
            "the answerer row claims nothing the status did not say"
        );
    }

    /// T93: a VM whose publish the VM host daemon could not confirm — no
    /// report from the guest, and no listener on the port it could
    /// attribute to this VM — is shown as unconfirmed on the NAME SURFACE
    /// row, never as serving, even beside a serving port the reply carries.
    #[tokio::test]
    async fn name_surface_shows_an_unconfirmed_publish_as_unconfirmed() {
        let unconfirmed = ZoneAnswererStatus::ProxyNotServing {
            port: 19_917,
            cause: ProxyDownCause::PublishUnconfirmed,
        };
        let line = name_surface_line(
            vm_host_name_surface(unconfirmed)
                .await
                .expect("an unconfirmed publish settles a surface"),
            Some(19_917),
        );
        assert!(
            line.starts_with("hostname proxy publish unconfirmed"),
            "the row says the publish is unconfirmed: {line}"
        );
        assert!(
            line.contains("127.0.0.1:19917"),
            "the row names the port: {line}"
        );
        assert!(
            !line.contains("still serves") && !line.contains("routes through it on"),
            "an unconfirmed publish must not be said to serve: {line}"
        );
    }

    /// T93: a refusal the guest reports after an unconfirmed start leaves
    /// the VM up with no hostname proxy. The row and the session start say
    /// so — the port, its holder, and that the VM is up — never in the
    /// start failure's words.
    #[tokio::test]
    async fn name_surface_names_a_late_refusal_as_a_running_vm_without_a_proxy() {
        let late = ZoneAnswererStatus::ProxyNotServing {
            port: 19_918,
            cause: ProxyDownCause::PortHeldAfterStart {
                holder: Some("pid 4242 (python3)".to_string()),
            },
        };
        let line = name_surface_line(
            vm_host_name_surface(late)
                .await
                .expect("a late refusal settles a surface"),
            None,
        );
        assert_eq!(
            line,
            "the hostname proxy is not serving · the VM is up without a hostname proxy: \
             pid 4242 (python3) holds 127.0.0.1:19918; free the port and restart the VM \
             to publish it",
            "the row names the port, the holder, and that the VM is up"
        );
        assert!(
            !line.contains("the live name surface; it is not serving —"),
            "a late refusal must not recycle the start failure's words: {line}"
        );

        let unnamed = LiveSurface::ProxyNotServing {
            port: 19_918,
            cause: ProxyDownCause::PortHeldAfterStart { holder: None },
        };
        let line = name_surface_line(unnamed, None);
        assert!(
            line.contains("another process on the host holds 127.0.0.1:19918")
                && line.contains("the VM is up"),
            "an unnamed holder still names the port and the running VM: {line}"
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
        let command = macos_command(15353, None);
        assert!(command.contains(RESOLVER_FILE), "{command}");
        assert!(
            command.contains("nameserver 127.0.0.1\\nport 15353\\n"),
            "{command}"
        );
        assert!(command.starts_with("sudo"), "{command}");
    }

    // NET-123's privileged step, on the one `sudo sh -c` NET-122 already
    // renders (design §7.1): the command's own bytes do the whole install —
    // the program and the plist are written from what the command carries,
    // not staged, not copied, not read from anywhere user-writable — and
    // the boot step loads last, so a re-run replaces the unit rather than
    // dying on its label. Pinned here on the text the render builds from
    // the same templates the e2e runs; the operator-run
    // `local_range_reserved_by_privileged_step` (MINIMAL_E2E_PRIVILEGED=1,
    // a macOS host with passwordless sudo) proves this command against a
    // real launchd.
    #[test]
    fn advisory_command_reserves_the_range_on_macos() {
        let install = test_install();
        let command = macos_command(15353, Some(&install));
        // The three files, written in order: the resolver file first
        // (NET-122's step, unchanged), then the unit's program and plist.
        let resolver_at = command
            .find(RESOLVER_FILE)
            .expect("the resolver step is named");
        let program_at = command
            .find(&format!("cat > {RANGE_PROGRAM_PATH}"))
            .expect("the program step is named");
        let plist_at = command
            .find(&format!("cat > {RANGE_PLIST_PATH}"))
            .expect("the plist step is named");
        assert!(
            resolver_at < program_at,
            "the resolver file is written before the range step's files: {command}"
        );
        assert!(program_at < plist_at, "{command}");
        // The directories the three files live in are made first — a stock
        // host has no `/etc/resolver` and no `/Library/PrivilegedHelperTools`
        // either.
        let mkdir_at = command
            .find(&format!(
                "mkdir -p /etc/resolver {RANGE_PROGRAM_DIR} {RANGE_PLIST_DIR}"
            ))
            .expect("the directory step is named");
        assert!(mkdir_at < resolver_at, "{command}");
        // The bytes the command writes are the bytes the render builds: the
        // heredoc bodies are byte-identical to the rendered program and to
        // the plist template, under their quoted delimiters — no staged
        // copy, no `$PATH` lookup, no argument, no environment, no file
        // read feeds either one.
        let program = range_program();
        assert!(
            command.contains(&program),
            "the command carries the rendered program's own bytes: {command}"
        );
        assert!(
            command.contains(RANGE_UNIT_PLIST),
            "the command carries the plist's own bytes: {command}"
        );
        assert!(
            command.contains(&format!("<<\\{RANGE_PROGRAM_HEREDOC}"))
                && command.contains(&format!("<<\\{RANGE_PLIST_HEREDOC}")),
            "the heredoc delimiters are quoted, so the bodies write byte for byte: {command}"
        );
        // The command must parse — in the shell a user pastes it into and in
        // the shell sudo hands its payload to. The whole payload rides inside
        // the one pair of single quotes, so a single apostrophe in either
        // body closes them: the paste then hangs at a continuation prompt
        // and `sh -n` rejects the line, which is what the round found. So
        // neither body may carry one, and both halves are parsed to prove it.
        assert!(
            !program.contains('\''),
            "the program body carries no apostrophe — the command rides inside \
             single quotes, and one inside a body closes them: {program}"
        );
        assert!(
            !RANGE_UNIT_PLIST.contains('\''),
            "the plist body carries no apostrophe — the command rides inside \
             single quotes, and one inside a body closes them: {RANGE_UNIT_PLIST}"
        );
        assert!(
            sh_parses(&command),
            "the command must parse in the shell it is pasted into: {command}"
        );
        let payload = command
            .strip_prefix("sudo sh -c '")
            .and_then(|rest| rest.strip_suffix('\''))
            .expect("the command is the one sudo sh -c, its payload quoted whole");
        assert!(
            sh_parses(payload),
            "the payload the root shell runs must parse: {payload}"
        );
        // Fail closed inside the one command: the payload opens with
        // `set -e;`, and every step is its own statement — separated by `;`
        // or by the newline a heredoc ends — because POSIX ignores `-e` for
        // every command of an `&&` list except its last: a `mkdir` or
        // `printf` that failed inside one would short-circuit its list
        // silently and the script would run on, the plist landing beside a
        // resolver file that did not, `launchctl bootstrap` loading the
        // stale program, and the command exiting 0 over a host it
        // half-configured. As statements, the first failure stops the
        // script before any later step runs. The one compound statement is
        // the guarded boot-out, whose `|| true` is what makes it guarded —
        // and that is an OR-list, never an `&&`.
        assert!(
            payload.starts_with("set -e;"),
            "the inner script fails closed — its first step is set -e: {payload}"
        );
        let bootout = format!("(launchctl bootout system/{RANGE_UNIT_LABEL} 2>/dev/null || true)");
        assert!(
            !payload.replace(&bootout, "").contains("&&"),
            "no step hides inside an && list, where set -e reaches only the \
             last command — the payload separates its steps, so the first \
             failure stops the script: {payload}"
        );
        // The range's steps outside the two bodies substitute nothing — no
        // `$`, no backtick — and the bodies themselves are quoted-delimiter
        // (asserted above), so a backtick inside one (the program's comments
        // carry markdown) writes rather than runs.
        let steps_only = command.replace(&program, "").replace(RANGE_UNIT_PLIST, "");
        let (range_steps, answerer_steps) = steps_only
            .split_once(" ; [ -d \"")
            .expect("the answerer service's step follows the range's");
        assert!(
            !range_steps.contains('$') && !steps_only.contains('`'),
            "the range's steps substitute nothing — the bytes they write are the bytes \
             they carry: {range_steps}"
        );
        // The answerer's steps substitute only the verified copy's own
        // names: the path component it walks, its temp file and its hash.
        let copy_names = answerer_steps
            .replace("$(dirname ", "")
            .replace("$p", "")
            .replace("$(mktemp ", "")
            .replace("$(shasum ", "")
            .replace("${h%% *}", "")
            .replace("$t", "")
            .replace("$h", "");
        assert!(
            !copy_names.contains('$'),
            "the answerer's steps substitute nothing but the copy's own names: {answerer_steps}"
        );
        // The range's steps copy nothing in from anywhere, user-writable or
        // not. The answerer service's step after them (NET-122's host
        // service) copies exactly one program — the daemon's own binary,
        // which cannot ride in the command — and only to the root-owned
        // path its custody checks read back, through a pinned temp copy.
        assert!(
            !range_steps.contains("cp ") && !range_steps.contains("install "),
            "nothing is copied in for the range, user-writable or not: {range_steps}"
        );
        assert_eq!(
            answerer_steps.matches("install -m ").count(),
            1,
            "the answerer step copies its one program: {answerer_steps}"
        );
        assert!(
            answerer_steps.contains(&format!(
                "install -m 0755 -o root -g wheel \"{}\" $t",
                install.source
            )) && answerer_steps.contains(&format!("mv -f $t \"{MACOS_ANSWERER_PROGRAM_PATH}\"")),
            "the copy lands at the root-owned path: {answerer_steps}"
        );
        // Root owns both files, at the exact modes the custody checks
        // verify, before launchd ever reads them.
        assert!(
            command.contains(&format!(
                "chown root:wheel {RANGE_PROGRAM_PATH} {RANGE_PLIST_PATH}"
            )),
            "both files are converged to root's ownership: {command}"
        );
        assert!(
            command.contains(&format!("chmod 0755 {RANGE_PROGRAM_PATH}")),
            "the program is root's alone to run: {command}"
        );
        assert!(
            command.contains(&format!("chmod 0644 {RANGE_PLIST_PATH}")),
            "the plist is root's alone to write: {command}"
        );
        // The boot step loads last: the old unit is booted out first — so a
        // re-run replaces it and re-runs the program rather than dying on
        // the label collision — then the new one is bootstrapped, which
        // loads it into the system domain, where launchd starts it at once,
        // asynchronously, so the range appears within about a second, and
        // its RunAtLoad re-applies the range at every boot after.
        let bootout_at = command.find(&bootout).expect("the boot-out step is named");
        let bootstrap = format!("launchctl bootstrap system {RANGE_PLIST_PATH}");
        let bootstrap_at = command
            .find(&bootstrap)
            .expect("the bootstrap step is named");
        assert!(
            plist_at < bootout_at,
            "the files are installed before the unit loads: {command}"
        );
        assert!(
            bootout_at < bootstrap_at,
            "the old unit is booted out before the new one loads: {command}"
        );
        assert!(
            command.ends_with('\''),
            "the load is the last step: {command}"
        );
        // And the resolver step is still NET-122's: the same file, the same
        // port, in the same one command — the range step stands beside it,
        // not in front of it.
        assert!(
            command.contains("nameserver 127.0.0.1\\nport 15353\\n"),
            "{command}"
        );
    }

    /// The rendered program applies exactly the reserved range and nothing
    /// else (NET-123): the addresses it walks are exactly the usable host
    /// addresses of the /24 — the addresses the bind probe probes — each one
    /// applied by a single absolute-path `ifconfig` alias as a `/32` on lo0,
    /// and an address lo0 already carries is skipped rather than re-added,
    /// so a re-run adds only the missing aliases and removes nothing. The
    /// program reads no argument, no environment variable and no file — its
    /// one read is the interface's own state, reported by the same
    /// absolute-path tool — so nothing user-writable can change what the
    /// boot step applies.
    #[test]
    fn range_program_applies_exactly_the_reserved_range() {
        let program = range_program();
        let lines: Vec<&str> = program.lines().collect();
        assert_eq!(
            lines.first(),
            Some(&"#!/bin/sh"),
            "the unit's program is a /bin/sh script: {program}"
        );
        // The walk: exactly the range's host addresses, in probe order, and
        // no address outside the range.
        let walk = lines
            .iter()
            .find(|line| line.starts_with("for addr in ") && line.ends_with("; do"))
            .copied()
            .unwrap_or_else(|| panic!("the program walks the range's addresses: {program}"));
        let list = walk
            .strip_prefix("for addr in ")
            .and_then(|rest| rest.strip_suffix("; do"))
            .expect("the walk line is `for addr in <addresses>; do`");
        let walked: Vec<String> = list.split_whitespace().map(str::to_string).collect();
        let expected: Vec<String> = switch::loopback::range_hosts()
            .map(|addr| addr.to_string())
            .collect();
        assert_eq!(
            walked, expected,
            "the program walks exactly the addresses the bind probe probes — every \
             usable host address of the /24 and no address outside it: {program}"
        );
        // The one application form: an absolute-path `ifconfig` alias with
        // the /32 mask, guarded by the skip over what lo0 already carries.
        assert!(
            program.contains(
                "case \" $present \" in *\" $addr \"*) ;; *) /sbin/ifconfig lo0 alias \
                 \"$addr\" 255.255.255.255 ;; esac"
            ),
            "each address is applied as one /32 lo0 alias by absolute path, skipped \
             when lo0 already carries it: {program}"
        );
        assert_eq!(
            program.matches("/sbin/ifconfig").count(),
            2,
            "ifconfig appears exactly twice — the read of the interface's own state \
             and the alias — both by absolute path: {program}"
        );
        // No address outside the range is named anywhere the program acts:
        // every IPv4-shaped literal on its working lines is one of the
        // walked addresses or the /32 mask.
        let addresses: std::collections::BTreeSet<String> = expected.iter().cloned().collect();
        for line in lines.iter().filter(|line| !line.starts_with('#')) {
            for word in line.split(|c: char| !c.is_ascii_alphanumeric() && c != '.') {
                if word.parse::<Ipv4Addr>().is_ok() {
                    assert!(
                        addresses.contains(word) || word == "255.255.255.255",
                        "the program names no address outside the reserved range \
                         ({word}): {program}"
                    );
                }
            }
        }
        // The program substitutes nothing but its own reads: no positional
        // argument, no environment variable, no file read in — the only
        // identifiers behind its `$` signs are its own two and the one
        // command substitution.
        for rest in program.split('$').skip(1) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            assert!(
                rest.starts_with('(') || name == "present" || name == "addr",
                "the program substitutes nothing but its own reads (found {name:?}) — \
                 no argument, no environment variable, no file: {program}"
            );
        }
        assert!(
            !program.contains('<'),
            "the program reads no file — nothing redirects one in: {program}"
        );
        assert!(
            !program.contains("127.0.0.1"),
            "the program applies the range, not the interim address: {program}"
        );
        assert!(
            program.contains("set -e"),
            "an alias that fails fails the program, so the unit says so: {program}"
        );
    }

    /// The custody checks over the range unit — NET-123's privileged step,
    /// checked where the hook is detected: root owns both files with no
    /// group or other write, the plist's `ProgramArguments` names the
    /// root-owned program path, and the loaded job under the label runs
    /// that same path, so files copied in without the unit behind them — or
    /// a job loaded from elsewhere under the label — are not mistaken for
    /// the unit. The first check that does not hold is the one the advisory
    /// and the bundle name.
    #[test]
    fn range_step_custody_is_root_owned() {
        // Root's facts: the state the command installs — installed, custody
        // holding, which is the advisory's quiet arm beside the probe's
        // present.
        let step = range_step_over(&root_owned_facts());
        assert_eq!(step.state, RangeStepState::Installed);
        assert!(step.custody_holds(), "root's files hold custody: {step:?}");
        assert_eq!(step.failed_check, None);

        // Neither file: absent, and no custody question arises — the
        // interim's state, whose fact is the range's, not the unit's.
        assert_eq!(
            range_step_over(&RangeFacts::default()).state,
            RangeStepState::Absent
        );

        // The program a user owns, however it reads otherwise: custody
        // fails, naming the file and the ownership it read.
        let mut facts = root_owned_facts();
        facts.program = Some(FileCustody {
            owner: 501,
            mode: 0o755,
        });
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(check.contains(RANGE_PROGRAM_PATH), "{check}");
        assert!(
            check.contains("uid 501"),
            "the check names the owner it read: {check}"
        );

        // Group-writable is not root's alone, whoever owns it.
        let mut facts = root_owned_facts();
        facts.plist = Some(FileCustody {
            owner: 0,
            mode: 0o666,
        });
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains(RANGE_PLIST_PATH) && check.contains("666"),
            "the check names the file and the mode it read: {check}"
        );

        // One file without the other is not the unit: the plist without its
        // program fails custody on the missing file, not on the ones that
        // read.
        let mut facts = root_owned_facts();
        facts.program = None;
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains(&format!("{RANGE_PROGRAM_PATH} is missing")),
            "the check names the file that is not there: {check}"
        );

        // The plist's ProgramArguments must name the root-owned program:
        // a plist pointing anywhere else — the easy way to run another
        // program under a root label — fails custody on exactly that.
        let mut facts = root_owned_facts();
        facts.plist_program = Some("/Users/runner/pwned".to_string());
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains("/Users/runner/pwned") && check.contains(RANGE_PROGRAM_PATH),
            "the check names the program the plist runs and the one it must: {check}"
        );
        // A plist that names no program at all does not pass either.
        let mut facts = root_owned_facts();
        facts.plist_program = None;
        assert_eq!(
            range_step_over(&facts).state,
            RangeStepState::CustodyFailed,
            "a plist with no ProgramArguments is no unit"
        );

        // And the loaded job must run that same path: a job loaded from
        // elsewhere under the label — or no job loaded at all — fails
        // custody, so the installed files alone are never mistaken for a
        // unit that runs.
        let mut facts = root_owned_facts();
        facts.loaded_program = Some("/Users/runner/pwned".to_string());
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains(RANGE_UNIT_LABEL) && check.contains("/Users/runner/pwned"),
            "the check names the label and the program the loaded job runs: {check}"
        );
        let mut facts = root_owned_facts();
        facts.loaded_program = None;
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains(RANGE_UNIT_LABEL),
            "the check names the label no job is loaded under: {check}"
        );
    }

    /// The walk: every directory component of both the unit's paths, from
    /// `/` down, is checked — not just the files' own owner. That is what
    /// makes a unit under `$HOME` or a user-owned Homebrew prefix fail
    /// custody: the component a user can write is inside the unit's path,
    /// and the failure names it.
    #[test]
    fn range_step_custody_walks_every_path_component() {
        // The walk, from `/` down — the directories, never the file itself
        // (the file's custody is its own check, beside this one).
        assert_eq!(
            path_components(RANGE_PROGRAM_PATH),
            ["/", "/Library", "/Library/PrivilegedHelperTools"]
        );
        assert_eq!(
            path_components(RANGE_PLIST_PATH),
            ["/", "/Library", "/Library/LaunchDaemons"]
        );
        // A home-directory path walks the same way — and that is the point:
        // the walk is what makes a unit under `$HOME` fail custody on the
        // component a user owns, never on the files' own owner alone.
        assert_eq!(
            path_components("/Users/runner/dev.minimal.local-range"),
            ["/", "/Users", "/Users/runner"]
        );
        // A user-owned component of the unit's own path fails custody, at
        // that component, however root-owned both files are.
        let mut facts = root_owned_facts();
        let tampered = facts
            .components
            .iter_mut()
            .find(|(path, _)| path == "/Library/PrivilegedHelperTools")
            .expect("the component is on the walk");
        tampered.1 = FileCustody {
            owner: 501,
            mode: 0o755,
        };
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        let check = step.failed_check.as_deref().expect("the check is named");
        assert!(
            check.contains("its directory /Library/PrivilegedHelperTools is owned by uid 501"),
            "the check names the directory and the ownership it read: {check}"
        );
        // A component that did not read is never counted as passing: the
        // walk's honest gap is said, not assumed.
        let mut facts = root_owned_facts();
        facts.components.clear();
        let step = range_step_over(&facts);
        assert_eq!(step.state, RangeStepState::CustodyFailed);
        assert!(
            step.failed_check
                .as_deref()
                .is_some_and(|check| check.contains("its directory / did not read")),
            "the walk says which component it could not read: {step:?}"
        );
    }

    /// One privilege elevation for the whole host's configuration
    /// (NET-122's contract, unchanged by the range step the command now
    /// carries): the command the advisory names is one `sudo sh -c`, and
    /// nothing inside it escalates on its own — the paste prompts once,
    /// however many files it writes.
    #[test]
    fn macos_advisory_command_elevates_exactly_once() {
        let command = macos_command(15353, Some(&test_install()));
        assert_eq!(
            command.matches("sudo").count(),
            1,
            "one privilege elevation for the resolver and the range together: {command}"
        );
        assert!(
            command.starts_with("sudo sh -c '"),
            "the whole host configuration is the one argument: {command}"
        );
        assert_eq!(
            command.matches("sh -c").count(),
            1,
            "and the one shell it runs: {command}"
        );
        // No second escalation hiding inside: no `osascript` prompt, no
        // nested `sudo`, no path the user's shell expands.
        assert!(!command.contains("osascript"), "{command}");
        assert!(
            !command.contains('~'),
            "the command's paths are absolute, never shell-expanded: {command}"
        );
    }

    /// NET-123's re-surface clause, the custody half: the advisory that
    /// fell quiet on a hook that routes comes back when the unit's custody
    /// fails — naming the failed check, and the command that reinstalls
    /// both files — and goes quiet again only when custody holds, the
    /// probe reading present beside it. The probe's own half is
    /// `bind_probe_reads_present_after_the_range_step`'s.
    #[test]
    fn range_step_custody_failure_resurfaces_the_advisory() {
        let port = 15353;
        let configured = routing_hook();
        // The host the command leaves behind: quiet — the probe present,
        // custody holding.
        assert!(
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &installed_range_step(),
                &AnswererStep::Installed,
                None
            )
            .is_none(),
            "custody holding over a present range is the quiet arm's whole condition"
        );
        // Custody failing on the same host: the advisory re-surfaces,
        // naming the check that failed, whatever the probe says — custody
        // is the fact the next boot turns on.
        let mut facts = root_owned_facts();
        facts.plist_program = Some("/Users/runner/pwned".to_string());
        let failed = range_step_over(&facts);
        let check = failed.failed_check.as_deref().expect("the check is named");
        let advisory = advisory_at(
            &configured,
            port,
            false,
            Some(true),
            &failed,
            &AnswererStep::Installed,
            None,
        )
        .expect("a custody failure re-surfaces the advisory");
        assert!(
            advisory.contains(check),
            "the advisory names the failed check: {advisory}"
        );
        assert!(
            advisory.contains(&format!("the range unit {RANGE_UNIT_LABEL} fails custody")),
            "the advisory says the custody verdict: {advisory}"
        );
        assert!(
            advisory.contains("Configure the host's resolver and reserve the local range with:"),
            "and names the command that reinstalls both files: {advisory}"
        );
        // The same failure under the interim: the interim is said, and the
        // custody check with it — the one fact that says *which* step of
        // the unit is not root's.
        let interim = advisory_at(
            &configured,
            port,
            true,
            None,
            &failed,
            &AnswererStep::Installed,
            None,
        )
        .expect("the interim re-surfaces the advisory");
        assert!(
            interim.contains(check),
            "the check is said under the interim too: {interim}"
        );
        // And an absent unit over a probe that reads present: the aliases
        // without the boot step behind them are a range the next boot
        // removes, not a host with nothing left to say.
        let advisory = advisory_at(
            &configured,
            port,
            false,
            Some(true),
            &range_step_over(&RangeFacts::default()),
            &AnswererStep::Installed,
            None,
        )
        .expect("an absent unit re-surfaces the advisory");
        assert!(
            advisory.contains(&format!(
                "the boot-time range unit {RANGE_UNIT_LABEL} is not installed"
            )),
            "the advisory names the absent unit: {advisory}"
        );
    }

    /// The Linux command's resolver steps are the ones NET-122 shipped, now
    /// as `set -e` statements: the range step the macOS arm carries must
    /// not touch them. Linux takes no range step — `lo` carries the whole
    /// `127/8` — and the dedicated link keeps its address, so the advisory
    /// over the not-needed step says nothing of the range's unit, its
    /// paths or its install. What follows the resolver steps is the
    /// answerer service's (NET-122's host service), never the range's.
    #[test]
    fn linux_advisory_command_is_unchanged() {
        let port = 15353;
        let resolver_steps = "sudo sh -c \"set -e; [ -e /sys/class/net/minzone0 ] \
             || ip link add minzone0 type dummy \
             ; ip link set minzone0 up \
             ; ip addr replace 100.127.255.254/32 dev minzone0 \
             ; resolvectl default-route minzone0 false \
             ; resolvectl dns minzone0 127.0.0.1:15353 \
             ; resolvectl domain minzone0 '~min.internal'";
        assert_eq!(
            linux_command(port, None),
            format!("{resolver_steps}\""),
            "without the answerer step the command is the resolver's alone"
        );
        let command = linux_command(port, Some(&test_install()));
        let answerer_steps = command
            .strip_prefix(resolver_steps)
            .unwrap_or_else(|| panic!("the resolver steps lead unchanged: {command}"));
        assert!(
            answerer_steps.starts_with(" ; [ -d '/usr/local/lib/minimal' ] || install -d"),
            "the answerer service's step follows them: {answerer_steps}"
        );
        assert!(
            !command.contains(RANGE_UNIT_LABEL) && !command.contains("local-range"),
            "the Linux command carries no range step: {command}"
        );
        // The quiet arm over the Linux step: the resolver's alone.
        let configured = routing_hook();
        assert!(
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &RangeStep::not_needed(),
                &AnswererStep::Installed,
                None
            )
            .is_none(),
            "the Linux quiet arm is unchanged by the range step"
        );
        let unconfigured = Hook::absent("test", "no hook for the zone");
        let advisory = advisory_at(
            &unconfigured,
            port,
            false,
            None,
            &RangeStep::not_needed(),
            &AnswererStep::Installed,
            None,
        )
        .expect("an unconfigured Linux host is advised");
        assert!(
            advisory.contains("Configure the host's resolver for the zone with:"),
            "the lead-in names the resolver alone: {advisory}"
        );
        assert!(
            !advisory.contains("reserve the local range"),
            "the Linux command takes no range step: {advisory}"
        );
        // The interim arm over the Linux step: the fact names the range
        // and stops — no claim that a command installs what it does not.
        let interim = advisory_at(
            &configured,
            port,
            true,
            None,
            &RangeStep::not_needed(),
            &AnswererStep::Installed,
            None,
        )
        .expect("the interim re-surfaces the advisory");
        assert!(
            !interim.contains("the command below installs the range"),
            "the Linux interim fact claims no range step the command has not: {interim}"
        );
    }

    /// The probe's own half of the range step: the addresses the installed
    /// program applies are exactly the addresses the bind probe probes, so
    /// the probe that read absent — the interim the advisory names — reads
    /// present once the step has run. Pinned purely, over the program's
    /// own bytes and the probe's injected bind (`probe_over`'s stand-in for
    /// a loopback); the operator-run e2e case (the local-range one, under
    /// its opt-in) proves the same fact against a real lo0.
    #[test]
    fn bind_probe_reads_present_after_the_range_step() {
        // The addresses the program applies, parsed from its own bytes: the
        // list its one walk carries.
        let program = range_program();
        let walk = program
            .lines()
            .find(|line| line.starts_with("for addr in ") && line.ends_with("; do"))
            .unwrap_or_else(|| panic!("the program walks the range's addresses: {program}"));
        let list = walk
            .strip_prefix("for addr in ")
            .and_then(|rest| rest.strip_suffix("; do"))
            .expect("the walk line is `for addr in <addresses>; do`");
        let applied: Vec<Ipv4Addr> = list
            .split_whitespace()
            .filter_map(|address| address.parse().ok())
            .collect();
        assert_eq!(
            applied.len(),
            254,
            "the program applies every usable host address: {program}"
        );
        // The host the step has not run on: none of the range is aliased,
        // and the probe — the same address list it always reads — reads
        // absent, the interim.
        let before = switch::loopback::probe_over(applied.iter().copied(), |_| {
            Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))
        });
        assert!(
            before.interim(),
            "a host whose lo0 carries none of the range is on the interim"
        );
        // The host after the step: the program's own addresses are the ones
        // aliased, and the probe over the range's addresses — the exact
        // list the daemon and the CLI read — finds every one of them. That
        // is the fact that ends the interim.
        let after = switch::loopback::probe_over(switch::loopback::range_hosts(), |addr| {
            if applied.contains(&addr) {
                Ok(())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::AddrNotAvailable))
            }
        });
        assert_eq!(after.probed, 254);
        assert_eq!(after.first_failure, None, "no address the step misses");
        assert!(
            after.present(),
            "the probe reads present over the range the step applied"
        );
        assert!(!after.interim());
    }

    /// NET-123's interim fact, in the platform's arms: on macOS the same
    /// command ends the interim — the range step is folded into the one
    /// `sudo` the note names — and on Linux nothing the command runs
    /// installs a range, so the fact names the range and stops. The render
    /// takes the step as its parameter, so both arms' text is asserted
    /// wherever the suite runs.
    #[test]
    fn interim_advisory_says_the_command_ends_it_on_macos() {
        let port = 15353;
        let configured = routing_hook();
        // The macOS arm: the fact says the command below installs the
        // range and ends the interim, and the lead-in says the command
        // configures the resolver and reserves the range.
        let interim = advisory_at(
            &configured,
            port,
            true,
            None,
            &range_step_over(&RangeFacts::default()),
            &AnswererStep::Installed,
            None,
        )
        .expect("the interim re-surfaces the advisory");
        assert!(
            interim.contains("127.0.0.1 interim") && interim.contains(&range_text()),
            "the interim and the range are still the fact's own words: {interim}"
        );
        assert!(
            interim.contains("the command below installs the range and ends the interim"),
            "the macOS interim fact names the command that ends it: {interim}"
        );
        assert!(
            interim.contains("Configure the host's resolver and reserve the local range with:"),
            "and the lead-in says what the command now does: {interim}"
        );
        // The Linux arm: the same fact, no claim about a step the command
        // does not carry.
        let interim = advisory_at(
            &configured,
            port,
            true,
            None,
            &RangeStep::not_needed(),
            &AnswererStep::Installed,
            None,
        )
        .expect("the interim re-surfaces the advisory");
        assert!(
            !interim.contains("the command below installs the range"),
            "the Linux fact claims no range step: {interim}"
        );
        assert!(
            interim.contains("Configure the host's resolver for the zone with:"),
            "the Linux lead-in names the resolver alone: {interim}"
        );
    }

    #[cfg(any(test, not(target_os = "macos")))]
    #[test]
    fn linux_command_targets_a_dedicated_link_off_the_default_route() {
        let command = linux_command(15353, Some(&test_install()));
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
        let advisory = advisory_at(
            &hook,
            15353,
            false,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            Some(&blocker),
        )
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
        let advisory = advisory_at(
            &routed,
            15353,
            false,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            Some(&blocker),
        )
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
        let advisory = advisory_at(
            &hook,
            15353,
            false,
            None,
            &range_step_on_this_os(),
            &AnswererStep::Installed,
            None,
        )
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
            // The range step's record beside the probe's result (NET-123's
            // diagnostics): whether the unit is installed, its files' owner
            // and mode, the program path the plist runs, and the custody
            // verdict over all of it.
            range_step: installed_range_step(),
        };
        let json = serde_json_lenient::to_string_pretty(&surface).unwrap();
        assert!(json.contains("\"zone\": \"min.internal\""), "{json}");
        assert!(json.contains("127.0.64.0/24"), "{json}");
        assert!(json.contains("\"interim_loopback\": false"), "{json}");
        assert!(json.contains("\"port\": 15353"), "{json}");
        assert!(
            json.contains("\"range_step\""),
            "the bundle carries the range step beside the probe: {json}"
        );
        assert!(
            json.contains("\"state\": \"Installed\""),
            "the record says the unit is installed: {json}"
        );
        assert!(
            json.contains(&format!("\"plist_program\": \"{RANGE_PROGRAM_PATH}\"")),
            "the record says which program the plist runs: {json}"
        );
        assert!(
            json.contains("\"owner\": 0"),
            "the record says who owns the unit's files: {json}"
        );
        assert!(
            json.contains("\"mode\": 493") && json.contains("\"mode\": 420"),
            "the record carries the files' modes (0755, 0644): {json}"
        );
        assert!(
            json.contains("\"failed_check\": null"),
            "an installed unit has no failed check to name: {json}"
        );
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
        let [surface] = live_name_surfaces(std::iter::once((Some(15353), true)))
            .await
            .try_into()
            .expect("one VM's facts in, one verdict out");
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
        let (hook, _, _) = ls_detection().await;
        assert!(
            hook.routes(15353),
            "both queries must read within the one deadline — run together, not \
             one after the other: {hook:?}"
        );
        drop(standin);
    }

    /// The answerer service's custody facts as the step leaves them: every
    /// directory component of the program copy's path and every unit's
    /// root-owned with no group or other write, the copy and every unit
    /// file root's, the unit naming the copy, and the copy answering
    /// `version` to the protocol probe.
    fn root_owned_answerer_facts(version: Option<u32>) -> AnswererFacts {
        let mut components = Vec::new();
        for path in
            std::iter::once(ANSWERER_PROGRAM_PATH).chain(ANSWERER_UNIT_PATHS.iter().copied())
        {
            for component in path_components(path) {
                components.push((
                    component,
                    FileCustody {
                        owner: 0,
                        mode: 0o755,
                    },
                ));
            }
        }
        AnswererFacts {
            components,
            program: Some(FileCustody {
                owner: 0,
                mode: 0o755,
            }),
            units: ANSWERER_UNIT_PATHS
                .iter()
                .map(|_| {
                    Some(FileCustody {
                        owner: 0,
                        mode: 0o644,
                    })
                })
                .collect(),
            unit_program: Some(ANSWERER_PROGRAM_PATH.to_string()),
            installed_version: version,
        }
    }

    // NET-122's host service, on the advisory's one privileged step: the
    // command copies `minzoned` to a root-owned path and installs the
    // service unit pointing at that copy — a launchd plist with socket
    // activation on macOS, a systemd socket and service pair on Linux —
    // run as the operator, never at the user-writable binary it copied
    // from; and the advisory re-surfaces until that service holds.
    #[test]
    fn advisory_installs_manager_held_answerer() {
        let install = test_install();
        let daemon = minvmd::net::answerer::CHANNEL_PROTOCOL_VERSION;

        // macOS: the copy, root's, and the plist naming it with both
        // sockets launchd holds.
        let mac = macos_command(15353, Some(&install));
        let copy = format!("install -m 0755 -o root -g wheel \"{}\" $t", install.source);
        let copy_at = mac
            .find(&copy)
            .expect("the macOS step copies the program, root's");
        let chown_at = mac
            .find(&format!("mv -f $t \"{MACOS_ANSWERER_PROGRAM_PATH}\""))
            .expect("the macOS step renames the verified copy into place");
        assert!(
            chown_at
                < mac
                    .find(&format!("chown root:wheel {ANSWERER_PLIST_PATH}"))
                    .unwrap(),
            "the copy is in place before the plist is written: {mac}"
        );
        let load_at = mac
            .find(&format!("launchctl bootstrap system {ANSWERER_PLIST_PATH}"))
            .expect("the macOS step loads the service into the system domain");
        assert!(copy_at < chown_at && chown_at < load_at, "{mac}");
        let plist = answerer_unit_plist(&install);
        assert!(
            mac.contains(&plist),
            "the command carries the plist's bytes: {mac}"
        );
        assert_eq!(
            plist_program_argument(&plist),
            Some(MACOS_ANSWERER_PROGRAM_PATH),
            "the plist runs the root-owned copy, never the source: {plist}"
        );
        assert!(
            !plist.contains(&format!("<string>{}</string>", install.source)),
            "the plist never names the user-writable source: {plist}"
        );
        for socket in [
            "<key>Sockets</key>",
            "<key>Listener</key>",
            "<key>Channel</key>",
        ] {
            assert!(
                plist.contains(socket),
                "launchd holds both sockets: {plist}"
            );
        }
        assert!(
            plist.contains(&format!(
                "<key>UserName</key>\n\t<string>{}</string>",
                install.operator
            )),
            "the service runs as the operator: {plist}"
        );
        assert!(
            plist.contains(
                "<key>SockType</key>\n\t\t\t<string>dgram</string>\n\t\t\t\
                 <key>SockProtocol</key>\n\t\t\t<string>UDP</string>\n\t\t\t\
                 <key>SockNodeName</key>\n\t\t\t<string>127.0.0.1</string>"
            ),
            "the listener is a loopback-only datagram socket launchd can create: {plist}"
        );
        assert!(
            !plist.contains('\''),
            "no apostrophe inside the single quotes"
        );
        assert!(sh_parses(&mac), "the macOS command parses: {mac}");

        // Linux: the copy, root's, and a system socket+service pair naming
        // it, run as the operator, the channel's directory the socket
        // unit's RuntimeDirectory.
        let linux = linux_command(15353, Some(&install));
        let copy = format!("install -m 0755 -o root -g root '{}' \\$t", install.source);
        let copy_at = linux
            .find(&copy)
            .expect("the Linux step copies the program, root's");
        let chown_at = linux
            .find(&format!("mv -f \\$t '{LINUX_ANSWERER_PROGRAM_PATH}'"))
            .expect("the Linux step renames the verified copy into place");
        assert!(
            chown_at
                < linux
                    .find(&format!("cat > {ANSWERER_UNIT_SOCKET_PATH}"))
                    .unwrap(),
            "the copy is in place before the units are written: {linux}"
        );
        let enable_at = linux
            .find(&format!("systemctl enable {ANSWERER_SYSTEMD_UNIT}.socket"))
            .expect("the Linux step enables the socket unit");
        assert!(copy_at < chown_at && chown_at < enable_at, "{linux}");
        let socket = answerer_socket_unit(&install);
        let service = answerer_service_unit(&install);
        assert!(
            linux.contains(&socket) && linux.contains(&service),
            "{linux}"
        );
        assert!(socket.contains("ListenDatagram=127.0.0.1:7656"), "{socket}");
        assert!(
            socket.contains(&format!("ListenStream={}", install.channel)),
            "{socket}"
        );
        if install.channel == "/run/minimal/answerer.sock" {
            assert!(socket.contains("RuntimeDirectory=minimal\n"), "{socket}");
        }
        assert_eq!(
            service_exec_start(&service),
            Some(LINUX_ANSWERER_PROGRAM_PATH),
            "the service runs the root-owned copy, never the source: {service}"
        );
        assert!(
            service.contains(&format!("User={}", install.operator)),
            "the service runs as the operator: {service}"
        );
        assert!(
            ANSWERER_UNIT_SOCKET_PATH.starts_with("/etc/systemd/system/")
                && ANSWERER_UNIT_SERVICE_PATH.starts_with("/etc/systemd/system/"),
            "system units, never a user-session unit"
        );
        assert!(sh_parses(&linux), "the Linux command parses: {linux}");
        // The install marker the daemons decide "installed" by is the unit
        // file this step writes.
        #[cfg(target_os = "macos")]
        assert_eq!(minvmd::net::answerer::INSTALL_MARKER, ANSWERER_PLIST_PATH);
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            minvmd::net::answerer::INSTALL_MARKER,
            ANSWERER_UNIT_SOCKET_PATH
        );

        // The step's checks read that state back as installed, and a unit
        // that names any other program fails custody.
        assert_eq!(
            answerer_step_over(&root_owned_answerer_facts(Some(daemon)), daemon),
            AnswererStep::Installed
        );
        let mut user_writable = root_owned_answerer_facts(Some(daemon));
        user_writable.unit_program = Some("/home/operator/.minimal/bin/minvmd".to_string());
        assert!(
            matches!(
                answerer_step_over(&user_writable, daemon),
                AnswererStep::CustodyFailed { .. }
            ),
            "a unit naming a user-writable binary fails custody"
        );

        // The advisory re-surfaces until the service holds, naming the
        // command that installs it; it falls quiet once it does.
        let port = 15353;
        let configured = Hook::configured("test", Some(port), "routes the zone");
        let advisory = advisory_at(
            &configured,
            port,
            false,
            Some(true),
            &range_step_on_this_os(),
            &verified(AnswererStep::Absent),
            None,
        )
        .expect("a host without the answerer service is advised");
        assert!(
            advisory.contains("not installed as a host service")
                && advisory.contains("install the Minimal box-name service"),
            "{advisory}"
        );
        assert!(
            advisory.contains(&command(port, verified_install().as_ref())),
            "{advisory}"
        );
        assert!(
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &range_step_on_this_os(),
                &AnswererStep::Installed,
                None,
            )
            .is_none(),
            "an installed, manager-held answerer lets the advisory fall quiet"
        );
    }

    // NET-122's upgrade path: the hook probe compares the installed copy's
    // channel protocol version with the daemon's and re-surfaces the
    // advisory on a mismatch — including a copy that does not answer the
    // probe at all — so an upgrade re-runs the step.
    #[test]
    fn hook_probe_resurfaces_advisory_on_protocol_mismatch() {
        let daemon = minvmd::net::answerer::CHANNEL_PROTOCOL_VERSION;
        let port = 15353;
        let configured = Hook::configured("test", Some(port), "routes the zone");
        let advise = |step: &AnswererStep| {
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &range_step_on_this_os(),
                step,
                None,
            )
        };

        let behind = answerer_step_over(&root_owned_answerer_facts(Some(daemon + 1)), daemon);
        assert_eq!(
            behind,
            AnswererStep::ProtocolMismatch {
                installed: Some(daemon + 1),
                daemon
            }
        );
        assert!(!behind.holds());
        let advisory =
            advise(&verified(behind)).expect("a mismatched copy re-surfaces the advisory");
        assert!(
            advisory.contains(&format!("speaks channel protocol {}", daemon + 1))
                && advisory.contains(&format!("not this daemon's {daemon}")),
            "the advisory names both versions: {advisory}"
        );
        assert!(
            advisory.contains(&command(port, verified_install().as_ref())),
            "{advisory}"
        );

        let silent = answerer_step_over(&root_owned_answerer_facts(None), daemon);
        assert_eq!(
            silent,
            AnswererStep::ProtocolMismatch {
                installed: None,
                daemon
            }
        );
        let advisory =
            advise(&verified(silent)).expect("a copy that does not answer re-surfaces it");
        assert!(
            advisory.contains(&format!(
                "does not answer this daemon's channel protocol {daemon}"
            )),
            "{advisory}"
        );

        let current = answerer_step_over(&root_owned_answerer_facts(Some(daemon)), daemon);
        assert!(current.holds());
        assert!(
            advise(&current).is_none(),
            "a matching copy lets it fall quiet"
        );
    }

    /// NET-122's identity check, through the real wiring
    /// ([`answerer_step_with_source`], the half of [`read_answerer_step`]
    /// after the service state is read) with the identity checker injected:
    /// a source that fails it is refused with the reason and never carried;
    /// a source that passes is pinned, and the rendered command carries the
    /// SHA-256 of exactly the bytes that were checked. The source sits in a
    /// prefix its user can write, so this is the pre-check; the privileged
    /// step's own re-check of the root-owned copy is
    /// `privileged_copy_refuses_a_source_swapped_after_render`.
    #[tokio::test]
    async fn advisory_refuses_an_unsigned_or_link_unclean_source() {
        use sha2::Digest as _;
        let port = 15353;
        let configured = Hook::configured("test", Some(port), "routes the zone");
        let advise = |step: &AnswererStep| {
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &range_step_on_this_os(),
                step,
                None,
            )
        };
        let dir = tempfile::tempdir().expect("a temp dir");
        let source = dir.path().join(ANSWERER_PROGRAM_NAME);
        let bytes = b"minzoned fixture bytes\n";
        std::fs::write(&source, bytes).expect("the fixture source");
        let source = source.display().to_string();
        let pinned = hex::encode(sha2::Sha256::digest(bytes));

        // A source that fails its identity check: refused, with the reason.
        let reason = "failed its Developer ID check: codesign --verify --strict -R did not \
                      accept it (test-requirement: code failed to satisfy specified code \
                      requirement(s))";
        let refused =
            answerer_step_with_source(AnswererStep::Absent, Some(source.clone()), |_| async {
                Err(SourceProblem::Refused(reason.to_string()))
            })
            .await;
        assert_eq!(
            refused,
            AnswererStep::SourceRefused {
                service: Box::new(AnswererStep::Absent),
                reason: reason.to_string(),
            }
        );
        assert!(!refused.holds(), "a refused source leaves the step to do");
        let advisory = advise(&refused).expect("a refused source still advises");
        assert!(
            advisory.contains(&format!(
                "this machine's box-zone answerer program {ANSWERER_PROGRAM_NAME} failed the \
                 check the advisory runs before offering to copy it ({reason})"
            )),
            "the advisory names the reason: {advisory}"
        );
        assert!(
            advisory.contains("not installed as a host service"),
            "the service state underneath the refusal survives: {advisory}"
        );
        assert!(
            !advisory.contains(ANSWERER_PROGRAM_PATH) && !advisory.contains(&pinned),
            "no copy of the program is carried: {advisory}"
        );
        assert!(
            !advisory.contains("install the Minimal box-name service"),
            "the lead-in offers no answerer install: {advisory}"
        );
        assert!(
            advisory.contains(&format!("\n  {}", command(port, None))),
            "the command is the resolver's alone: {advisory}"
        );

        // A source that passes: verified and pinned to its bytes' SHA-256,
        // with the requirement the root step re-checks the copy by.
        let requirement =
            answerer_requirement("3G47C5HY64", "dev.minimal.minzoned").expect("safe values");
        let checked = std::sync::Mutex::new(None);
        let passed =
            answerer_step_with_source(AnswererStep::Absent, Some(source.clone()), |path| {
                *checked.lock().unwrap() = Some(path);
                let requirement = requirement.clone();
                async move { Ok(Some(requirement)) }
            })
            .await;
        assert_eq!(
            checked.lock().unwrap().as_deref(),
            Some(source.as_str()),
            "the identity check ran on the source the step copies"
        );
        let AnswererStep::SourceVerified {
            service,
            source: verified,
        } = &passed
        else {
            panic!("a passing source is verified: {passed:?}");
        };
        assert_eq!(**service, AnswererStep::Absent);
        assert_eq!(
            verified.sha256, pinned,
            "the pin is the checked bytes' hash"
        );
        assert_eq!(verified.requirement.as_deref(), Some(requirement.as_str()));
        let advisory = advise(&passed).expect("a verified source advises the step");
        assert!(
            advisory.contains(&format!(" in {pinned}) ;;")),
            "the rendered command carries the pinned hash: {advisory}"
        );
        assert!(
            advisory.contains("install the Minimal box-name service"),
            "the lead-in offers the answerer install: {advisory}"
        );
        #[cfg(target_os = "macos")]
        assert!(
            advisory.contains(&format!(
                "codesign --verify --strict -R \"={}\" $t",
                requirement.replace('"', "\\\"")
            )),
            "the root step re-verifies the copy against the requirement: {advisory}"
        );

        // The checker this build really runs — the debug-and-test half of
        // the gate — verifies without a requirement, and the pin still
        // applies.
        let real = answerer_step_with_source(
            AnswererStep::Absent,
            Some(source.clone()),
            answerer_source_identity,
        )
        .await;
        assert!(
            matches!(
                &real,
                AnswererStep::SourceVerified { source: VerifiedSource { sha256, requirement: None, .. }, .. }
                    if *sha256 == pinned
            ),
            "{real:?}"
        );

        // A source that cannot be read is refused, never pinned to nothing.
        let unreadable = answerer_step_with_source(
            AnswererStep::Absent,
            Some(dir.path().join("absent").display().to_string()),
            answerer_source_identity,
        )
        .await;
        assert!(
            matches!(&unreadable, AnswererStep::SourceRefused { reason, .. }
                if reason.starts_with("could not be read to pin its SHA-256")),
            "{unreadable:?}"
        );

        // A held step is not touched: no source is checked.
        for step in [AnswererStep::Installed] {
            let untouched =
                answerer_step_with_source(step.clone(), Some(source.clone()), |_| async {
                    panic!("a step that holds checks no source")
                })
                .await;
            assert_eq!(untouched, step);
        }
    }

    /// When the release ships no `minzoned`, or the build carries no
    /// signing identity to verify one by, the step is unavailable and the
    /// advisory says so by name — it never silently drops the step.
    #[tokio::test]
    async fn advisory_names_an_unavailable_answerer_step() {
        let port = 15353;
        let configured = Hook::configured("test", Some(port), "routes the zone");
        let advise = |step: &AnswererStep| {
            advisory_at(
                &configured,
                port,
                false,
                Some(true),
                &range_step_on_this_os(),
                step,
                None,
            )
            .expect("a host still missing the service is advised")
        };

        let unshipped = answerer_step_with_source(AnswererStep::Absent, None, |_| async {
            panic!("no source, nothing to check")
        })
        .await;
        assert_eq!(
            unshipped,
            AnswererStep::SourceUnavailable {
                service: Box::new(AnswererStep::Absent),
                reason: ANSWERER_NOT_SHIPPED.to_string(),
            }
        );
        let advisory = advise(&unshipped);
        assert!(
            advisory.contains(
                "this release ships no minzoned; the answerer service step is unavailable"
            ),
            "{advisory}"
        );
        assert!(
            advisory.contains("not installed as a host service"),
            "the service state underneath survives: {advisory}"
        );
        assert!(
            advisory.contains(&format!("\n  {}", command(port, None)))
                && !advisory.contains("install the Minimal box-name service"),
            "the command carries no answerer step: {advisory}"
        );

        // A macOS release build with no TEAMID or identifier compiled in.
        let no_identity = macos_answerer_requirement(None, Some("dev.minimal.minzoned"))
            .expect_err("no TEAMID, no requirement");
        assert_eq!(
            no_identity,
            SourceProblem::Unavailable(ANSWERER_NO_SIGNING_IDENTITY.to_string())
        );
        assert!(macos_answerer_requirement(Some("3G47C5HY64"), None).is_err());
        let step = answerer_step_with_source(
            AnswererStep::Absent,
            Some(TEST_ANSWERER_SOURCE.to_string()),
            |_| async { Err(no_identity) },
        )
        .await;
        let advisory = advise(&step);
        assert!(
            advisory.contains(
                "this build carries no signing identity; the answerer service step is \
                 unavailable"
            ),
            "{advisory}"
        );
        assert!(
            !advisory.contains("install the Minimal box-name service"),
            "never a fallback to a weaker check: {advisory}"
        );

        // The requirement a build that does carry one checks by.
        assert_eq!(
            macos_answerer_requirement(Some("3G47C5HY64"), Some("dev.minimal.minzoned")),
            Ok(
                "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
                and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate \
                leaf[subject.OU] = \"3G47C5HY64\" and identifier \"dev.minimal.minzoned\""
                    .to_string()
            )
        );
        for (teamid, identifier) in [("3G47\"C5", "id"), ("TEAM", "id' x"), ("", "id")] {
            assert_eq!(
                answerer_requirement(teamid, identifier),
                None,
                "{teamid:?} / {identifier:?} cannot ride in the command"
            );
        }
    }

    /// A temp tree the privileged copy fragment runs in, unprivileged:
    /// `install` is stubbed to a plain `cp` (ownership needs root), and
    /// `find` delegates to the real one inside the tree with `-user root`
    /// mapped to `COPY_ROOT` (this user unless a test says otherwise), and
    /// answers as root's for the ancestors above the tree.
    struct CopyHarness {
        _root: tempfile::TempDir,
        stubs: std::path::PathBuf,
        tree: std::path::PathBuf,
        ancestor: std::path::PathBuf,
        dest_dir: std::path::PathBuf,
        dest: std::path::PathBuf,
        source: std::path::PathBuf,
        checked: &'static [u8],
        pinned: String,
    }

    impl CopyHarness {
        fn new() -> Self {
            use sha2::Digest as _;
            use std::os::unix::fs::PermissionsExt as _;
            let root = tempfile::tempdir().expect("a temp dir");
            let base = root.path().canonicalize().expect("the temp dir resolves");
            let stubs = base.join("stubs");
            let tree = base.join("tree");
            let ancestor = tree.join("a");
            let dest_dir = ancestor.join("dest");
            std::fs::create_dir_all(&stubs).unwrap();
            std::fs::create_dir_all(&dest_dir).unwrap();
            for dir in [&tree, &ancestor, &dest_dir] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let stub = |name: &str, body: &str| {
                let path = stubs.join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            };
            // `install -m 0755 -o root -g <group> <src> <dst>`: the last two
            // arguments are the copy.
            stub(
                "install",
                "if [ \"$1\" = -d ]; then while [ $# -gt 1 ]; do shift; done; \
                 mkdir -m 0755 \"$1\"; exit; fi\n\
                 while [ $# -gt 2 ]; do shift; done\ncp \"$1\" \"$2\"",
            );
            stub(
                "find",
                "p=$1; shift\n\
                 case \"$p\" in \"$COPY_TREE\"|\"$COPY_TREE\"/*) ;; *) printf '%s\\n' \"$p\"; exit 0 ;; esac\n\
                 owner=${COPY_ROOT:-$(id -un)}\n\
                 exec /usr/bin/find \"$p\" $(printf '%s ' \"$@\" | sed \"s/-user root/-user $owner/\")",
            );
            let source = base.join(ANSWERER_PROGRAM_NAME);
            let checked: &'static [u8] = b"the bytes the advisory checked\n";
            std::fs::write(&source, checked).unwrap();
            let pinned = hex::encode(sha2::Sha256::digest(checked));
            let dest = dest_dir.join("minzoned");
            CopyHarness {
                _root: root,
                stubs,
                tree,
                ancestor,
                dest_dir,
                dest,
                source,
                checked,
                pinned,
            }
        }

        /// Runs the rendered fragment the way the pasted command's inner
        /// shell receives it — the payload's own quoting, then `sh -c` —
        /// with `COPY_ROOT` as the owner the `find` stub calls root.
        fn run(&self, copy_root: Option<&str>) -> std::process::Output {
            let macos = cfg!(target_os = "macos");
            let install = AnswererInstall {
                source: self.source.display().to_string(),
                sha256: self.pinned.clone(),
                ..test_install()
            };
            let fragment = verified_copy_steps(
                &install,
                &self.dest_dir.display().to_string(),
                &self.dest.display().to_string(),
                macos,
            );
            let pasted = if macos {
                format!("sh -c 'set -e{fragment}'")
            } else {
                format!("sh -c \"set -e{fragment}\"")
            };
            let mut command = std::process::Command::new("/bin/sh");
            command
                .args(["-c", &pasted])
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        self.stubs.display(),
                        std::env::var("PATH").unwrap_or_default()
                    ),
                )
                .env("COPY_TREE", &self.tree)
                .env_remove("COPY_ROOT");
            if let Some(owner) = copy_root {
                command.env("COPY_ROOT", owner);
            }
            command.output().expect("sh runs")
        }

        /// The temp copies left in the destination directory.
        fn leftovers(&self) -> Vec<String> {
            std::fs::read_dir(&self.dest_dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with('.'))
                .collect()
        }

        /// Asserts a refusal that names `offender` as the first component
        /// of the destination's path that fails custody, with nothing
        /// copied.
        fn assert_refused_at(&self, output: &std::process::Output, offender: &std::path::Path) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "refused: {stderr}");
            assert!(
                stderr.contains(&format!(
                    "minimal: {}, on the path to {}, is not a root-owned, non-sticky directory",
                    offender.display(),
                    self.dest_dir.display()
                )),
                "the refusal names the first offender {}: {stderr}",
                offender.display()
            );
            assert!(!self.dest.exists(), "nothing reaches the destination");
            assert!(self.leftovers().is_empty(), "{:?}", self.leftovers());
        }
    }

    /// A stock host has no destination dir until the first install: the
    /// root step creates it root-owned at 0755 (never the umask's mode)
    /// before the ancestor walk, which then checks the new dir with the rest.
    #[test]
    fn privileged_copy_creates_a_missing_destination() {
        use std::os::unix::fs::PermissionsExt as _;
        let harness = CopyHarness::new();
        std::fs::remove_dir(&harness.dest_dir).unwrap();

        let output = harness.run(None);
        assert!(
            output.status.success(),
            "a missing destination is created and the checked bytes install: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mode = std::fs::metadata(&harness.dest_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755, "the destination is created at 0755");
        assert_eq!(std::fs::read(&harness.dest).unwrap(), harness.checked);
    }

    /// The privileged step's verified copy (design §7.1): the rendered copy
    /// fragment copies the pinned bytes into place, and refuses a source
    /// swapped after the render, removing its temp copy and naming both
    /// hashes.
    #[test]
    fn privileged_copy_refuses_a_source_swapped_after_render() {
        use sha2::Digest as _;
        let harness = CopyHarness::new();

        let output = harness.run(None);
        assert!(
            output.status.success(),
            "the checked bytes install: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read(&harness.dest).unwrap(), harness.checked);
        assert!(harness.leftovers().is_empty(), "{:?}", harness.leftovers());

        std::fs::remove_file(&harness.dest).unwrap();
        let swapped = b"bytes planted after the advisory checked\n";
        std::fs::write(&harness.source, swapped).unwrap();
        let actual = hex::encode(sha2::Sha256::digest(swapped));
        let output = harness.run(None);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "a swapped source is refused");
        assert!(
            stderr.contains(&harness.pinned) && stderr.contains(&actual),
            "the refusal names both hashes: {stderr}"
        );
        assert!(!harness.dest.exists(), "nothing reaches the destination");
        assert!(
            harness.leftovers().is_empty(),
            "the temp copy is removed: {:?}",
            harness.leftovers()
        );
    }

    /// Every ancestor of the destination counts, not only the directory
    /// itself: one that others can write, or a sticky one, lets a user
    /// rename the directory away between the check and the rename, so the
    /// step refuses and names it before anything is copied.
    #[test]
    fn privileged_copy_refuses_a_user_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;
        let harness = CopyHarness::new();
        for mode in [0o777, 0o775, 0o757, 0o1755] {
            std::fs::set_permissions(&harness.ancestor, std::fs::Permissions::from_mode(mode))
                .unwrap();
            let output = harness.run(None);
            harness.assert_refused_at(&output, &harness.ancestor);
        }
        std::fs::set_permissions(&harness.ancestor, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let output = harness.run(None);
        assert!(
            output.status.success(),
            "the same tree with the ancestor closed installs: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// A destination directory root does not own is refused before
    /// anything is copied: the real `find` says so of this user-owned temp
    /// tree, the destination directory the first component it walks. A
    /// suite run as root owns the tree, so the test asserts only off root.
    #[test]
    fn privileged_copy_refuses_a_user_owned_destination() {
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let harness = CopyHarness::new();
        let output = harness.run(Some("root"));
        harness.assert_refused_at(&output, &harness.dest_dir);
    }

    /// NET-122's upgrade path the other way: a root-owned copy OLDER than
    /// this daemon — what a release upgrade leaves behind — re-surfaces
    /// the advisory the way a newer one does, and the command it names
    /// re-copies the program, so an old root copy never runs silently
    /// against a new channel.
    #[test]
    fn advisory_resurfaces_when_service_binary_is_older() {
        let daemon = minvmd::net::answerer::CHANNEL_PROTOCOL_VERSION;
        let port = 15353;
        let configured = Hook::configured("test", Some(port), "routes the zone");

        let older = answerer_step_over(&root_owned_answerer_facts(Some(daemon - 1)), daemon);
        assert_eq!(
            older,
            AnswererStep::ProtocolMismatch {
                installed: Some(daemon - 1),
                daemon
            }
        );
        assert!(!older.holds(), "a behind copy does not hold");

        // Even with the hook routing the zone and everything else held, a
        // behind copy re-surfaces the advisory: the host service exists,
        // and it still speaks the box a release upgrade replaced.
        let advisory = advisory_at(
            &configured,
            port,
            false,
            Some(true),
            &range_step_on_this_os(),
            &verified(older),
            None,
        )
        .expect("a behind copy re-surfaces the advisory even when the hook routes");
        assert!(
            advisory.contains(&format!("speaks channel protocol {}", daemon - 1))
                && advisory.contains(&format!("not this daemon's {daemon}")),
            "the advisory names both versions: {advisory}"
        );
        // And the command it names re-copies the root-owned program.
        let install = verified_install().expect("the step's inputs");
        assert!(
            advisory.contains(&command(port, Some(&install))),
            "the command carries the answerer step: {advisory}"
        );
        #[cfg(target_os = "macos")]
        let re_copy = [
            format!("install -m 0755 -o root -g wheel \"{}\" $t", install.source),
            format!("mv -f $t \"{MACOS_ANSWERER_PROGRAM_PATH}\""),
        ];
        #[cfg(not(target_os = "macos"))]
        let re_copy = [
            format!("install -m 0755 -o root -g root '{}' \\$t", install.source),
            format!("mv -f \\$t '{LINUX_ANSWERER_PROGRAM_PATH}'"),
        ];
        for step in &re_copy {
            assert!(
                advisory.contains(step),
                "the command re-copies the root-owned program ({step}): {advisory}"
            );
        }
        assert!(
            advisory.contains(&format!(" in {}) ;;", install.sha256)),
            "the re-copy is pinned to the verified source's hash: {advisory}"
        );
    }

    /// The handover's order (NET-122's privileged step): the command
    /// installs the units without starting the port socket, asks each of
    /// this CLI's daemons to release the hook port, and only then starts
    /// the unit and waits for it; either wait running out removes what the
    /// step installed, asks the daemons to re-bind, and exits non-zero —
    /// and with no daemon known the unit starts directly.
    #[test]
    fn advisory_releases_the_port_before_starting_the_unit() {
        let install = test_install();
        let linux = linux_command(15353, Some(&install));
        let release = format!(
            "'{LINUX_ANSWERER_PROGRAM_PATH}' release --control '{}' --control '{}'",
            install.controls[0], install.controls[1]
        );
        let enable_at = linux
            .find(&format!("systemctl enable {ANSWERER_SYSTEMD_UNIT}.socket"))
            .expect("the units are enabled");
        let release_at = linux
            .find(&release)
            .expect("the daemons are asked to release");
        let start_at = linux
            .find(&format!(
                "systemctl start --no-block {ANSWERER_SYSTEMD_UNIT}.socket"
            ))
            .expect("the socket unit is started");
        assert!(
            enable_at < release_at && release_at < start_at,
            "install, release, then start: {linux}"
        );
        assert!(
            !linux[..release_at].contains("systemctl start") && !linux.contains("enable --now"),
            "nothing starts the port socket before the release: {linux}"
        );
        let cancel = format!(
            "'{LINUX_ANSWERER_PROGRAM_PATH}' release-cancel --control '{}' --control '{}'",
            install.controls[0], install.controls[1]
        );
        assert_eq!(
            linux.matches(&cancel).count(),
            3,
            "every failed wait asks the daemons to re-bind: {linux}"
        );
        // Those three, and the verified copy's four refusals (creating the
        // destination dir, its ancestor walk, the copy, the hash pin), which
        // run before anything is released and so have nothing to re-bind.
        assert_eq!(
            linux.matches("exit 1").count(),
            7,
            "and fails the command: {linux}"
        );
        assert!(
            linux.contains("(a collision)"),
            "a port taken is named a collision"
        );
        assert!(sh_parses(&linux), "{linux}");
        let payload = linux
            .strip_prefix("sudo sh -c \"")
            .and_then(|rest| rest.strip_suffix('"'))
            .expect("one sudo sh -c, its payload double-quoted whole");
        assert!(
            !payload.replace("\\$", "").contains('$') && !payload.contains('`'),
            "nothing inside the double quotes expands in the outer shell — the copy's own \
             names are escaped for the inner one: {payload}"
        );

        let mac = macos_command(15353, Some(&install));
        let release_at = mac.find("release --control").expect("macOS releases too");
        let load_at = mac
            .find(&format!("launchctl bootstrap system {ANSWERER_PLIST_PATH}"))
            .expect("macOS loads the plist");
        assert!(
            release_at < load_at,
            "launchd follows the same order: {mac}"
        );
        assert!(sh_parses(&mac), "{mac}");

        // No daemon known: the unit starts directly, nothing to release.
        let alone = AnswererInstall {
            controls: Vec::new(),
            ..install
        };
        let direct = linux_command(15353, Some(&alone));
        assert!(!direct.contains(" release"), "{direct}");
        assert!(
            direct.contains(&format!(
                "systemctl start --no-block {ANSWERER_SYSTEMD_UNIT}.socket"
            )),
            "{direct}"
        );
        assert!(sh_parses(&direct), "{direct}");
    }

    /// NET-122's host service on a native host: the advisory offers the
    /// same privileged step a VM-backed host gets — the root-owned copy of
    /// `minzoned`, released out of the daemon serving this session and
    /// then started as the manager-held answerer — and the socket the
    /// command asks to release is the native daemon's own, the control
    /// socket beside its ssh socket in the Minimald provider dir this
    /// CLI's state dir resolves. The advisory goes quiet only once the
    /// service holds the zone, never when the resolver step alone is done.
    #[test]
    fn native_advisory_installs_manager_held_answerer() {
        // The control socket a native session start records, by the same
        // rule the start itself uses: beside the daemon's ssh socket.
        let native_control = crate::cmd::control_sock_beside(
            &crate::client::resolve_socket_path(
                Some(std::path::Path::new("/state/minimal")),
                false,
            )
            .expect("the native daemon's ssh socket"),
        )
        .expect("the control socket beside it");
        assert_eq!(
            native_control,
            std::path::Path::new("/state/minimal/providers/local-minimald0/control.sock"),
            "the native daemon's control socket sits in the Minimald provider dir"
        );
        set_handover_controls(vec![native_control.display().to_string()]);
        struct ControlsReset;
        impl Drop for ControlsReset {
            fn drop(&mut self) {
                set_handover_controls(Vec::new());
            }
        }
        let _reset = ControlsReset;

        let port = 15353;
        // A host without the service: the step is offered, and the
        // command asks the native daemon to release the interim before the
        // manager-held answerer takes the port.
        let unconfigured = Hook::absent("test", "no hook for the zone");
        let advisory = advisory_at(
            &unconfigured,
            port,
            false,
            None,
            &RangeStep::not_needed(),
            &verified(AnswererStep::Absent),
            None,
        )
        .expect("a native host without the answerer service is advised");
        assert!(
            advisory.contains("not installed as a host service")
                && advisory.contains("install the Minimal box-name service"),
            "the native advisory offers the answerer service step: {advisory}"
        );
        assert!(
            advisory.contains(&command(port, verified_install().as_ref())),
            "the command is the step's own render: {advisory}"
        );
        assert!(
            advisory.contains(&native_control.display().to_string()),
            "the command names the native daemon's control socket: {advisory}"
        );
        let release_at = advisory
            .find("release --control")
            .expect("the native daemon is asked to release the hook port");
        #[cfg(target_os = "macos")]
        let start_at = advisory
            .find(&format!("launchctl bootstrap system {ANSWERER_PLIST_PATH}"))
            .expect("the service is loaded into launchd");
        #[cfg(not(target_os = "macos"))]
        let start_at = advisory
            .find(&format!(
                "systemctl start --no-block {ANSWERER_SYSTEMD_UNIT}.socket"
            ))
            .expect("the socket unit is started");
        assert!(
            release_at < start_at,
            "release the interim before the service takes the port: {advisory}"
        );

        // The resolver step alone no longer quiets a native host: with the
        // hook routing and the range present, the advisory still names the
        // missing service, and goes quiet only once it holds the zone.
        assert!(
            advisory_at(
                &routing_hook(),
                port,
                false,
                Some(true),
                &RangeStep::not_needed(),
                &verified(AnswererStep::Absent),
                None,
            )
            .is_some(),
            "a routing hook does not quiet a native host without the service"
        );
        assert!(
            advisory_at(
                &routing_hook(),
                port,
                false,
                Some(true),
                &RangeStep::not_needed(),
                &AnswererStep::Installed,
                None,
            )
            .is_none(),
            "the native advisory goes quiet once the answerer service is \
             manager-held"
        );
    }

    /// `answerer_source` resolves `minzoned` — beside this `min`, then
    /// on `PATH` — and never names `minvmd`, nor a bare name: with no
    /// `minzoned` anywhere it finds nothing, however many `minvmd`s
    /// sit where it looks.
    #[test]
    fn answerer_source_never_names_an_absent_minvmd() {
        let beside = tempfile::TempDir::new().expect("a dir beside min");
        let on_path = tempfile::TempDir::new().expect("a dir on PATH");
        for dir in [&beside, &on_path] {
            std::fs::write(dir.path().join("minvmd"), b"").expect("a minvmd sits here");
        }
        let path = std::env::join_paths([on_path.path()]).expect("a PATH");
        assert_eq!(
            answerer_source_in(Some(beside.path()), Some(&path)),
            None,
            "no minzoned anywhere: nothing is named"
        );
        std::fs::write(on_path.path().join(ANSWERER_PROGRAM_NAME), b"").expect("on PATH");
        let found =
            answerer_source_in(Some(beside.path()), Some(&path)).expect("the one on PATH is found");
        assert!(
            found.ends_with("/minzoned") && found.starts_with('/'),
            "{found}"
        );
        std::fs::write(beside.path().join(ANSWERER_PROGRAM_NAME), b"").expect("beside min");
        assert_eq!(
            answerer_source_in(Some(beside.path()), Some(&path)),
            Some(
                beside
                    .path()
                    .join(ANSWERER_PROGRAM_NAME)
                    .display()
                    .to_string()
            ),
            "the one beside min wins"
        );
    }
}
