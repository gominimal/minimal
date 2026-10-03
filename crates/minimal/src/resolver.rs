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

use serde::Serialize;
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
        mode: metadata.permissions().mode(),
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
/// label, or the print could not be read. One read-only call of the
/// system's own service manager; nothing it does can prompt.
async fn launchctl_print_program() -> Option<String> {
    let output = tokio::process::Command::new("launchctl")
        .arg("print")
        .arg(format!("system/{RANGE_UNIT_LABEL}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
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
    // stub for host lookups to bypass, so nothing can block the command,
    // and the one read this makes carries no deadline to bound.
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
/// a first run has nothing to boot out — then `bootstrap` into the system
/// domain, which runs the program now (the range is present on this boot)
/// and registers [`RANGE_UNIT_PLIST`]'s `RunAtLoad` to re-apply it at every
/// boot after. A re-run replaces the unit and re-runs the program rather
/// than dying on a label collision.
///
/// The whole payload rides inside the one pair of single quotes that
/// `sh -c` takes it under, so neither body the heredocs write may carry an
/// apostrophe of its own: one inside a body closes the quote, the paste
/// hangs at a continuation prompt, and `sh -n` rejects the rendered line —
/// which is why the suite parses both halves of the command and asserts
/// the bodies carry none (see `advisory_command_reserves_the_range_on_macos`).
#[cfg(any(test, target_os = "macos"))]
pub(crate) fn macos_command(port: u16) -> String {
    let program = range_program();
    format!(
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
         ; launchctl bootstrap system {RANGE_PLIST_PATH}'"
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
/// on this host's own loopback, the range step this host's detection read
/// beside the hook, and whether anything blocks the command (NET-122,
/// NET-123). Pure.
///
/// `None` — nothing to say — when the hook already routes the zone to this
/// answerer, the daemon did not publish at the interim, the range read
/// present on this host's own loopback, the range step holds custody,
/// *and* nothing blocks the command. Otherwise the advisory says what is
/// missing and names the exact command. The interim re-surfaces the advisory
/// even when the hook routes (NET-123: "re-surface the advisory of
/// NET-122"): a session on the interim is a fact the user has no other way
/// to see. The interim fact names the step that ends it — installing the
/// range on the host — and whose job that step is is the platform's: on
/// macOS the same advisory command does it ([`COMMAND_RESERVES_THE_RANGE`]'s
/// platform — [`macos_command`]'s one `sudo sh -c` installs the range unit
/// beside the resolver file it writes), so the fact says the command below
/// installs the range and ends the interim; on Linux the whole `127/8` is
/// local to `lo`, no install is needed, and the fact names the range as
/// what is missing and stops there. Either way the command the advisory
/// names is the whole of the host's missing configuration: the lead-in says
/// what it does — on macOS "configure the host's resolver and reserve the
/// local range", on Linux "configure the host's resolver for the zone" —
/// and nothing the note asks for stands beside that command unprovided.
/// String assembly only.
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
    // host whose missing configuration has nothing left to name.
    if hook.routes(port)
        && !interim
        && !matches!(range_present, Some(false))
        && blocker.is_none()
        && range_step.custody_holds()
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
            // The lead-in says what the command does on this platform:
            // reserves the local range beside the resolver file where the
            // OS needs a step for it, the resolver alone where it does not.
            let lead_in = if range_step.state == RangeStepState::NotNeeded {
                "Configure the host's resolver for the zone with:"
            } else {
                "Configure the host's resolver and reserve the local range with:"
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
/// Printed once per session start, to stderr; never prompts.
pub(crate) fn session_advisory_at(
    detection: &(Hook, Option<String>, RangeStep),
    zone_answerer_port: Option<u16>,
    interim_loopback: bool,
    range_present: Option<bool>,
) -> Option<String> {
    let port = zone_answerer_port?;
    let (hook, blocker, range_step) = detection;
    advisory_at(
        hook,
        port,
        interim_loopback,
        range_present,
        range_step,
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
                None
            )
            .is_none(),
            "a configured host must not be re-advised"
        );

        // A hook routing a *stale* port is advised: the command points the
        // resolver at this daemon's answerer, not the old one's.
        let stale = Hook::configured("test", Some(port - 1), "routes the zone elsewhere");
        let advisory = advisory_at(&stale, port, false, None, &range_step_on_this_os(), None)
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
        let advisory = session_advisory_at(&detection, Some(port), false, None);
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
        let advisory = session_advisory_at(&detection, Some(port), false, Some(true));
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

    // NET-123's privileged step, on the one `sudo sh -c` NET-122 already
    // renders (design §7.1): the command's own bytes do the whole install —
    // the program and the plist are written from what the command carries,
    // not staged, not copied, not read from anywhere user-writable — and
    // the boot step loads last, so a re-run replaces the unit rather than
    // dying on its label. Pinned here on the text the render builds from
    // the same templates the e2e runs; the macOS lane's
    // `local_range_reserved_by_privileged_step` proves this command against
    // a real launchd.
    #[test]
    fn advisory_command_reserves_the_range_on_macos() {
        let command = macos_command(15353);
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
        // The steps outside the two bodies substitute nothing — no `$`, no
        // backtick — and the bodies themselves are quoted-delimiter
        // (asserted above), so a backtick inside one (the program's comments
        // carry markdown) writes rather than runs.
        let steps_only = command.replace(&program, "").replace(RANGE_UNIT_PLIST, "");
        assert!(
            !steps_only.contains('$') && !steps_only.contains('`'),
            "the steps substitute nothing — the bytes they write are the bytes they \
             carry: {steps_only}"
        );
        assert!(
            !steps_only.contains("cp ") && !steps_only.contains("install "),
            "nothing is copied in from anywhere, user-writable or not: {steps_only}"
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
        // the label collision — then the new one is bootstrapped into the
        // system domain, which runs the program now and registers
        // RunAtLoad to re-apply the range at every boot after.
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
        let command = macos_command(15353);
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
        let advisory = advisory_at(&configured, port, false, Some(true), &failed, None)
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
        let interim = advisory_at(&configured, port, true, None, &failed, None)
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

    /// The Linux command is byte-identical to the one NET-122 shipped: the
    /// range step this task adds to the macOS arm must not touch it. Linux
    /// takes no range step — `lo` carries the whole `127/8` — and the
    /// dedicated link keeps its address, so the advisory over the
    /// not-needed step says nothing of the range's unit, its paths or its
    /// install.
    #[test]
    fn linux_advisory_command_is_unchanged() {
        let port = 15353;
        assert_eq!(
            linux_command(port),
            "sudo sh -c \"[ -e /sys/class/net/minzone0 ] \
             || ip link add minzone0 type dummy \
             && ip link set minzone0 up \
             && ip addr replace 100.127.255.254/32 dev minzone0 \
             && resolvectl default-route minzone0 false \
             && resolvectl dns minzone0 127.0.0.1:15353 \
             && resolvectl domain minzone0 '~min.internal'\""
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
    /// a loopback); the macOS lane's e2e case proves the same fact against
    /// a real lo0.
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
        let advisory = advisory_at(
            &hook,
            15353,
            false,
            None,
            &range_step_on_this_os(),
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
        let advisory = advisory_at(&hook, 15353, false, None, &range_step_on_this_os(), None)
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
}
