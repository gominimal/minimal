//! `min host list|show` and `min provider list [--all]`: the local hosts
//! and the well-known local providers they belong to.
//!
//! For `local` and `local-minvmd`, `min` is the provider. It walks the
//! per-host state directories under `<minimal_dir>/providers/` and reads
//! each host over that host's own socket. No daemon serves these lists.
//!
//! BCLI-046: the providers are `local`, `local-minvmd` and `local-box`, and
//! a host is named after its daemon instance: `local0..N` for the native
//! daemons (state directory `local-minimald<N>`), `local-minvmd0..N` for the
//! VM host daemons.
//!
//! BCLI-049: `min host stop <host>` stops each running box on the host,
//! then its daemon, and its VM on a VM host.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Serialize;

use super::output::{self, ObjectType, OutputMode, Rendered};
use crate::client;
use crate::{GlobalArgs, HostShowArgs, HostStopArgs, Provider, ProviderListArgs};

/// The hint `--provider local-minimald` prints on stderr after the command
/// ends (BCLI-046).
pub const PROVIDER_ALIAS_HINT: &str = "local-minimald is now called local.";

/// The environment variable a box sets for the processes in it. Its presence
/// is what makes the `local-box` provider present.
const IN_BOX_ENV: &str = "MINIMAL_SESSION_NAME";

/// Read `--provider local-minimald` as `local` (BCLI-046). Returns the hint
/// to print once the command ends, when the old name was used.
pub fn read_provider_alias(global: &mut GlobalArgs) -> Option<&'static str> {
    if global.provider == Some(Provider::LocalMinimald) {
        tracing::debug!("--provider local-minimald read as local");
        global.provider = Some(Provider::Local);
        Some(PROVIDER_ALIAS_HINT)
    } else {
        None
    }
}

/// The alias hint of a run that failed. The error path prints it, so a
/// machine output mode carries it in the error object's `hint` field and
/// prints no separate line (BCLI-042).
static FAILED_RUN_ALIAS_HINT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Hand the alias hint to the error path of a run that failed.
pub fn defer_alias_hint_to_failure(hint: &'static str) {
    // A second set in one process keeps the first hint, which is the same.
    let _ = FAILED_RUN_ALIAS_HINT.set(hint);
}

/// The alias hint the error path prints for a failed run, if any.
#[must_use]
pub fn failed_run_alias_hint() -> Option<&'static str> {
    FAILED_RUN_ALIAS_HINT.get().copied()
}

/// A well-known local provider: one per local deployment style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LocalProvider {
    /// The native daemons on this machine.
    Local,
    /// The VM host daemons on this machine.
    LocalMinvmd,
    /// The parent daemon of the box `min` runs in.
    LocalBox,
}

impl LocalProvider {
    /// Every well-known local provider.
    pub const ALL: [Self; 3] = [Self::Local, Self::LocalMinvmd, Self::LocalBox];

    /// The provider's name, as `--provider` and the listings spell it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::LocalMinvmd => "local-minvmd",
            Self::LocalBox => "local-box",
        }
    }
}

/// One local host: a daemon instance with a state directory on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHost {
    /// The host's name: `local<N>`, `local-minvmd<N>`, or
    /// `<vm>.local-minvmd<N>` for a named VM.
    pub name: String,
    /// The provider the host belongs to.
    pub provider: LocalProvider,
    /// The daemon instance number. A named VM has the number of the VM host
    /// directory it nests in.
    pub instance: u32,
    /// The VM name, for a named VM at `local-minvmd<N>/<vm>`. `None` for
    /// the host that the instance directory itself holds.
    pub vm: Option<String>,
    /// The host's state directory.
    pub dir: PathBuf,
    /// Why the named VMs in this VM host directory were not read, when its
    /// directory could not be listed. `None` when they were read, or when
    /// the host holds no named VMs.
    pub unread_vms: Option<String>,
}

impl LocalHost {
    /// The host-side socket `min` connects to.
    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.dir.join(paths::SSH_SOCK_FILE)
    }
}

/// The host for a `providers/<dir>` name, or `None` when the name is not a
/// local daemon instance.
#[must_use]
pub fn host_for_dir_name(dir_name: &str) -> Option<(LocalProvider, u32, String)> {
    let parse = |rest: &str| -> Option<u32> {
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // A number with a leading zero is no instance: `local-minimald01`
        // would name the same host as `local-minimald1`.
        let n: u32 = rest.parse().ok()?;
        (n.to_string() == rest).then_some(n)
    };
    if let Some(rest) = dir_name.strip_prefix("local-minimald") {
        let n = parse(rest)?;
        return Some((LocalProvider::Local, n, format!("local{n}")));
    }
    if let Some(rest) = dir_name.strip_prefix("local-minvmd") {
        let n = parse(rest)?;
        return Some((LocalProvider::LocalMinvmd, n, format!("local-minvmd{n}")));
    }
    None
}

/// The `providers` directory under the state directory `min` resolves.
fn providers_dir(minimal_dir: Option<&Path>) -> std::io::Result<PathBuf> {
    let base = match minimal_dir {
        Some(dir) => std::path::absolute(dir)?,
        None => paths::minimal_state_dir()
            .as_utf8_path()
            .as_std_path()
            .to_path_buf(),
    };
    Ok(base.join("providers"))
}

/// Every local host with a state directory on this machine, in provider
/// order, then instance order.
///
/// # Errors
///
/// The state directory cannot be read.
pub fn local_hosts(minimal_dir: Option<&Path>) -> std::io::Result<Vec<LocalHost>> {
    let dir = providers_dir(minimal_dir)?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut hosts = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some((provider, instance, name)) = host_for_dir_name(&file_name) {
            let mut unread_vms = None;
            if provider == LocalProvider::LocalMinvmd {
                // One unreadable VM host directory hides its named VMs
                // only, never the other hosts. The host keeps the reason,
                // so `min host list` and `min host show` can say so.
                match named_vms(&entry.path(), instance) {
                    Ok(vms) => hosts.extend(vms),
                    Err(e) => {
                        tracing::debug!(
                            dir = %entry.path().display(),
                            "named VMs not read: {e:#}"
                        );
                        unread_vms = Some(e.to_string());
                    }
                }
            }
            hosts.push(LocalHost {
                name,
                provider,
                instance,
                vm: None,
                dir: entry.path(),
                unread_vms,
            });
        }
    }
    hosts.sort_by(|a, b| (a.provider, a.instance, &a.vm).cmp(&(b.provider, b.instance, &b.vm)));
    Ok(hosts)
}

/// The named VMs in one VM host directory: each subdirectory whose name is
/// a valid VM name. Each named VM is its own minvmd, with its own socket.
/// The default VM is the host directory itself, so a `default` subdirectory
/// is no VM.
fn named_vms(host_dir: &Path, instance: u32) -> std::io::Result<Vec<LocalHost>> {
    let mut vms = Vec::new();
    for entry in std::fs::read_dir(host_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(vm) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if vm == paths::DEFAULT_VM_NAME || paths::validate_vm_name(&vm).is_err() {
            continue;
        }
        // The ssh host alias, `<vm>.local-minvmd<N>`: the name `min box
        // list` prints for the same host, and one no other host can have.
        let Some(name) = paths::ssh_host_alias(&entry.path()) else {
            continue;
        };
        vms.push(LocalHost {
            name,
            provider: LocalProvider::LocalMinvmd,
            instance,
            vm: Some(vm),
            dir: entry.path(),
            unread_vms: None,
        });
    }
    Ok(vms)
}

/// One line for each VM host whose named VMs were not read: the host, the
/// directory that could not be read, and why. `min host list` prints them
/// after its table, and `min host show` after its refusal.
#[must_use]
pub fn unread_vm_notes(hosts: &[LocalHost]) -> Vec<String> {
    hosts
        .iter()
        .filter_map(|h| {
            let reason = h.unread_vms.as_ref()?;
            Some(format!(
                "The named VMs of {} are not listed, because {} cannot be read: {reason}.",
                h.name,
                h.dir.display()
            ))
        })
        .collect()
}

/// Whether a host's daemon answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    /// The daemon answered on its socket.
    Running,
    /// Nothing answers on the socket.
    Stopped,
    /// Something is at the socket, but it did not answer.
    Unreachable,
}

impl HostState {
    fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Unreachable => "not responding",
        }
    }
}

/// Read a host's state and, when it runs, its daemon version. One connect
/// attempt and one `GetVersion`, both under [`client::PROBE_TIMEOUT`].
pub async fn probe_host(host: &LocalHost) -> (HostState, Option<String>) {
    let sock = host.socket();
    let probe = async {
        let mut client = match client::Client::probe(&sock).await {
            Ok(client) => client,
            Err(client::ProbeRefusal::NotRunning) => return (HostState::Stopped, None),
            Err(client::ProbeRefusal::Unreachable(e)) => {
                tracing::debug!(host = %host.name, "host probe failed: {e:#}");
                return (HostState::Unreachable, None);
            }
        };
        match client.oneshot_rpc::<minimald_rpc::GetVersion>(()).await {
            Ok(resp) => (HostState::Running, Some(resp.long_version)),
            Err(e) => {
                tracing::debug!(host = %host.name, "GetVersion failed: {e:#}");
                (HostState::Unreachable, None)
            }
        }
    };
    if let Ok(answer) = tokio::time::timeout(client::PROBE_TIMEOUT, probe).await {
        answer
    } else {
        tracing::debug!(host = %host.name, "host probe timed out");
        (HostState::Unreachable, None)
    }
}

/// One row of `min host list`.
#[derive(Debug, Serialize)]
pub struct HostRow {
    pub name: String,
    pub provider: &'static str,
    pub state: HostState,
}

impl Rendered for HostRow {
    const TYPE: ObjectType = ObjectType::Host;
    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{:<16} {:<14} {}",
            self.name,
            self.provider,
            self.state.label()
        )
    }
}

/// `min host show <host>`.
#[derive(Debug, Serialize)]
pub struct HostDetail {
    pub name: String,
    pub provider: &'static str,
    pub state: HostState,
    pub socket: PathBuf,
    pub daemon_version: Option<String>,
}

impl Rendered for HostDetail {
    const TYPE: ObjectType = ObjectType::Host;
    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        writeln!(out, "Host:            {}", self.name)?;
        writeln!(out, "Provider:        {}", self.provider)?;
        writeln!(out, "State:           {}", self.state.label())?;
        writeln!(out, "Socket:          {}", self.socket.display())?;
        match (&self.daemon_version, self.state) {
            (Some(version), _) => writeln!(out, "Daemon version:  {version}"),
            (None, HostState::Stopped) => writeln!(
                out,
                "Daemon version:  unknown, because the daemon is not running"
            ),
            (None, _) => writeln!(
                out,
                "Daemon version:  unknown, because the daemon did not answer"
            ),
        }
    }
}

/// One row of `min provider list`.
#[derive(Debug, Serialize)]
pub struct ProviderRow {
    pub name: &'static str,
    pub hosts: Vec<String>,
}

impl Rendered for ProviderRow {
    const TYPE: ObjectType = ObjectType::Provider;
    fn text(&self, out: &mut dyn Write) -> std::io::Result<()> {
        let hosts = if self.hosts.is_empty() {
            "-".to_owned()
        } else {
            self.hosts.join(", ")
        };
        writeln!(out, "{:<14} {hosts}", self.name)
    }
}

/// `min host list`: each local host with its name, provider and state
/// (BCLI-047).
///
/// # Errors
///
/// The state directory cannot be read, or `out` fails.
pub async fn cmd_host_list(global: &GlobalArgs, out: &mut dyn Write) -> anyhow::Result<()> {
    let hosts = local_hosts(global.minimal_dir.as_deref())?;
    if hosts.is_empty() {
        writeln!(out, "No local host on this machine yet.")?;
        return Ok(());
    }
    // Probe every host at once, so N unresponsive hosts cost one
    // `PROBE_TIMEOUT`, not N of them.
    let states = futures::future::join_all(hosts.iter().map(probe_host)).await;
    let rows: Vec<HostRow> = hosts
        .iter()
        .zip(states)
        .map(|(host, (state, _))| HostRow {
            name: host.name.clone(),
            provider: host.provider.name(),
            state,
        })
        .collect();
    writeln!(out, "{:<16} {:<14} STATE", "HOST", "PROVIDER")?;
    output::write_objects(out, OutputMode::Text, &rows)?;
    for note in unread_vm_notes(&hosts) {
        writeln!(out, "{note}")?;
    }
    Ok(())
}

/// `min host show <host>`: the host's state, its host-side socket and its
/// daemon version (BCLI-048).
///
/// # Errors
///
/// No local host has that name, the state directory cannot be read, or
/// `out` fails.
pub async fn cmd_host_show(
    global: &GlobalArgs,
    args: &HostShowArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let hosts = local_hosts(global.minimal_dir.as_deref())?;
    let host = named_host(&hosts, &args.host)?;
    let (state, daemon_version) = probe_host(host).await;
    let detail = HostDetail {
        name: host.name.clone(),
        provider: host.provider.name(),
        state,
        socket: host.socket(),
        daemon_version,
    };
    output::write_object(out, OutputMode::Text, &detail)?;
    Ok(())
}

/// The local host named `name`, or the refusal that names `min host list`.
fn named_host<'a>(hosts: &'a [LocalHost], name: &str) -> anyhow::Result<&'a LocalHost> {
    if let Some(host) = hosts.iter().find(|h| h.name == name) {
        return Ok(host);
    }
    let mut msg =
        format!("no local host is named '{name}'. Run `min host list` to see the local hosts.");
    for note in unread_vm_notes(hosts) {
        msg.push('\n');
        msg.push_str(&note);
    }
    anyhow::bail!(msg)
}

/// The line `min host stop` prints once the boxes and the daemon of `host`
/// are stopped. `vm` is true for a VM host, whose VM stops with its daemon.
#[must_use]
pub fn host_stop_summary(stopped_boxes: usize, host: &str, vm: bool) -> String {
    let boxes = if stopped_boxes == 1 { "box" } else { "boxes" };
    if vm {
        format!("Stopped {stopped_boxes} {boxes}, the daemon and its VM on {host}.")
    } else {
        format!("Stopped {stopped_boxes} {boxes} and the daemon on {host}.")
    }
}

/// `min host stop <host> [--force]` (BCLI-049): stops each running box on
/// the host as `min box stop` does, then the daemon, and its VM on a VM
/// host. `--force` force-stops each box, and stops the daemon without a
/// wait for its clean shutdown. A host whose daemon is down is the goal
/// state: the command says so and exits 0.
///
/// # Errors
///
/// No local host has that name, the daemon does not answer, a box or the
/// daemon does not stop, or `out` fails.
pub async fn cmd_host_stop(
    global: &GlobalArgs,
    args: &HostStopArgs,
    mut out: &mut dyn Write,
) -> anyhow::Result<()> {
    let hosts = local_hosts(global.minimal_dir.as_deref())?;
    let host = named_host(&hosts, &args.host)?;
    let vm_dir = (host.provider == LocalProvider::LocalMinvmd).then(|| host.dir.clone());
    let (state, _) = probe_host(host).await;
    tracing::debug!(host = %host.name, ?state, force = args.force, "host stop");
    if state == HostState::Stopped {
        writeln!(out, "{} is not running.", host.name)?;
        return Ok(());
    }
    // Ungated: as for `min stop`, stopping a daemon of another version is
    // the remedy the version check itself names.
    let mut client = match client::Client::connect(&host.socket()).await {
        Ok(client) => client,
        Err(e) => return host_unreachable(host, vm_dir, args.force, e, out).await,
    };
    let listed = super::list_box_records(&mut client, None)
        .await
        .with_context(|| format!("the boxes on {} were not listed", host.name))?;
    let mut stopped = 0;
    for entry in listed.iter().filter(|e| e.state == "running") {
        let target = entry
            .name
            .clone()
            .unwrap_or_else(|| entry.box_id.to_string());
        super::stop_listed_box(&mut client, &mut out, entry.box_id, &target, args.force)
            .await
            .with_context(|| {
                format!(
                    "the daemon on {} was not stopped, because {target} did not stop",
                    host.name
                )
            })?;
        stopped += 1;
    }
    let vm = vm_dir.is_some();
    super::shut_down_host_daemon(client, &host.name, vm_dir, args.force).await?;
    writeln!(out, "{}", host_stop_summary(stopped, &host.name, vm))?;
    Ok(())
}

/// `min host stop` for a host whose daemon does not answer. With `--force`
/// on a VM host, the VM is stopped from this machine. Otherwise the command
/// fails, and on a VM host it names `--force`.
async fn host_unreachable(
    host: &LocalHost,
    vm_dir: Option<PathBuf>,
    force: bool,
    cause: anyhow::Error,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let force_command = format!("min host stop {} --force", host.name);
    match vm_dir {
        Some(dir) if force => {
            tracing::debug!(host = %host.name, "daemon unreachable, stopping the VM from this machine: {cause:#}");
            let outcome = super::stop_vm_from_host_at(dir, true, force_command).await?;
            use minvmd::cmd::stop::HostStop;
            match outcome {
                HostStop::NothingSignalled => writeln!(out, "{} is not running.", host.name)?,
                HostStop::GuestAcknowledged => {
                    writeln!(out, "Stopped the daemon and its VM on {}.", host.name)?;
                }
                HostStop::GuestUnacknowledged => writeln!(
                    out,
                    "The daemon on {} did not answer, so its VM was stopped from this machine. \
                     Its boxes ended without their stop steps.",
                    host.name
                )?,
            }
            Ok(())
        }
        Some(_) => Err(cause.context(format!(
            "the daemon on {} does not answer. Run `{force_command}` to stop its VM from this machine.",
            host.name
        ))),
        None => Err(cause.context(format!("the daemon on {} does not answer.", host.name))),
    }
}

/// `min provider list [--all]` (BCLI-052). Without `--all`, the provider
/// this command selects. With it, every well-known local provider present
/// on this machine: `local` and `local-minvmd` when they have a host, and
/// `local-box` when `min` runs in a box.
///
/// # Errors
///
/// The state directory cannot be read, or `out` fails.
pub fn cmd_provider_list(
    global: &GlobalArgs,
    args: &ProviderListArgs,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let in_box = std::env::var_os(IN_BOX_ENV).is_some();
    provider_list(global, args.all, in_box, out)
}

/// [`cmd_provider_list`] with the in-box check given, so a test can set it.
///
/// # Errors
///
/// As [`cmd_provider_list`].
pub fn provider_list(
    global: &GlobalArgs,
    all: bool,
    in_box: bool,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    let hosts = local_hosts(global.minimal_dir.as_deref())?;
    let hosts_of = |provider: LocalProvider| -> Vec<String> {
        hosts
            .iter()
            .filter(|h| h.provider == provider)
            .map(|h| h.name.clone())
            .collect()
    };
    let rows: Vec<ProviderRow> = if all {
        LocalProvider::ALL
            .into_iter()
            .filter(|&p| match p {
                LocalProvider::LocalBox => in_box,
                _ => hosts.iter().any(|h| h.provider == p),
            })
            .map(|p| ProviderRow {
                name: p.name(),
                hosts: hosts_of(p),
            })
            .collect()
    } else {
        let selected = match client::client_host_kind(global.use_minvmd()) {
            paths::HostKind::Minvmd => LocalProvider::LocalMinvmd,
            paths::HostKind::Minimald => LocalProvider::Local,
        };
        vec![ProviderRow {
            name: selected.name(),
            hosts: hosts_of(selected),
        }]
    };
    if rows.is_empty() {
        writeln!(out, "No local provider on this machine yet.")?;
        return Ok(());
    }
    writeln!(out, "{:<14} HOSTS", "PROVIDER")?;
    output::write_objects(out, OutputMode::Text, &rows)?;
    Ok(())
}
