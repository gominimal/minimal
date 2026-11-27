//! CLI subcommand implementations for `minvmd`.

pub mod answerer;
pub mod boot;
pub mod config;
pub mod run;
pub mod status;
pub mod stop;
pub mod vmm_child;

/// vsock port used by the VMM child to signal the parent that the guest is up.
///
/// The guest's init writes `READY\n` to this vsock port; libkrun forwards the
/// connection to the host UNIX socket registered by the parent before spawning
/// the VMM child. The parent reads `READY` to confirm boot (R2.4).
///
/// Must match the guest rootfs's READY/agent port. The canonical value is
/// `7350` — both the guest rootfs manifest (`etc/microvm/manifest`:
/// `vsock_port_ready=7350`) and the reference impl (min-ctl: cold boot to a TCP
/// connection on `127.0.0.1:7350`) use it. The host previously used `9799`,
/// which no guest emits on, so the READY marker never arrived.
pub const VSOCK_MARKER_PORT: u32 = 7350;

/// Environment variable that carries the host-side UNIX socket path for the
/// READY marker from the parent to the VMM child.
pub const MARKER_SOCK_ENV: &str = "MINVMD_MARKER_SOCK";

/// Environment variable selecting an own-IP VM. When set to a truthy value
/// (`1`/`true`/`yes`/`on`, case-insensitive), the supervisor spawns the host gvproxy switch and
/// the VMM child registers the per-PTask shuttle vsock bridge + sets the VM's
/// network mode to `OwnIp`. Read by both the parent supervisor (to decide
/// whether to spawn gvproxy) and the VMM child (to configure the VM), so the two
/// processes stay consistent. Unset/false ⇒ a `HostNet` VM with no host gvproxy.
pub const OWN_IP_ENV: &str = "MINVMD_VM_OWN_IP";

/// Whether [`OWN_IP_ENV`] requests an own-IP VM.
#[must_use]
pub fn own_ip_requested() -> bool {
    std::env::var(OWN_IP_ENV).is_ok_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

/// The one-per-stop info line (NET-055): it names the VM being stopped and
/// its state directory, so a stop in the log answers "which VM?" at a glance.
///
/// Every stop funnels here, but only the process that observes the VM die
/// logs it: the `run` supervisor and a foreground `boot`, when the VMM child
/// exits — which is where a `min stop` (a Shutdown RPC the guest answers by
/// powering off) surfaces, since only the supervisor sees that stop happen.
/// The `minvmd stop` CLI does not: whenever it stops something, the
/// supervisor is alive and watching (it holds the alive lock `stop`
/// requires), so a CLI line too would log one stop twice — and a no-op stop
/// would log a stop that never happened. One definition of the line, so the
/// fields cannot drift between the witnesses that log it.
pub fn log_stopping_vm(state_dir: &std::path::Path) {
    tracing::info!(
        vm = %crate::state::vm_name(),
        state_dir = %state_dir.display(),
        "stopping VM"
    );
}

/// Environment variable overriding the [`DEFAULT_READY_TIMEOUT_SECS`] wait for
/// the guest `READY` marker.
pub const READY_TIMEOUT_ENV: &str = "MINVMD_READY_TIMEOUT_SECS";

/// Default seconds `boot`/`run` wait for the guest to write its `READY` marker
/// (R2.4). A cold boot of a multi-GiB VM on the generic guest kernel — early
/// kernel bring-up, a large driver-probe phase, then the in-VM minimald init
/// (mount, pivot_root, networking) — was observed at ~22–28s and is slower
/// under host load, so the default carries generous margin. Override with
/// [`READY_TIMEOUT_ENV`] for slower hosts, or to fail faster on fast ones.
pub const DEFAULT_READY_TIMEOUT_SECS: u64 = 60;

/// The READY-marker wait, overridable via [`READY_TIMEOUT_ENV`]. A non-numeric,
/// empty, or zero value falls back to [`DEFAULT_READY_TIMEOUT_SECS`] — a zero
/// wait would make `recv_timeout` return instantly and every boot "time out".
#[must_use]
pub fn ready_timeout() -> std::time::Duration {
    let secs = std::env::var(READY_TIMEOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .unwrap_or(DEFAULT_READY_TIMEOUT_SECS);
    std::time::Duration::from_secs(secs)
}

/// Environment variable overriding the [`DEFAULT_VM_RAM_MIB`] guest RAM size.
pub const VM_RAM_MIB_ENV: &str = "MINVMD_VM_RAM_MIB";

/// Environment variable overriding the [`DEFAULT_VM_VCPUS`] guest vcpu count.
pub const VM_VCPUS_ENV: &str = "MINVMD_VM_VCPUS";

/// Default guest vcpu count. 2 is the v0.1 baseline; stay below the guest
/// kernel's `CONFIG_NR_CPUS`. Overridable via [`VM_VCPUS_ENV`] or persisted
/// resource config (see [`effective_vcpus`]).
pub const DEFAULT_VM_VCPUS: u8 = 2;

/// Logical cores backed off from the vcpu ceiling for the host side: the VMM
/// and its worker threads, plus whatever else the machine is running.
pub const VCPU_HOST_RESERVE: u32 = 2;

/// Upper bound on guest vcpus for a host with `logical_cores` logical CPUs:
/// the core count minus [`VCPU_HOST_RESERVE`], floored at [`DEFAULT_VM_VCPUS`]
/// so small hosts keep the baseline, saturated to the `u8` vcpu type. The
/// ceiling is host-derived rather than a fixed cap so a many-core host can run
/// a wide VM; the generic guest kernel's `CONFIG_NR_CPUS` (typically ≥ 64) is
/// assumed not to be the binding constraint.
#[must_use]
pub fn max_vm_vcpus(logical_cores: u32) -> u8 {
    u8::try_from(logical_cores.saturating_sub(VCPU_HOST_RESERVE))
        .unwrap_or(u8::MAX)
        .max(DEFAULT_VM_VCPUS)
}

/// The host's logical core count (1 if probing fails) — the input to
/// [`max_vm_vcpus`].
pub(crate) fn host_logical_cores() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Default guest RAM in MiB. 512 MiB is the floor to reach userspace; the extra
/// headroom feeds the in-VM session build, whose package cache lives on a tmpfs
/// (`/run/minimal/cache`) sized from RAM (1024 MiB overflowed `StorageFull`
/// unpacking large packages) — a stop-gap until the seeded cache disk lands.
///
/// The default is **arch-conditional** because libkrun boots a same-arch guest,
/// so the minvmd binary's `target_arch` is the guest's arch. On x86_64 a guest
/// sized at 4096 MiB straddles the 32-bit MMIO/PCI hole (~3–4 GiB), which
/// mis-places the initramfs so the kernel finds no `/init` and panics in
/// `prepare_namespace` ("VFS: cannot open root device"). aarch64 has no such low
/// hole. So x86_64 defaults to a hole-safe 2048 MiB (CI-proven) and aarch64 to
/// 4096; either can be raised via [`VM_RAM_MIB_ENV`] (x86_64 to a hole-safe size,
/// i.e. ≤3072 or ≥6144).
#[cfg(target_arch = "x86_64")]
pub const DEFAULT_VM_RAM_MIB: u32 = 2048;
/// See the x86_64 variant for the full rationale (the MMIO-hole caveat).
#[cfg(not(target_arch = "x86_64"))]
pub const DEFAULT_VM_RAM_MIB: u32 = 4096;

/// Parse a positive integer from environment variable `var`; a missing,
/// non-numeric, empty, or non-positive value is treated as unset. Shared by the
/// `MINVMD_VM_RAM_MIB` / `MINVMD_VM_VCPUS` overrides.
fn positive_env<T>(var: &str) -> Option<T>
where
    T: std::str::FromStr + PartialOrd + Default,
{
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse::<T>().ok())
        .filter(|value| *value > T::default())
}

/// The `MINVMD_VM_RAM_MIB` override as a positive value, if set and valid.
pub(crate) fn env_ram_mib() -> Option<u32> {
    positive_env(VM_RAM_MIB_ENV)
}

/// The `MINVMD_VM_VCPUS` override as a positive value, if set and valid.
pub(crate) fn env_vcpus() -> Option<u8> {
    positive_env(VM_VCPUS_ENV)
}

/// The persisted resource config from the host dir. A missing file yields
/// the all-`None` default; a malformed file is logged — so a boot that silently
/// falls back to built-in defaults is at least diagnosable — and also treated as
/// the default, so an unreadable file never blocks boot (R9.7).
pub(crate) fn persisted_resource_config() -> crate::config::ResourceConfig {
    match crate::config::ResourceConfig::read(&crate::state::host_dir()) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read persisted resource config; using defaults");
            crate::config::ResourceConfig::default()
        }
    }
}

/// Clamp a resolved vcpu count to this host's [`max_vm_vcpus`]. Warns when it
/// clamps (e.g. an over-large [`VM_VCPUS_ENV`] override that skips `config set`
/// validation) so a boot with fewer vcpus than requested is not silent.
fn clamp_vcpus(vcpus: u8) -> u8 {
    let max = max_vm_vcpus(host_logical_cores());
    if vcpus > max {
        tracing::warn!(
            requested = vcpus,
            max,
            "requested vcpu count exceeds the host-derived vcpu ceiling; clamping"
        );
        max
    } else {
        vcpus
    }
}

/// The effective guest RAM in MiB, resolved as
/// `env override ?? persisted config ?? default` (R9.7). The
/// [`VM_RAM_MIB_ENV`] override still wins so power users keep a per-boot escape
/// hatch; `minvmd config set --ram-mib` supplies the persisted layer beneath it.
///
/// Note: the RAM stop-gap is *not* reduced when the cache moves to the writable
/// volume. A reduced baseline is only safe once a failed volume mount is fatal
/// (no silent tmpfs fallback) and the floor is measured against real in-VM build
/// memory pressure; reducing it here would leave a mount-failed VM at half RAM
/// with the cache still on the tmpfs. Out of scope for this feature — deferred to
/// a separate memory-pressure spec.
#[must_use]
pub fn effective_ram_mib() -> u32 {
    env_ram_mib()
        .or_else(|| persisted_resource_config().ram_mib)
        .unwrap_or(DEFAULT_VM_RAM_MIB)
}

/// The effective guest vcpu count, resolved as
/// `env override ?? persisted config ?? default` (R9.7) and clamped to this
/// host's [`max_vm_vcpus`] so an over-large env/config value cannot brick the
/// boot.
#[must_use]
pub fn effective_vcpus() -> u8 {
    clamp_vcpus(
        env_vcpus()
            .or_else(|| persisted_resource_config().vcpus)
            .unwrap_or(DEFAULT_VM_VCPUS),
    )
}

/// Resolve `(vcpus, ram_mib)` from a **single** read of the persisted config, so
/// the pair cannot tear when `config.toml` changes between two separate
/// `effective_*` calls (e.g. the two `booted_*` fields recorded at the Running
/// transition). Per-field env overrides still take precedence; vcpus is clamped
/// to this host's [`max_vm_vcpus`].
#[must_use]
pub fn effective_resources() -> (u8, u32) {
    let env_v = env_vcpus();
    let env_r = env_ram_mib();
    let cfg = persisted_resource_config();
    (
        clamp_vcpus(env_v.or(cfg.vcpus).unwrap_or(DEFAULT_VM_VCPUS)),
        env_r.or(cfg.ram_mib).unwrap_or(DEFAULT_VM_RAM_MIB),
    )
}

/// Environment variable overriding the per-box cap on Box Egress Proxy
/// connections (see [`effective_bep_per_box_cap`]).
pub const BEP_PER_BOX_CAP_ENV: &str = "MINVMD_BEP_PER_BOX_CAP";

/// The `MINVMD_BEP_PER_BOX_CAP` override as a positive value, if set and valid.
pub(crate) fn env_bep_per_box_cap() -> Option<u32> {
    positive_env(BEP_PER_BOX_CAP_ENV)
}

/// The largest per-box cap `minvmd` accepts. Each slot of a box's share
/// holds listening sockets with their own buffers while it is idle, so an
/// unbounded cap (a typo such as `4000000000`) can exhaust memory when a box
/// registers. `minvmd config set` refuses a value above it, and
/// [`resolve_bep_per_box_cap`] clamps an env or `config.toml` value to it.
pub const MAX_BEP_PER_BOX_CAP: u32 = 1024;

/// Where the effective per-box cap came from, in the precedence order
/// [`resolve_bep_per_box_cap`] applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapSource {
    /// The [`BEP_PER_BOX_CAP_ENV`] override.
    Env,
    /// `bep_per_box_cap` in `config.toml`, written by `minvmd config set`.
    Config,
    /// [`switch::bep_host::DEFAULT_PER_SOURCE_CAP`].
    Default,
}

impl CapSource {
    /// The label `minvmd config show` prints beside the value.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Env => "env",
            Self::Config => "config",
            Self::Default => "default",
        }
    }
}

/// Resolve the per-box cap from its layers: the env override, then the
/// persisted config, then the switch's recorded default. A zero in either
/// layer counts as unset, because a box with no share can open nothing.
/// A value above [`MAX_BEP_PER_BOX_CAP`] is clamped to it. Pure, so the precedence is testable without the process environment.
#[must_use]
pub fn resolve_bep_per_box_cap(env: Option<u32>, persisted: Option<u32>) -> (usize, CapSource) {
    let positive = |v: Option<u32>| {
        v.filter(|v| *v > 0)
            .map(|v| v.min(MAX_BEP_PER_BOX_CAP) as usize)
    };
    if let Some(cap) = positive(env) {
        (cap, CapSource::Env)
    } else if let Some(cap) = positive(persisted) {
        (cap, CapSource::Config)
    } else {
        (switch::bep_host::DEFAULT_PER_SOURCE_CAP, CapSource::Default)
    }
}

/// The effective per-box cap on Box Egress Proxy connections — each
/// registered box's share of the proxy listener pool (spec NET-132) —
/// with the layer it came from, resolved as
/// `env override ?? persisted config ?? default`. Read once at boot, so a
/// `minvmd config set --bep-per-box-cap` takes effect on the next boot.
#[must_use]
pub fn effective_bep_per_box_cap() -> (usize, CapSource) {
    let env = env_bep_per_box_cap();
    let persisted = persisted_resource_config().bep_per_box_cap;
    let resolved = resolve_bep_per_box_cap(env, persisted);
    let raw = match resolved.1 {
        CapSource::Env => env,
        CapSource::Config => persisted,
        CapSource::Default => None,
    };
    if let Some(raw) = raw.filter(|v| *v > MAX_BEP_PER_BOX_CAP) {
        tracing::warn!(
            requested = raw,
            max = MAX_BEP_PER_BOX_CAP,
            source = resolved.1.label(),
            "per-box BEP connection cap above the maximum; clamped"
        );
    }
    resolved
}

/// Verify the host hypervisor backend is accessible before booting a VM (R2.4).
///
/// On Linux, libkrun drives KVM, which needs a readable `/dev/kvm`. Probe it
/// with an `O_RDONLY` open so `boot`/`run` fail fast with an actionable message
/// instead of an opaque libkrun error from `krun_start_enter`.
///
/// On macOS, libkrun drives Hypervisor.framework, which a Mac that is itself a
/// virtual machine without nested virtualization does not have. libkrun only
/// finds that out in the VMM child, after the supervisor has detached, so the
/// caller waited out the whole spawn timeout before a vague failure
/// (gominimal/inbox#1178). Read `kern.hv_support` here instead and refuse at
/// once when it is a clear 0 ([`hv_support_refusal`]).
#[cfg(minvmd_libkrun)]
pub(crate) fn ensure_hypervisor_accessible() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .open("/dev/kvm")
            .map(|_| ())
            .map_err(|e| kvm_access_error(&e))
    }

    #[cfg(target_os = "macos")]
    {
        match hv_support_refusal(read_hv_support()) {
            Some(refusal) => Err(anyhow::anyhow!(refusal)),
            None => Ok(()),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Ok(())
}

/// The refusal for a macOS host whose `kern.hv_support` sysctl reads `value`,
/// or `None` to go on with the boot.
///
/// Only a clear 0 refuses: the kernel says this Mac has no hypervisor, and no
/// VM can start on it. A 1 goes on, and so does a value that could not be
/// read (`None`) or one this code does not know: an unreadable sysctl is not
/// evidence that the hypervisor is missing, and libkrun still reports a real
/// failure later. Kept platform-independent so the decision and its wording
/// are unit-tested on every host, though only macOS calls it.
#[cfg(any(test, all(minvmd_libkrun, target_os = "macos")))]
fn hv_support_refusal(value: Option<i32>) -> Option<&'static str> {
    match value {
        Some(0) => Some(
            "this Mac has no hypervisor support (`sysctl kern.hv_support` is 0), so the \
             Minimal VM cannot start. Run on a physical Mac, or on a virtual Mac whose host \
             turns on nested virtualization.",
        ),
        _ => None,
    }
}

/// Read the integer sysctl `kern.hv_support`: 1 when this Mac can run a
/// hypervisor, 0 when it cannot. `None` when the sysctl is absent or cannot
/// be read.
#[cfg(all(minvmd_libkrun, target_os = "macos"))]
fn read_hv_support() -> Option<i32> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name is a NUL-terminated C string, and `value`/`size`
    // describe a writable `c_int` the kernel fills in; no new value is set.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.hv_support".as_ptr(),
            (&raw mut value).cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && size == std::mem::size_of::<libc::c_int>()).then_some(value)
}

/// Map a `/dev/kvm` open failure to an actionable, user-facing error (R2.4).
///
/// `ENOENT` → the KVM module is not loaded / the host has no hardware
/// virtualization; `EACCES` → the caller is not in the `kvm` group. Other
/// errors are wrapped verbatim. Kept platform-independent (so it is exercised
/// by unit tests on every libkrun build) even though it is only invoked on
/// Linux.
#[cfg(minvmd_libkrun)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn kvm_access_error(err: &std::io::Error) -> anyhow::Error {
    use std::io::ErrorKind;

    match err.kind() {
        ErrorKind::NotFound => anyhow::anyhow!(
            "/dev/kvm not found: the KVM kernel module is not loaded or the host has no \
             hardware virtualization. Load it (`modprobe kvm` plus `kvm_intel`/`kvm_amd`) \
             or run on a KVM-capable host."
        ),
        ErrorKind::PermissionDenied => anyhow::anyhow!(
            "/dev/kvm: permission denied. Add your user to the `kvm` group \
             (`sudo usermod -aG kvm $USER`, then re-login) or adjust the device permissions."
        ),
        _ => anyhow::anyhow!("opening /dev/kvm: {err}"),
    }
}

/// Returns the path to the VM SSH known_hosts file:
/// `<host dir>/known_hosts`.
#[cfg(minvmd_libkrun)]
pub(crate) fn default_vm_known_hosts_path() -> std::path::PathBuf {
    crate::state::host_dir().join(paths::KNOWN_HOSTS_FILE)
}

/// Outcome of the guest boot beacon (R2.4/R2.5): the guest either reached
/// READY, or refused with `MOUNT_FAILED\n<reason>\n` because the data volume
/// could not be mounted, or refused with `STATE_REFUSED\n<reason>\n` because
/// a newer build wrote the box state on the volume.
#[cfg(any(minvmd_libkrun, test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BootBeacon {
    /// The guest is up and serving.
    Ready,
    /// The guest refused READY: the data volume mount failed (R2.5).
    MountFailed {
        /// One-line failure cause relayed from the guest (capped there).
        reason: String,
    },
    /// The guest refused READY: the data volume mounted, but a newer build
    /// wrote the box state on it. The guest changed nothing on it.
    StateRefused {
        /// The guest's one-line refusal text (capped there).
        reason: String,
    },
}

/// Read the boot beacon from `reader`. For a `READY` beacon, if a valid SSH
/// public key is on the second line, record it in `known_hosts_path`
/// (R2.1–R2.4); for a `MOUNT_FAILED` beacon, carry the guest's one-line
/// reason (R2.5).
///
/// Returns `Err` only when the first line is neither marker. Key parse
/// failures and known_hosts write errors are logged as warnings and do not
/// abort boot (R2.3).
#[cfg(any(minvmd_libkrun, test))]
pub(crate) fn read_ready_beacon<R: std::io::BufRead>(
    reader: &mut R,
    known_hosts_path: &std::path::Path,
) -> Result<BootBeacon, String> {
    use std::io::BufRead;
    let mut line = String::new();
    // Use UFCS so Rust resolves `Self = &mut R` (not `R`) in the function-call
    // context, producing Take<&mut R> without a move out of the mutable reference.
    std::io::Read::take(reader.by_ref(), 32)
        .read_line(&mut line)
        .map_err(|e| format!("reading READY marker: {e}"))?;
    let trimmed = line.trim();
    if trimmed == "STATE_REFUSED" {
        let mut reason = String::new();
        if let Err(e) = std::io::Read::take(reader.by_ref(), 1024).read_line(&mut reason) {
            tracing::debug!(error = %e, "failed to read STATE_REFUSED reason line");
        }
        let reason = reason.trim();
        return Ok(BootBeacon::StateRefused {
            reason: if reason.is_empty() {
                "A newer min wrote the box state on the data volume.".to_string()
            } else {
                reason.to_string()
            },
        });
    }
    if trimmed == "MOUNT_FAILED" {
        // Optional second line: the failure reason (guest caps it at 512 B;
        // 1024 here leaves margin without unbounding the read).
        let mut reason = String::new();
        if let Err(e) = std::io::Read::take(reader.by_ref(), 1024).read_line(&mut reason) {
            tracing::debug!(error = %e, "failed to read MOUNT_FAILED reason line");
        }
        let reason = reason.trim();
        return Ok(BootBeacon::MountFailed {
            reason: if reason.is_empty() {
                "no reason given".to_string()
            } else {
                reason.to_string()
            },
        });
    }
    if trimmed != "READY" {
        return Err(format!("expected READY on marker socket, got {trimmed:?}"));
    }

    // Try to read the optional second line: SSH host public key (R2.1).
    // Cap the read at 4097 bytes so the allocation ceiling is enforced at the
    // I/O layer rather than after the fact.
    let mut pubkey_line = String::new();
    match std::io::Read::take(reader.by_ref(), 4097).read_line(&mut pubkey_line) {
        Err(e) => {
            tracing::debug!(error = %e, "failed to read pubkey line from beacon; skipping");
        }
        Ok(0) => {
            tracing::debug!("no pubkey line in ready beacon");
        }
        Ok(_) => {
            let key_str = pubkey_line.trim();
            if key_str.len() > 4096 {
                tracing::warn!(len = key_str.len(), "pubkey line too long; skipping");
                return Ok(BootBeacon::Ready);
            }
            if !key_str.is_empty() {
                // R2.4: create the directory hierarchy before writing.
                if let Some(parent) = known_hosts_path.parent()
                    && let Err(e) = std::fs::create_dir_all(parent)
                {
                    tracing::warn!(
                        error = %e,
                        path = %parent.display(),
                        "failed to create known_hosts directory; skipping key write",
                    );
                    return Ok(BootBeacon::Ready);
                }
                // R2.2: parse and record the key.
                match russh::keys::ssh_key::PublicKey::from_openssh(key_str) {
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse SSH host key from beacon");
                    }
                    Ok(pubkey) => {
                        // Key the known_hosts entry on the alias ssh connects
                        // with (`local-minvmd0` for the default VM,
                        // `<vm>.local-minvmd0` for a named VM) rather than a
                        // fixed host name. The path is always
                        // `<host dir>/known_hosts`, so a missing alias is
                        // a programming error.
                        let host_alias = known_hosts_path.parent().and_then(paths::ssh_host_alias);
                        debug_assert!(
                            host_alias.is_some(),
                            "known_hosts path {} has no provider-dir parent",
                            known_hosts_path.display(),
                        );
                        let Some(host_alias) = host_alias else {
                            tracing::warn!(
                                path = %known_hosts_path.display(),
                                "known_hosts path has no provider-dir parent; skipping key write",
                            );
                            return Ok(BootBeacon::Ready);
                        };
                        // `learn_known_hosts_path` appends unconditionally; drop
                        // any prior entry for this host first so the file records
                        // exactly one current key instead of growing a line per
                        // spawn (#782). Best-effort: a prune failure must not
                        // abort boot (R2.3).
                        if let Err(e) =
                            paths::prune_known_hosts_entries(known_hosts_path, &host_alias, 22)
                        {
                            tracing::warn!(error = %e, "failed to prune stale known_hosts entries");
                        }
                        match russh::keys::known_hosts::learn_known_hosts_path(
                            &host_alias,
                            22,
                            &pubkey,
                            known_hosts_path,
                        ) {
                            Err(e) => {
                                tracing::warn!(error = %e, "failed to write SSH host key to known_hosts");
                            }
                            Ok(()) => {
                                tracing::info!(
                                    path = %known_hosts_path.display(),
                                    "recorded VM SSH host key in known_hosts",
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(BootBeacon::Ready)
}

/// Build the user-facing error for a guest `MOUNT_FAILED` boot (R2.5 host
/// half). Fatality follows from whether the volume image pre-existed this
/// boot: a pre-existing image may hold session data, so it is left untouched
/// and the message points at repair; a freshly provisioned blank one is
/// removed so the next boot does not misclassify the failed blank as prior
/// state.
#[cfg(minvmd_libkrun)]
pub(crate) fn mount_failed_error(
    reason: &str,
    volume_path: &std::path::Path,
    volume_preexisted: bool,
) -> anyhow::Error {
    if volume_preexisted {
        anyhow::anyhow!(
            "guest failed to mount the data volume at {path}: {reason}. \
             The image pre-exists and may hold session data — it was left untouched. \
             Repair it (e2fsck) or move it aside (or point {env} elsewhere), then retry.",
            path = volume_path.display(),
            env = crate::volume::DATA_VOLUME_PATH_ENV,
        )
    } else {
        anyhow::anyhow!(
            "guest failed to format/mount the freshly provisioned data volume at {path}: \
             {reason}. The blank image was removed; check {env} and retry.",
            path = volume_path.display(),
            env = crate::volume::VOLUME_BYTES_ENV,
        )
    }
}

/// Build the error for a guest `STATE_REFUSED` boot: the guest's refusal
/// text, then the host path of the data volume that holds the state. The
/// guest names its own mount point, which a person on the host cannot open.
/// The volume is never touched: it holds the newer build's state.
#[cfg(any(minvmd_libkrun, test))]
pub(crate) fn state_refused_error(reason: &str, volume_path: &std::path::Path) -> anyhow::Error {
    anyhow::Error::new(StateRefusedError(format!(
        "{reason} That state is on the data volume {}.",
        volume_path.display()
    )))
}

/// The error [`state_refused_error`] builds. A caller tells it from other
/// boot failures by its type, and keeps the volume for it.
#[cfg(any(minvmd_libkrun, test))]
#[derive(Debug)]
pub(crate) struct StateRefusedError(String);

#[cfg(any(minvmd_libkrun, test))]
impl std::fmt::Display for StateRefusedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(any(minvmd_libkrun, test))]
impl std::error::Error for StateRefusedError {}

/// Whether the data-volume image already exists before this boot provisions
/// it — the input to the R2.5 fatality decision. A stat error counts as
/// **pre-existing**: the failure disposition for a pre-existing image is
/// "never touch it", so doubt must land on the safe side rather than let a
/// transient stat failure send a data-bearing image down the delete branch.
#[cfg(minvmd_libkrun)]
pub(crate) fn volume_preexists(volume_path: &std::path::Path) -> bool {
    volume_path.try_exists().unwrap_or(true)
}

/// Disposition of the data-volume image after a failed boot (R2.5 host half):
/// an image that pre-existed this boot may hold session data and is never
/// touched; a blank one freshly provisioned by this boot holds nothing and is
/// removed. Runs on **every** failed-boot arm — mount failure, beacon read
/// error, READY timeout — because a blank stranded by a timeout would be
/// misclassified as "pre-existing, may hold session data" on the next boot,
/// wedging all subsequent boots behind a scary message about an empty file.
#[cfg(minvmd_libkrun)]
pub(crate) fn discard_fresh_volume_image(volume_path: &std::path::Path, volume_preexisted: bool) {
    if volume_preexisted {
        return;
    }
    // Racing a concurrent boot's fresh provisioning is possible but harmless:
    // both boots fail loudly either way.
    match std::fs::remove_file(volume_path) {
        Ok(()) => {
            tracing::info!(
                path = %volume_path.display(),
                "removed freshly provisioned volume image after failed boot",
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                error = %e,
                path = %volume_path.display(),
                "removing freshly provisioned volume image after failed boot",
            );
        }
    }
}

#[cfg(all(test, minvmd_libkrun))]
mod tests {
    use super::kvm_access_error;
    use std::io::{Error, ErrorKind};

    #[test]
    fn enoent_maps_to_module_guidance() {
        let msg = kvm_access_error(&Error::from(ErrorKind::NotFound)).to_string();
        assert!(msg.contains("/dev/kvm"), "got: {msg}");
        assert!(msg.contains("not loaded"), "got: {msg}");
    }

    #[test]
    fn eacces_maps_to_kvm_group_guidance() {
        let msg = kvm_access_error(&Error::from(ErrorKind::PermissionDenied)).to_string();
        assert!(msg.contains("permission denied"), "got: {msg}");
        assert!(msg.contains("`kvm` group"), "got: {msg}");
    }
}

#[cfg(test)]
mod hv_support_tests {
    use super::hv_support_refusal;

    #[test]
    fn a_clear_zero_refuses_and_says_why_and_what_to_do() {
        let msg = hv_support_refusal(Some(0)).expect("kern.hv_support = 0 refuses");
        assert!(msg.contains("no hypervisor support"), "got: {msg}");
        assert!(msg.contains("kern.hv_support"), "got: {msg}");
        assert!(msg.contains("nested virtualization"), "got: {msg}");
        assert!(!msg.contains('\n'), "one line: {msg}");
    }

    #[test]
    fn a_host_with_a_hypervisor_boots() {
        assert_eq!(hv_support_refusal(Some(1)), None);
    }

    #[test]
    fn an_absent_or_unreadable_sysctl_does_not_refuse() {
        assert_eq!(hv_support_refusal(None), None);
    }

    #[test]
    fn only_zero_refuses() {
        for value in [-1, 2, i32::MAX] {
            assert_eq!(hv_support_refusal(Some(value)), None, "value {value}");
        }
    }
}

#[cfg(test)]
mod vcpu_ceiling_tests {
    use super::*;

    #[test]
    fn max_backs_off_the_host_reserve() {
        assert_eq!(max_vm_vcpus(64), 62);
        assert_eq!(max_vm_vcpus(8), 6);
    }

    #[test]
    fn max_floors_at_the_default_on_small_hosts() {
        assert_eq!(max_vm_vcpus(1), DEFAULT_VM_VCPUS);
        assert_eq!(max_vm_vcpus(4), DEFAULT_VM_VCPUS);
    }

    #[test]
    fn max_saturates_to_the_vcpu_type() {
        assert_eq!(max_vm_vcpus(1000), u8::MAX);
    }
}

#[cfg(test)]
mod beacon_tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_ready_beacon_writes_known_hosts_entry() {
        use russh::keys::{Algorithm, PrivateKey, key::safe_rng};

        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let pubkey = key.public_key();
        let openssh = pubkey.to_openssh().unwrap();

        let beacon = format!("READY\n{openssh}\n");
        let mut reader = Cursor::new(beacon.into_bytes());

        let tmp = tempfile::tempdir().unwrap();
        // Default-VM layout: the known_hosts file sits directly in the
        // host dir, so the alias is its basename.
        let known_hosts_path = tmp
            .path()
            .join("providers")
            .join("local-minvmd0")
            .join("known_hosts");

        read_ready_beacon(&mut reader, &known_hosts_path)
            .expect("read_ready_beacon must succeed with valid beacon");

        let contents =
            std::fs::read_to_string(&known_hosts_path).expect("known_hosts file must be created");
        assert!(
            contents.contains("local-minvmd0"),
            "known_hosts must contain 'local-minvmd0', got: {contents:?}"
        );
        assert!(
            contents.contains(&openssh),
            "known_hosts must contain the beacon public key, got: {contents:?}"
        );
    }

    #[test]
    fn read_ready_beacon_keys_named_vm_on_its_alias() {
        use russh::keys::{Algorithm, PrivateKey, key::safe_rng};

        let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let pubkey = key.public_key();
        let openssh = pubkey.to_openssh().unwrap();

        let beacon = format!("READY\n{openssh}\n");
        let mut reader = Cursor::new(beacon.into_bytes());

        let tmp = tempfile::tempdir().unwrap();
        // Named-VM layout: the known_hosts file sits in the per-name
        // subdirectory, so the alias is the VM name namespaced under the
        // host name.
        let known_hosts_path = tmp
            .path()
            .join("providers")
            .join("local-minvmd0")
            .join("alpha")
            .join("known_hosts");

        read_ready_beacon(&mut reader, &known_hosts_path)
            .expect("read_ready_beacon must succeed with valid beacon");

        let contents =
            std::fs::read_to_string(&known_hosts_path).expect("known_hosts file must be created");
        assert!(
            contents.contains("alpha.local-minvmd0 "),
            "known_hosts must key the entry on the namespaced alias \
             'alpha.local-minvmd0', got: {contents:?}"
        );
    }

    #[test]
    fn read_ready_beacon_tolerates_missing_pubkey_line() {
        let mut reader = Cursor::new(b"READY\n".as_ref());
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts_path = tmp.path().join("known_hosts");

        read_ready_beacon(&mut reader, &known_hosts_path)
            .expect("must not fail when pubkey line is absent");
        assert!(
            !known_hosts_path.exists(),
            "no known_hosts should be written when pubkey line is absent"
        );
    }

    #[test]
    fn read_ready_beacon_rejects_oversized_pubkey_line() {
        // A pubkey line longer than 4096 bytes must be skipped gracefully
        // without writing known_hosts.
        let oversized = "x".repeat(5000);
        let beacon = format!("READY\n{oversized}\n");
        let mut reader = Cursor::new(beacon.into_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts_path = tmp.path().join("known_hosts");

        read_ready_beacon(&mut reader, &known_hosts_path)
            .expect("must not fail on oversized pubkey (graceful skip)");
        assert!(
            !known_hosts_path.exists(),
            "no known_hosts should be written when pubkey line is too long"
        );
    }

    #[test]
    fn read_ready_beacon_rejects_wrong_marker() {
        let mut reader = Cursor::new(b"NOTREADY\n".as_ref());
        let tmp = tempfile::tempdir().unwrap();
        let known_hosts_path = tmp.path().join("known_hosts");

        let err = read_ready_beacon(&mut reader, &known_hosts_path)
            .expect_err("must fail when first line is not READY");
        assert!(
            err.contains("READY"),
            "error must mention READY, got: {err:?}"
        );
    }

    #[test]
    fn read_ready_beacon_returns_ready_variant() {
        let mut reader = Cursor::new(b"READY\n".as_ref());
        let tmp = tempfile::tempdir().unwrap();
        let beacon = read_ready_beacon(&mut reader, &tmp.path().join("known_hosts")).unwrap();
        assert_eq!(beacon, BootBeacon::Ready);
    }

    #[test]
    fn read_ready_beacon_parses_mount_failed_with_reason() {
        let mut reader = Cursor::new(b"MOUNT_FAILED\nmkfs.ext4 failed: exit 1\n".as_ref());
        let tmp = tempfile::tempdir().unwrap();
        let beacon = read_ready_beacon(&mut reader, &tmp.path().join("known_hosts")).unwrap();
        assert_eq!(
            beacon,
            BootBeacon::MountFailed {
                reason: "mkfs.ext4 failed: exit 1".to_string()
            }
        );
    }

    #[test]
    fn read_ready_beacon_parses_state_refused() {
        let text = "A newer min wrote the box state in /var/lib/minimal. That state has \
                    format version 2.";
        let payload = format!("STATE_REFUSED\n{text}\n");
        let mut reader = Cursor::new(payload.as_bytes());
        let tmp = tempfile::tempdir().unwrap();
        let beacon = read_ready_beacon(&mut reader, &tmp.path().join("known_hosts")).unwrap();
        assert_eq!(
            beacon,
            BootBeacon::StateRefused {
                reason: text.to_string()
            }
        );
        let err = state_refused_error(text, std::path::Path::new("/h/minimal/data.ext4"));
        assert_eq!(
            err.to_string(),
            format!("{text} That state is on the data volume /h/minimal/data.ext4.")
        );
        assert!(err.is::<StateRefusedError>());

        let mut reader = Cursor::new(b"STATE_REFUSED\n".as_ref());
        let beacon = read_ready_beacon(&mut reader, &tmp.path().join("known_hosts")).unwrap();
        assert!(matches!(beacon, BootBeacon::StateRefused { .. }), "{beacon:?}");
    }

    #[test]
    fn read_ready_beacon_parses_mount_failed_without_reason() {
        let mut reader = Cursor::new(b"MOUNT_FAILED\n".as_ref());
        let tmp = tempfile::tempdir().unwrap();
        let beacon = read_ready_beacon(&mut reader, &tmp.path().join("known_hosts")).unwrap();
        assert_eq!(
            beacon,
            BootBeacon::MountFailed {
                reason: "no reason given".to_string()
            }
        );
    }

    #[test]
    fn read_ready_beacon_replaces_prior_host_key_without_growth() {
        use russh::keys::{Algorithm, PrivateKey, key::safe_rng};

        let tmp = tempfile::tempdir().unwrap();
        let known_hosts_path = tmp.path().join("known_hosts");

        // Two spawns, each carrying a freshly generated host key — the VM guest
        // regenerates its key on every boot (its key lives on tmpfs). The file
        // must record only the latest key on a single line, not grow by a line
        // per spawn (#782).
        let mut latest = String::new();
        for _ in 0..2 {
            let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
            latest = key.public_key().to_openssh().unwrap();
            let beacon = format!("READY\n{latest}\n");
            let mut reader = Cursor::new(beacon.into_bytes());
            read_ready_beacon(&mut reader, &known_hosts_path)
                .expect("read_ready_beacon must succeed with valid beacon");
        }

        let contents = std::fs::read_to_string(&known_hosts_path).unwrap();
        assert_eq!(
            contents.lines().filter(|l| !l.trim().is_empty()).count(),
            1,
            "known_hosts must hold exactly one entry after repeated spawns, got: {contents:?}",
        );
        assert!(
            contents.contains(&latest),
            "known_hosts must hold the latest host key, got: {contents:?}",
        );
    }
}

#[cfg(test)]
mod bep_cap_tests {
    use super::{CapSource, resolve_bep_per_box_cap};
    use switch::bep_host::DEFAULT_PER_SOURCE_CAP;

    #[test]
    fn effective_bep_per_box_cap_prefers_env_then_config_then_default() {
        assert_eq!(
            resolve_bep_per_box_cap(Some(32), Some(128)),
            (32, CapSource::Env)
        );
        assert_eq!(
            resolve_bep_per_box_cap(None, Some(128)),
            (128, CapSource::Config)
        );
        assert_eq!(
            resolve_bep_per_box_cap(None, None),
            (DEFAULT_PER_SOURCE_CAP, CapSource::Default)
        );
    }

    #[test]
    fn effective_bep_per_box_cap_treats_zero_as_unset() {
        assert_eq!(
            resolve_bep_per_box_cap(Some(0), Some(96)),
            (96, CapSource::Config)
        );
        assert_eq!(
            resolve_bep_per_box_cap(None, Some(0)),
            (DEFAULT_PER_SOURCE_CAP, CapSource::Default)
        );
    }

    #[test]
    fn effective_bep_per_box_cap_clamps_to_the_maximum() {
        let max = super::MAX_BEP_PER_BOX_CAP as usize;
        assert_eq!(
            resolve_bep_per_box_cap(Some(4_000_000_000), None),
            (max, CapSource::Env)
        );
        assert_eq!(
            resolve_bep_per_box_cap(None, Some(u32::MAX)),
            (max, CapSource::Config)
        );
        assert_eq!(
            resolve_bep_per_box_cap(None, Some(super::MAX_BEP_PER_BOX_CAP)),
            (max, CapSource::Config)
        );
    }

    #[test]
    fn effective_bep_per_box_cap_default_admits_one_pulumi_preview() {
        // Sixty parallel CONNECTs from one box must all get a share.
        let (cap, source) = resolve_bep_per_box_cap(None, None);
        assert_eq!(source, CapSource::Default);
        assert!(cap >= 60, "the default cap {cap} resets a Pulumi preview");
    }

    #[test]
    fn effective_bep_per_box_cap_source_labels() {
        assert_eq!(CapSource::Env.label(), "env");
        assert_eq!(CapSource::Config.label(), "config");
        assert_eq!(CapSource::Default.label(), "default");
    }
}
