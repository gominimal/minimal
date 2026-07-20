//! `minvmd __krun-vmm` hidden subcommand (R2.3).
//!
//! This is the VMM child process that calls `krun_start_enter`. It is spawned
//! by `minvmd boot` and is not intended to be run directly by users (hence the
//! double-underscore prefix).
//!
//! With libkrun (macOS via Hypervisor.framework, Linux via KVM):
//! 1. Reads kernel, rootfs, and initramfs paths from `MINVMD_KERNEL_PATH` /
//!    `MINVMD_ROOTFS_PATH` / `MINVMD_INITRAMFS`.
//! 2. Reads the READY-marker socket path from `MINVMD_MARKER_SOCK`.
//! 3. Creates and configures a libkrun context (kernel + initramfs, ext4 root
//!    disk via `krun_add_disk2`, resources).
//! 4. Boots the initramfs: the kernel unpacks it into a RAM root and runs its
//!    `/init` (minimald) as PID 1; `/init` mounts the ext4 rootfs (`/dev/vda`)
//!    and chroots into it.
//! 5. Registers the marker socket for `VSOCK_MARKER_PORT` (guest→host): the
//!    guest workload connects to that vsock port and writes `READY\n`, which
//!    libkrun bridges to the host UNIX socket where the parent listens.
//! 6. Calls `krun_start_enter`, which boots the VM. On success libkrun
//!    `exit()`s with the guest workload's exit code and never returns here.
//!
//! Without libkrun this subcommand bails immediately with a "no libkrun" error.

use anyhow::{Result, bail};

/// Run the `__krun-vmm` subcommand.
pub fn run() -> Result<()> {
    #[cfg(minvmd_libkrun)]
    return run_vmm();

    #[cfg(not(minvmd_libkrun))]
    bail!("`minvmd __krun-vmm` requires libkrun (macOS, or Linux with libkrun installed)");
}

#[cfg(minvmd_libkrun)]
fn run_vmm() -> Result<()> {
    use anyhow::Context as _;

    use crate::cmd::{MARKER_SOCK_ENV, VSOCK_MARKER_PORT};
    use crate::image::{resolve_initramfs_path, resolve_kernel_path, resolve_rootfs_path};
    use crate::krun::Context;
    use crate::vm::VmConfig;

    let kernel = resolve_kernel_path().context("resolving kernel path")?;
    let rootfs = resolve_rootfs_path().context("resolving rootfs path")?;
    let initramfs = resolve_initramfs_path().context("resolving initramfs path")?;
    let marker_sock = std::env::var(MARKER_SOCK_ENV).with_context(|| {
        format!("reading {MARKER_SOCK_ENV}: VMM child must be spawned by `minvmd boot`")
    })?;

    let mut ctx = Context::create().context("krun_create_ctx")?;
    // vcpus and guest RAM are the *effective* values: env override ?? persisted
    // `minvmd config` ?? default (R9.7). RAM keeps its tmpfs-headroom default and
    // x86_64 hole-safe rule (see `DEFAULT_VM_RAM_MIB`); vcpus stay below the
    // kernel's CONFIG_NR_CPUS. `apply` configures the kernel + initramfs, the
    // ext4 root disk, the writable data volume, and the vsock bridge.
    let mut cfg = VmConfig::new(
        crate::cmd::effective_vcpus(),
        crate::cmd::effective_ram_mib(),
        kernel,
        rootfs,
        initramfs,
    );
    // An own-IP VM registers the per-PTask gvproxy shuttle vsock
    // bridge in `apply`; the host gvproxy is spawned by the parent supervisor.
    // The env var keeps the parent's gvproxy-spawn decision and this child's VM
    // config in lock-step.
    if crate::cmd::own_ip_requested() {
        cfg = cfg.with_network_mode(minimald_rpc::NetworkMode::OwnIp);
    }

    // Provision + attach the per-VM writable data volume as /dev/vdb (spec R1.4).
    // On by default: the image lives at the resolved path (MINVMD_DATA_VOLUME_PATH
    // override, else `<provider dir>/data-vol.raw`) and is created sparse if
    // missing.
    // Provisioning at the literal path — not a stem-reconstructed one — so an
    // explicit override is honoured verbatim.
    let data_volume_path = crate::volume::resolve_data_volume_path();
    crate::volume::ensure_sparse_raw(&data_volume_path, crate::volume::volume_bytes())
        .context("provisioning writable data volume")?;
    cfg = cfg.with_data_volume(data_volume_path);

    cfg.apply(&mut ctx)
        .context("applying VmConfig to krun context")?;

    // Console capture (hvc0 → host file). `MINVMD_BOOT_LOG=<path>` overrides;
    // the default is `<provider dir>/boot.log` — a silently-discarded console
    // is exactly the evidence lost in wedged-boot/dead-transport incidents,
    // and `min bug` bundles this file (tail-capped) per provider. Truncated
    // each boot so it holds the current VM generation's console.
    let boot_log = std::env::var_os("MINVMD_BOOT_LOG")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| crate::state::provider_dir().join("boot.log"));
    // Capture is diagnostics, not a boot dependency: any failure — creating
    // the file or wiring the console — warns and boots on, never propagates.
    if let Err(e) = std::fs::File::create(&boot_log) {
        tracing::warn!(path = %boot_log.display(), error = %e, "cannot create boot log; console discarded");
    } else if let Err(e) = ctx.set_console_output(&boot_log) {
        tracing::warn!(path = %boot_log.display(), error = %e, "cannot wire console to boot log; console discarded");
    }

    // Register the READY-marker vsock port (guest→host). The plain
    // `krun_add_vsock_port` is `krun_add_vsock_port2(.., listen=false)`: the
    // parent listens on the host UDS `marker_sock`; the guest workload connects
    // to AF_VSOCK CID 2 (host) port VSOCK_MARKER_PORT and writes `READY\n`,
    // which libkrun bridges to the parent.
    ctx.add_vsock_port(VSOCK_MARKER_PORT, &marker_sock)
        .context("registering READY-marker vsock port")?;

    tracing::info!(
        port = VSOCK_MARKER_PORT,
        sock = %marker_sock,
        "initramfs boot + READY-marker vsock port set; calling krun_start_enter"
    );

    // start_enter consumes the context and boots the VM. On success, libkrun
    // exit()s the process with the guest workload's exit code and never
    // returns. On failure it returns a VmError; we surface it as an anyhow
    // error so the parent can observe the child's non-zero exit.
    let err = ctx.start_enter();
    bail!("krun_start_enter returned unexpectedly: {err}");
}
