//! `minvmd __krun-vmm` hidden subcommand (R2.3).
//!
//! This is the VMM child process that calls `krun_start_enter`. It is spawned
//! by `minvmd boot` and is not intended to be run directly by users (hence the
//! double-underscore prefix).
//!
//! On macOS:
//! 1. Reads kernel and rootfs from `MINVMD_KERNEL_PATH` / `MINVMD_ROOTFS_PATH`.
//! 2. Reads the READY-marker socket path from `MINVMD_MARKER_SOCK`.
//! 3. Creates and configures a libkrun context (kernel + cmdline, ext4 root
//!    disk via `krun_add_disk2`, resources).
//! 4. Sets the guest workload via the kernel `init=` cmdline: the ext4 block
//!    root has no libkrun `/init.krun`, so the kernel execs the workload
//!    directly as PID 1. Default `/sbin/minvmd-stub-init`, `MINVMD_EXEC`
//!    overrides.
//! 5. Registers the marker socket for `VSOCK_MARKER_PORT` (guest→host): the
//!    guest workload connects to that vsock port and writes `READY\n`, which
//!    libkrun bridges to the host UNIX socket where the parent listens (R2.4).
//! 6. Calls `krun_start_enter`, which boots the VM. On success libkrun
//!    `exit()`s with the guest workload's exit code and never returns here.
//!
//! On Linux this subcommand bails immediately with a "macOS only" error.

use anyhow::{Result, bail};

/// Run the `__krun-vmm` subcommand.
pub fn run() -> Result<()> {
    #[cfg(target_os = "macos")]
    return run_macos();

    #[cfg(not(target_os = "macos"))]
    bail!("`minvmd __krun-vmm` is macOS-only; this Linux build is a no-op stub");
}

#[cfg(target_os = "macos")]
fn run_macos() -> Result<()> {
    use anyhow::Context as _;

    use crate::cmd::{MARKER_SOCK_ENV, VSOCK_MARKER_PORT};
    use crate::image::{resolve_kernel_path, resolve_rootfs_path};
    use crate::krun::Context;
    use crate::vm::VmConfig;

    let kernel = resolve_kernel_path().context("resolving kernel path")?;
    let rootfs = resolve_rootfs_path().context("resolving rootfs path")?;
    let marker_sock = std::env::var(MARKER_SOCK_ENV).with_context(|| {
        format!("reading {MARKER_SOCK_ENV}: VMM child must be spawned by `minvmd boot`")
    })?;

    // Guest workload run as the kernel `init=`. The root is a block device
    // (ext4 via krun_add_disk2), which has no libkrun `/init.krun`, so the
    // kernel execs this directly as PID 1. Default to the v0.1 bring-up stub;
    // `MINVMD_EXEC` overrides (e.g. /sbin/minimald in Stage 2).
    let exec =
        std::env::var("MINVMD_EXEC").unwrap_or_else(|_| "/sbin/minvmd-stub-init".to_string());

    let mut ctx = Context::create().context("krun_create_ctx")?;
    // 2 vCPU / 1024 MiB: 512 MiB is the practical floor to reach userspace;
    // 1024 MiB is cheap headroom under Hypervisor.framework with no boot
    // penalty. (Stay below the kernel's CONFIG_NR_CPUS.) The boot command may
    // expose these as flags in a future change. `apply` configures the kernel +
    // cmdline (with `init=exec`), the ext4 root disk, and the vsock bridge.
    let cfg = VmConfig::new(2, 1024, kernel, rootfs, exec.clone());
    cfg.apply(&mut ctx)
        .context("applying VmConfig to krun context")?;

    // Optional early-boot console capture for diagnosing a stuck boot. Off by
    // default; set `MINVMD_BOOT_LOG=<path>` to capture hvc0 to a host file.
    if let Some(log_path) = std::env::var_os("MINVMD_BOOT_LOG") {
        ctx.set_console_output(&log_path)
            .context("setting console output log")?;
    }

    // Register the READY-marker vsock port (guest→host). The plain
    // `krun_add_vsock_port` is `krun_add_vsock_port2(.., listen=false)`: the
    // parent listens on the host UDS `marker_sock`; the guest workload connects
    // to AF_VSOCK CID 2 (host) port VSOCK_MARKER_PORT and writes `READY\n`,
    // which libkrun bridges to the parent (R2.4).
    ctx.add_vsock_port(VSOCK_MARKER_PORT, &marker_sock)
        .context("registering READY-marker vsock port")?;

    tracing::info!(
        port = VSOCK_MARKER_PORT,
        sock = %marker_sock,
        exec = %exec,
        "guest workload + READY-marker vsock port set; calling krun_start_enter"
    );

    // start_enter consumes the context and boots the VM. On success, libkrun
    // exit()s the process with the guest workload's exit code and never
    // returns. On failure it returns a VmError; we surface it as an anyhow
    // error so the parent can observe the child's non-zero exit.
    let err = ctx.start_enter();
    bail!("krun_start_enter returned unexpectedly: {err}");
}
