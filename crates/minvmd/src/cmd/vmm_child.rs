//! `minvmd __krun-vmm` hidden subcommand (R2.3).
//!
//! This is the VMM child process that calls `krun_start_enter`. It is spawned
//! by `minvmd boot` and is not intended to be run directly by users (hence the
//! double-underscore prefix).
//!
//! On macOS:
//! 1. Reads kernel and rootfs from `MINVMD_KERNEL_PATH` / `MINVMD_ROOTFS_PATH`.
//! 2. Reads the READY-marker socket path from `MINVMD_MARKER_SOCK`.
//! 3. Creates and configures a libkrun context (kernel, rootfs, resources).
//! 4. Sets the guest workload via `krun_set_exec` (libkrun's `/init.krun` runs
//!    as PID 1 and forks it); default `/sbin/minvmd-stub-init`, `MINVMD_EXEC`
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

    let mut ctx = Context::create().context("krun_create_ctx")?;
    // 2 vCPU / 1024 MiB: 512 MiB is the practical floor to reach Alpine
    // userspace; 1024 MiB is cheap headroom under Hypervisor.framework with no
    // boot penalty. (Stay below the kernel's CONFIG_NR_CPUS.) The boot command
    // may expose these as flags in a future change.
    let cfg = VmConfig::new(2, 1024, kernel, rootfs);
    cfg.apply(&mut ctx)
        .context("applying VmConfig to krun context")?;

    // Set the guest workload. libkrun's own init (`/init.krun`) runs as PID 1,
    // mounts /proc,/sys,/dev, reads this target from /.krun_config.json, and
    // forks it — so the rootfs needs no init system, only this binary. Default
    // to the v0.1 bring-up stub; `MINVMD_EXEC` overrides (e.g. /sbin/minimald).
    // Pass an explicit minimal envp (not None): None inherits the full host env
    // into the guest, which can overflow the ~2 KiB aarch64 kernel cmdline.
    let exec =
        std::env::var("MINVMD_EXEC").unwrap_or_else(|_| "/sbin/minvmd-stub-init".to_string());
    let argv: [&str; 0] = [];
    ctx.set_exec(&exec, &argv, Some(&["PATH=/usr/sbin:/usr/bin:/sbin:/bin"]))
        .with_context(|| format!("setting guest exec workload: {exec}"))?;

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
