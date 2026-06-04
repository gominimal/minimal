//! `minvmd __krun-vmm` hidden subcommand (R2.3).
//!
//! This is the VMM child process that calls `krun_start_enter`. It is spawned
//! by `minvmd boot` and is not intended to be run directly by users (hence the
//! double-underscore prefix).
//!
//! On macOS:
//! 1. Reads kernel and rootfs from `MINVMD_KERNEL_PATH` / `MINVMD_ROOTFS_PATH`.
//! 2. Reads the READY-marker socket path from `MINVMD_MARKER_SOCK`.
//! 3. Creates and configures a libkrun context.
//! 4. Registers the marker socket as the host-side endpoint for
//!    `VSOCK_MARKER_PORT`: when the guest's init connects to that vsock port
//!    and writes `READY\n`, libkrun forwards the data through to the host
//!    UNIX socket where the parent is listening (R2.4).
//! 5. Calls `krun_start_enter`, which boots the VM. On success libkrun
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
    // Default 2 vcpus and 512 MiB RAM; the boot command may expose these as
    // flags in a future change.
    let cfg = VmConfig::new(2, 512, kernel, rootfs);
    cfg.apply(&mut ctx)
        .context("applying VmConfig to krun context")?;

    // Register the READY-marker vsock port. When the guest's init connects to
    // VSOCK_MARKER_PORT and writes `READY\n`, libkrun forwards the connection
    // to the host UNIX socket at `marker_sock`, where the parent is listening
    // (R2.4).
    ctx.add_vsock_port(VSOCK_MARKER_PORT, &marker_sock)
        .context("registering READY-marker vsock port")?;

    tracing::info!(
        port = VSOCK_MARKER_PORT,
        sock = %marker_sock,
        "READY-marker vsock port registered; calling krun_start_enter"
    );

    // start_enter consumes the context and boots the VM. On success, libkrun
    // exit()s the process with the guest workload's exit code and never
    // returns. On failure it returns a VmError; we surface it as an anyhow
    // error so the parent can observe the child's non-zero exit.
    let err = ctx.start_enter();
    bail!("krun_start_enter returned unexpectedly: {err}");
}
