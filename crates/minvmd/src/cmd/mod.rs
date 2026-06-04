//! CLI subcommand implementations for `minvmd`.

pub mod boot;
pub mod vmm_child;

/// vsock port used by the VMM child to signal the parent that the guest is up.
///
/// The guest's init writes `READY\n` to this vsock port; libkrun forwards the
/// connection to the host UNIX socket registered by the parent before spawning
/// the VMM child. The parent reads `READY` to confirm boot (R2.4).
///
/// Must match the guest rootfs's READY/agent port. The canonical value is
/// `7350` — both the guest rootfs manifest (`etc/minvmd/manifest`:
/// `vsock_port_ready=7350`) and the reference impl (min-ctl: cold boot to a TCP
/// connection on `127.0.0.1:7350`) use it. The host previously used `9799`,
/// which no guest emits on, so the READY marker never arrived.
pub const VSOCK_MARKER_PORT: u32 = 7350;

/// Environment variable that carries the host-side UNIX socket path for the
/// READY marker from the parent to the VMM child.
pub const MARKER_SOCK_ENV: &str = "MINVMD_MARKER_SOCK";
