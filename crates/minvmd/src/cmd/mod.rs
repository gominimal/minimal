//! CLI subcommand implementations for `minvmd`.

pub mod boot;
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

/// Environment variable selecting an own-IP VM. When set to a
/// truthy value (`1`/`true`), the supervisor spawns the host gvproxy switch and
/// the VMM child registers the per-PTask shuttle vsock bridge + sets the VM's
/// network mode to `OwnIp`. Read by both the parent supervisor (to decide
/// whether to spawn gvproxy) and the VMM child (to configure the VM), so the two
/// processes stay consistent. Unset/false ⇒ a `HostNet` VM with no host gvproxy.
pub const OWN_IP_ENV: &str = "MINVMD_VM_OWN_IP";

/// Whether [`OWN_IP_ENV`] requests an own-IP VM.
#[must_use]
pub fn own_ip_requested() -> bool {
    matches!(
        std::env::var(OWN_IP_ENV).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// Verify the host hypervisor backend is accessible before booting a VM (R2.4).
///
/// On Linux, libkrun drives KVM, which needs a readable `/dev/kvm`. Probe it
/// with an `O_RDONLY` open so `boot`/`run` fail fast with an actionable message
/// instead of an opaque libkrun error from `krun_start_enter`. On macOS the
/// check is skipped — Hypervisor.framework availability is verified by
/// `krun_create_ctx` itself.
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

    #[cfg(not(target_os = "linux"))]
    Ok(())
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
