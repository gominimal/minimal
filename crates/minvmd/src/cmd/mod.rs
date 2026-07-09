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

/// The guest RAM size in MiB, overridable via [`VM_RAM_MIB_ENV`]. A non-numeric,
/// empty, or zero value falls back to [`DEFAULT_VM_RAM_MIB`].
///
/// Note: the RAM stop-gap is *not* reduced when the cache moves to the writable
/// volume. A reduced baseline is only safe once a failed volume mount is fatal
/// (no silent tmpfs fallback) and the floor is measured against real in-VM build
/// memory pressure; reducing it here would leave a mount-failed VM at half RAM
/// with the cache still on the tmpfs. Out of scope for this feature — deferred to
/// a separate memory-pressure spec.
#[must_use]
pub fn vm_ram_mib() -> u32 {
    std::env::var(VM_RAM_MIB_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|&mib| mib > 0)
        .unwrap_or(DEFAULT_VM_RAM_MIB)
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

/// Returns the path to the VM SSH known_hosts file:
/// `<provider dir>/known_hosts`.
#[cfg(minvmd_libkrun)]
pub(crate) fn default_vm_known_hosts_path() -> std::path::PathBuf {
    crate::state::provider_dir().join("known_hosts")
}

/// Read the READY beacon from `reader` and, if a valid SSH public key is on
/// the second line, record it in `known_hosts_path` (R2.1–R2.4).
///
/// Returns `Err` only when the first line is not `READY`. Key parse failures
/// and known_hosts write errors are logged as warnings and do not abort boot
/// (R2.3).
#[cfg(any(minvmd_libkrun, test))]
pub(crate) fn read_ready_beacon<R: std::io::BufRead>(
    reader: &mut R,
    known_hosts_path: &std::path::Path,
) -> Result<(), String> {
    use std::io::BufRead;
    let mut line = String::new();
    // Use UFCS so Rust resolves `Self = &mut R` (not `R`) in the function-call
    // context, producing Take<&mut R> without a move out of the mutable reference.
    std::io::Read::take(reader.by_ref(), 32)
        .read_line(&mut line)
        .map_err(|e| format!("reading READY marker: {e}"))?;
    let trimmed = line.trim();
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
                return Ok(());
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
                    return Ok(());
                }
                // R2.2: parse and record the key.
                match russh::keys::ssh_key::PublicKey::from_openssh(key_str) {
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse SSH host key from beacon");
                    }
                    Ok(pubkey) => {
                        match russh::keys::known_hosts::learn_known_hosts_path(
                            // TODO: pass instance_num through once multi-instance is needed
                            "local-0",
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

    Ok(())
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
        let known_hosts_path = tmp.path().join("known_hosts");

        read_ready_beacon(&mut reader, &known_hosts_path)
            .expect("read_ready_beacon must succeed with valid beacon");

        let contents =
            std::fs::read_to_string(&known_hosts_path).expect("known_hosts file must be created");
        assert!(
            contents.contains("local-0"),
            "known_hosts must contain 'local-0', got: {contents:?}"
        );
        assert!(
            contents.contains(&openssh),
            "known_hosts must contain the beacon public key, got: {contents:?}"
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
}
