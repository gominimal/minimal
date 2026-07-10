//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, initramfs, root disk, network mode). The network mode
//! selects how the VM attaches to the per-host gvproxy switch supervised by
//! [`crate::net`] (R1.4, R1.5).

use std::path::PathBuf;

use minimald_rpc::{EgressPolicy, NetworkMode};

use crate::error::VmError;

/// Environment variable selecting the data volume's `sync_mode` (spec R1.9).
/// Accepts `none` / `relaxed` / `full` (case-insensitive), the legacy booleans
/// `false` → none and `true` → relaxed, or the raw libkrun codes `0` / `1` / `2`.
/// Defaults to `relaxed` — libkrun's recommended mode: it honours flush but, on
/// macOS, skips the drive-level sync, bounding the crash data-loss window
/// without the throughput cost of full sync.
pub const DISK_SYNC_ENV: &str = "MINVMD_DISK_SYNC";

/// Environment variable toggling `direct_io` (bypass the host page cache) on the
/// data volume (spec R1.9). Accepts `true` / `1` (any other value is false).
/// Defaults to `false`, correct for guest ext4 (the guest journal and page cache
/// interact poorly with host `O_DIRECT`).
pub const DISK_DIRECT_IO_ENV: &str = "MINVMD_DISK_DIRECT_IO";

/// Which of the spec's deployment models (DM1–DM5) a minvmd host runs under.
///
/// minvmd manages libkrun VMs, which only exist on DM1/DM3/DM4; DM2 is native
/// Linux with no VM boundary. The distinction matters for VM-wide egress
/// (R2.5): a `vm_egress` policy is meaningful only where a VM exists, and is a
/// configuration error on DM2 (see [`VmConfig::validate_for`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    /// macOS + one or more libkrun Linux VMs.
    Dm1,
    /// Native Linux, minimald on the host directly (no VM).
    Dm2,
    /// Native Linux + one or more Linux VMs.
    Dm3,
    /// DM2 + DM3 combined.
    Dm4,
    /// Any of the above with a network-accessible, authenticated minimald.
    Dm5,
}

/// Configuration parameters for a single microVM.
///
/// Build with [`VmConfig::new`] and apply to a libkrun
/// [`Context`][crate::krun::Context] with [`VmConfig::apply`]. The network mode
/// defaults to [`NetworkMode::HostNet`]; override it with
/// [`VmConfig::with_network_mode`].
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub num_vcpus: u8,
    /// RAM in mebibytes.
    pub ram_mib: u32,
    /// Kernel image path.
    pub kernel_path: PathBuf,
    /// Path to the read-only ext4 root disk image (loaded via `krun_add_disk2`
    /// as `/dev/vda`). The initramfs `/init` (minimald) mounts + chroots into it.
    pub rootfs_path: PathBuf,
    /// Initramfs image the kernel boots: it unpacks into a RAM root and runs its
    /// `/init` (minimald as pid-1), instead of booting a block-device root. This
    /// is how minimald is shipped as pid-1 without baking it into the rootfs.
    pub initramfs: PathBuf,
    /// How this VM attaches to the per-host gvproxy switch (R1.5). Defaults to
    /// [`NetworkMode::HostNet`]; an `OwnIp` VM is wired to the switch as a
    /// client via the per-PTask vsock shuttle.
    pub network_mode: NetworkMode,
    /// VM-wide egress policy applied to all traffic from this VM, regardless of
    /// per-PTask mode (R2.5). Only meaningful on a deployment model with a VM
    /// boundary (DM1/DM3/DM4); rejected on DM2 by [`VmConfig::validate_for`].
    /// `None` means no VM-wide egress restriction.
    pub vm_egress: Option<EgressPolicy>,
    /// Path to the per-VM writable data volume image, attached as `/dev/vdb`
    /// via `krun_add_disk3` (spec R1.4). `None` means no data volume is attached
    /// (legacy tmpfs-only boot). Provision the image with
    /// [`crate::volume::ensure_sparse_raw`] before setting this.
    pub data_volume_path: Option<PathBuf>,
}

impl VmConfig {
    /// Construct a new `VmConfig`.
    #[must_use]
    pub fn new(
        num_vcpus: u8,
        ram_mib: u32,
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        initramfs: PathBuf,
    ) -> Self {
        Self {
            num_vcpus,
            ram_mib,
            kernel_path,
            rootfs_path,
            initramfs,
            network_mode: NetworkMode::default(),
            vm_egress: None,
            data_volume_path: None,
        }
    }

    /// Set the VM network mode (R1.5), consuming and returning `self`.
    #[must_use]
    pub fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
        self
    }

    /// Attach a per-VM writable data volume image as `/dev/vdb` (spec R1.4),
    /// consuming and returning `self`. The image must already be provisioned
    /// (see [`crate::volume::ensure_sparse_raw`]).
    #[must_use]
    pub fn with_data_volume(mut self, data_volume_path: PathBuf) -> Self {
        self.data_volume_path = Some(data_volume_path);
        self
    }

    /// Set the VM-wide egress policy (R2.5), consuming and returning `self`.
    #[must_use]
    pub fn with_vm_egress(mut self, vm_egress: EgressPolicy) -> Self {
        self.vm_egress = Some(vm_egress);
        self
    }

    /// Validates this config against the active deployment model (R2.5).
    ///
    /// `vm_egress` is VM-wide egress, meaningful only where a VM boundary exists
    /// (DM1/DM3/DM4). On DM2 (native Linux, minimald on the host with no VM) it
    /// has nothing to apply to and collapses to per-PTask egress (UC3), so a
    /// `vm_egress` set on DM2 is a configuration error rather than a silent
    /// no-op. [`DeploymentMode::Dm5`] does not by itself encode an underlying
    /// model, so it may resolve to DM2 (no VM boundary); `vm_egress` is rejected
    /// there too — fail closed rather than silently accept a policy that might
    /// have nothing to enforce it — until the underlying model is resolved.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::Configuration`] when `vm_egress` is set and `mode` is
    /// [`DeploymentMode::Dm2`] or [`DeploymentMode::Dm5`], or
    /// [`VmError::InvalidEgressSubnet`] when `vm_egress` is accepted for `mode`
    /// but carries an `allow_subnets` entry that is not a valid CIDR prefix.
    pub fn validate_for(&self, mode: DeploymentMode) -> Result<(), VmError> {
        if let Some(vm_egress) = self.vm_egress.as_ref() {
            let reason = match mode {
                DeploymentMode::Dm2 => Some(
                    "VM-wide egress is not applicable on DM2 (native Linux has no VM \
                     boundary); use per-PTask egress instead",
                ),
                DeploymentMode::Dm5 => Some(
                    "VM-wide egress cannot be applied on DM5 until its underlying \
                     deployment model is resolved; DM5 does not by itself guarantee a \
                     VM boundary to enforce it",
                ),
                DeploymentMode::Dm1 | DeploymentMode::Dm3 | DeploymentMode::Dm4 => None,
            };
            if let Some(reason) = reason {
                return Err(VmError::Configuration {
                    what: "vm_egress",
                    reason,
                });
            }
            // vm_egress is accepted for this mode (a VM boundary exists); validate
            // that each allow_subnets entry is a syntactically valid CIDR prefix,
            // mirroring the per-PTask egress check in
            // `sessions::Record::validate_policy`, so a misconfigured subnet is
            // named here rather than failing opaquely when #553's enforcement
            // layer parses it.
            if let Some(bad) = vm_egress.first_invalid_subnet() {
                return Err(VmError::InvalidEgressSubnet {
                    cidr: bad.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Whether this VM joins the per-host gvproxy switch as an own-IP client.
    ///
    /// Only an [`NetworkMode::OwnIp`] VM provisions a tap + relay; `HostNet` and
    /// `NoNet` never attach to the switch (R1.5).
    #[must_use]
    pub fn is_own_ip(&self) -> bool {
        matches!(self.network_mode, NetworkMode::OwnIp)
    }

    /// The tap interface name this VM's own-IP PTask is bridged onto, derived
    /// from `index` so each PTask on a host gets a distinct, deterministic name.
    ///
    /// The name fits the kernel's 15-char `IFNAMSIZ` limit for any `u32` index.
    #[must_use]
    pub fn tap_name(index: u32) -> String {
        format!("vmtap{index}")
    }

    /// Apply this configuration to an existing libkrun [`Context`][crate::krun::Context].
    ///
    /// Configures vcpus, RAM, kernel + initramfs, the ext4 root disk, and the
    /// host UDS↔vsock bridge for minimald (R3.1).
    #[cfg(minvmd_libkrun)]
    pub fn apply(&self, ctx: &mut crate::krun::Context) -> Result<(), crate::error::VmError> {
        ctx.set_vm_config(self.num_vcpus, self.ram_mib)?;

        // Initramfs boot: the kernel unpacks the initramfs into a RAM root and
        // runs its `/init` (no `root=`/`init=` cmdline). minimald-as-/init mounts
        // devtmpfs itself, then mounts the rootfs disk below and chroots into it.
        ctx.set_kernel(
            &self.kernel_path,
            crate::image::kernel_format(),
            Some(&self.initramfs),
            Some("console=hvc0"),
        )?;
        // Attach the rootfs as a block device (/dev/vda) for the initramfs
        // `/init` to mount + chroot into; the kernel root is the initramfs.
        ctx.add_disk(
            "root",
            &self.rootfs_path,
            crate::krun::DiskFormat::Raw,
            true,
        )?;
        // Attach the per-VM writable data volume as /dev/vdb (spec R1.4). Disks
        // are enumerated vd{a,b,…} in registration order, so this follows the
        // read-only root. The sync/cache posture is resolved from the R1.9
        // tunables rather than hardcoded, so its throughput cost can be measured
        // (Proof Artifact 4) and tuned per platform.
        if let Some(data_path) = &self.data_volume_path {
            let (direct_io, sync_mode) = resolve_disk_flags();
            tracing::info!(
                data_path = %data_path.display(),
                direct_io,
                ?sync_mode,
                "attaching writable data volume as /dev/vdb",
            );
            ctx.add_disk_with_sync(
                "data",
                data_path,
                crate::krun::DiskFormat::Raw,
                false,
                direct_io,
                sync_mode,
            )?;
        }
        // Network attachment (R1.5): the VM joins the per-host gvproxy switch
        // supervised by `crate::net` according to `network_mode`. The libkrun
        // device wiring (tap fd handed to gvproxy over the per-PTask vsock
        // shuttle) is driven by the switch handle, not configured here; record
        // the selected mode so a stuck boot can be diagnosed.
        tracing::debug!(network_mode = ?self.network_mode, "VM network mode selected");

        // R3.1: register the host UDS bridge (listen=true). libkrun listens on
        // the host UDS and bridges each accepted connection to the guest process
        // listening on vsock VSOCK_BRIDGE_PORT.
        let uds_path = crate::sock::resolve_uds_path()
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::check_uds_path_len(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::prepare_socket_dir(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        // Drop a stale socket from a prior run; libkrun's listen-bind fails
        // EEXIST otherwise (e.g. on a persistent runner).
        crate::sock::remove_stale_socket(&uds_path)
            .map_err(|source| crate::error::VmError::Io { source })?;
        // R3.5: TSI ~62-concurrent-connection cap. libkrun's TSI layer
        // multiplexes guest vsock connections over a single host transport; the
        // practical ceiling is ~62 concurrent connections on this port before
        // new ones queue. Acceptable for v0.1 workloads (<10 concurrent).
        ctx.add_vsock_port2(crate::sock::VSOCK_BRIDGE_PORT, &uds_path, true)?;

        // gvproxy shuttle bridge (extended to the root netns). The
        // guest connects to AF_VSOCK CID 2 (the host) on
        // VSOCK_GVPROXY_SHUTTLE_PORT; with `listen = false` libkrun dials the
        // host gvproxy `-listen` switch socket and splices the two, carrying raw
        // L2 frames between a guest tap and the host gvproxy (the single gVisor
        // stack). Registered for every VM, not just own-IP: the guest's root
        // netns (the daemon) attaches a primary tap here for egress, and own-IP
        // PTasks attach further taps as additional clients on the same switch.
        // If the host gvproxy did not come up, the guest's connect simply fails
        // and the relay reports no egress — boot is unaffected.
        let switch_sock = crate::net::resolve_switch_sock()
            .map_err(|source| crate::error::VmError::Io { source })?;
        crate::sock::check_uds_path_len(&switch_sock)
            .map_err(|source| crate::error::VmError::Io { source })?;
        ctx.add_vsock_port2(crate::net::VSOCK_GVPROXY_SHUTTLE_PORT, &switch_sock, false)?;
        tracing::info!(
            port = crate::net::VSOCK_GVPROXY_SHUTTLE_PORT,
            switch_sock = %switch_sock.display(),
            "registered gvproxy shuttle vsock bridge",
        );
        Ok(())
    }
}

/// Resolve the data-volume `(direct_io, sync_mode)` from the R1.9 environment
/// tunables ([`DISK_DIRECT_IO_ENV`], [`DISK_SYNC_ENV`]). Defaults: `direct_io =
/// false`, `sync_mode = Relaxed`.
#[cfg(minvmd_libkrun)]
fn resolve_disk_flags() -> (bool, crate::krun::SyncMode) {
    use crate::krun::SyncMode;

    let direct_io = match std::env::var(DISK_DIRECT_IO_ENV) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => true,
            "false" | "0" => false,
            _ => {
                tracing::warn!(
                    env = DISK_DIRECT_IO_ENV,
                    value = %v,
                    "unrecognized value; using default direct_io=false",
                );
                false
            }
        },
        Err(_) => false,
    };

    let sync_mode = match std::env::var(DISK_SYNC_ENV) {
        Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
            "none" | "false" | "0" => SyncMode::None,
            "relaxed" | "true" | "1" => SyncMode::Relaxed,
            "full" | "2" => SyncMode::Full,
            _ => {
                tracing::warn!(
                    env = DISK_SYNC_ENV,
                    value = %v,
                    "unrecognized value; using default sync_mode=relaxed",
                );
                SyncMode::Relaxed
            }
        },
        Err(_) => SyncMode::Relaxed,
    };

    (direct_io, sync_mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_config_stores_fields() {
        let cfg = VmConfig::new(
            2,
            512,
            PathBuf::from("/boot/Image.gz"),
            PathBuf::from("/var/lib/rootfs.img"),
            PathBuf::from("/var/lib/initramfs.cpio"),
        );
        assert_eq!(cfg.num_vcpus, 2);
        assert_eq!(cfg.ram_mib, 512);
        assert_eq!(cfg.kernel_path, PathBuf::from("/boot/Image.gz"));
        assert_eq!(cfg.rootfs_path, PathBuf::from("/var/lib/rootfs.img"));
        assert_eq!(cfg.initramfs, PathBuf::from("/var/lib/initramfs.cpio"));
    }

    #[test]
    fn network_mode_defaults_to_host_net() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert_eq!(cfg.network_mode, NetworkMode::HostNet);
    }

    #[test]
    fn with_network_mode_overrides_default() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_network_mode(NetworkMode::OwnIp);
        assert_eq!(cfg.network_mode, NetworkMode::OwnIp);
        assert!(cfg.is_own_ip());
    }

    #[test]
    fn host_net_and_no_net_are_not_own_ip() {
        let base = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(
            !base
                .clone()
                .with_network_mode(NetworkMode::HostNet)
                .is_own_ip()
        );
        assert!(!base.with_network_mode(NetworkMode::NoNet).is_own_ip());
    }

    #[test]
    fn tap_name_is_deterministic_and_within_ifnamsiz() {
        assert_eq!(VmConfig::tap_name(2), "vmtap2");
        assert_eq!(VmConfig::tap_name(3), "vmtap3");
        assert_ne!(VmConfig::tap_name(2), VmConfig::tap_name(3));
        // Kernel IFNAMSIZ is 16 (15 usable chars); the widest u32 must fit.
        assert!(VmConfig::tap_name(u32::MAX).len() < 16);
    }

    #[test]
    fn vm_egress_defaults_to_none_and_round_trips() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(cfg.vm_egress.is_none());
        let cfg = cfg.with_vm_egress(EgressPolicy::default());
        assert!(cfg.vm_egress.is_some());
    }

    #[test]
    fn vm_egress_is_rejected_on_dm2() {
        // R2.5: VM-wide egress is a configuration error on DM2 (no VM boundary).
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        let err = cfg.validate_for(DeploymentMode::Dm2).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a typed configuration error, got {err:?}"
        );
    }

    #[test]
    fn vm_egress_is_rejected_on_dm5() {
        // R2.5 fail-closed: DM5 does not encode a VM boundary, so a VM-wide
        // egress policy is rejected until the underlying model is resolved.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        let err = cfg.validate_for(DeploymentMode::Dm5).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a typed configuration error, got {err:?}"
        );
    }

    #[test]
    fn vm_egress_is_accepted_on_vm_deployment_models() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy::default());
        // DM1/DM3/DM4 each have a VM boundary, so vm_egress is valid.
        assert!(cfg.validate_for(DeploymentMode::Dm1).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm3).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm4).is_ok());
    }

    #[test]
    fn vm_egress_with_invalid_cidr_is_rejected_on_vm_deployment_models() {
        // vm_egress is accepted on DM1/DM3/DM4, but an allow_subnets entry that is
        // not a valid CIDR prefix is named at config time, mirroring the per-PTask
        // egress check, rather than failing opaquely under #553's enforcement.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "not-a-cidr".into()]),
            ..EgressPolicy::default()
        });
        for mode in [
            DeploymentMode::Dm1,
            DeploymentMode::Dm3,
            DeploymentMode::Dm4,
        ] {
            let err = cfg.validate_for(mode).unwrap_err();
            assert!(
                matches!(&err, VmError::InvalidEgressSubnet { cidr } if cidr == "not-a-cidr"),
                "expected an invalid-egress-subnet error, got {err:?}"
            );
        }
    }

    #[test]
    fn vm_egress_with_valid_cidrs_is_accepted_on_vm_deployment_models() {
        // Both IPv4 and IPv6 CIDR prefixes pass the syntactic check.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["10.0.0.0/8".into(), "fd00::/8".into()]),
            ..EgressPolicy::default()
        });
        assert!(cfg.validate_for(DeploymentMode::Dm1).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm3).is_ok());
        assert!(cfg.validate_for(DeploymentMode::Dm4).is_ok());
    }

    #[test]
    fn vm_egress_with_invalid_cidr_still_rejected_first_by_mode_on_dm2() {
        // On DM2 the mode rejection fires before the CIDR check, so even an
        // invalid-CIDR vm_egress surfaces as the Configuration error, not
        // InvalidEgressSubnet — the mode incompatibility is the dominant fault.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        )
        .with_vm_egress(EgressPolicy {
            allow_subnets: Some(vec!["not-a-cidr".into()]),
            ..EgressPolicy::default()
        });
        let err = cfg.validate_for(DeploymentMode::Dm2).unwrap_err();
        assert!(
            matches!(
                err,
                VmError::Configuration {
                    what: "vm_egress",
                    ..
                }
            ),
            "expected a mode configuration error, got {err:?}"
        );
    }

    #[test]
    fn absent_vm_egress_is_valid_on_dm2() {
        // No vm_egress => nothing to reject, even on DM2.
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        assert!(cfg.validate_for(DeploymentMode::Dm2).is_ok());
    }

    #[test]
    fn vm_config_clone() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            PathBuf::from("/i"),
        );
        let cfg2 = cfg.clone();
        assert_eq!(cfg.num_vcpus, cfg2.num_vcpus);
        assert_eq!(cfg.ram_mib, cfg2.ram_mib);
        assert_eq!(cfg.initramfs, cfg2.initramfs);
    }
}
