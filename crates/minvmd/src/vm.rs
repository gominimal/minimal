//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, initramfs, root disk, network mode). The network mode
//! selects how the VM attaches to the per-host gvproxy switch supervised by
//! [`crate::net`] (R1.4, R1.5).

use std::path::PathBuf;

use minimald_rpc::{EgressPolicy, NetworkMode};

use crate::error::VmError;

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
        }
    }

    /// Set the VM network mode (R1.5), consuming and returning `self`.
    #[must_use]
    pub fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
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
    /// [`DeploymentMode::Dm2`] or [`DeploymentMode::Dm5`].
    pub fn validate_for(&self, mode: DeploymentMode) -> Result<(), VmError> {
        if self.vm_egress.is_some() {
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
        Ok(())
    }
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
