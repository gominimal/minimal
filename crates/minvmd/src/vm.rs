//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, initramfs, root disk, network mode). The network mode
//! selects how the VM attaches to the per-host gvproxy switch supervised by
//! [`crate::net`] (R1.4, R1.5).

use std::path::PathBuf;

use minimald_rpc::NetworkMode;

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
        }
    }

    /// Set the VM network mode (R1.5), consuming and returning `self`.
    #[must_use]
    pub fn with_network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = network_mode;
        self
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
