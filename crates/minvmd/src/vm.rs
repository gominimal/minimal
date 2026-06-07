//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, root disk, exec target). No network device is added in
//! v0.1; gvproxy/TSI integration is tracked in #160.

use std::path::PathBuf;

/// Configuration parameters for a single microVM.
///
/// Build with [`VmConfig::new`] and apply to a libkrun
/// [`Context`][crate::krun::Context] with [`VmConfig::apply`].
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub num_vcpus: u8,
    /// RAM in mebibytes.
    pub ram_mib: u32,
    /// Kernel image path.
    pub kernel_path: PathBuf,
    /// Path to the read-only ext4 root disk image (loaded via `krun_add_disk2`
    /// as `/dev/vda`).
    pub rootfs_path: PathBuf,
    /// Guest workload run as the kernel `init=` (a block root has no libkrun
    /// `/init.krun`, so the kernel execs this directly as PID 1).
    pub exec_target: String,
    /// Optional persistent writable data disk, attached rw as `/dev/vdb`. The
    /// guest (minimald) formats it on first boot and mounts it for its session
    /// store + SSH host key (the root is read-only). `None` = no data disk.
    pub data_disk: Option<PathBuf>,
}

impl VmConfig {
    /// Construct a new `VmConfig`.
    #[must_use]
    pub fn new(
        num_vcpus: u8,
        ram_mib: u32,
        kernel_path: PathBuf,
        rootfs_path: PathBuf,
        exec_target: String,
    ) -> Self {
        Self {
            num_vcpus,
            ram_mib,
            kernel_path,
            rootfs_path,
            exec_target,
            data_disk: None,
        }
    }

    /// Attach a persistent writable data disk (rw `/dev/vdb`). Off by default.
    #[must_use]
    pub fn with_data_disk(mut self, path: PathBuf) -> Self {
        self.data_disk = Some(path);
        self
    }

    /// Apply this configuration to an existing libkrun [`Context`][crate::krun::Context].
    ///
    /// Configures vcpus, RAM, kernel + cmdline, the ext4 root disk, and the host
    /// UDS↔vsock bridge for minimald (R3.1).
    #[cfg(target_os = "macos")]
    pub fn apply(&self, ctx: &mut crate::krun::Context) -> Result<(), crate::error::VmError> {
        ctx.set_vm_config(self.num_vcpus, self.ram_mib)?;

        // Boot from a read-only ext4 disk image (krun_add_disk2 → /dev/vda)
        // rather than a virtiofs directory. A block root has no libkrun
        // `/init.krun`, so the kernel runs the guest workload directly via an
        // explicit `init=` cmdline (libkrun's virtiofs-only default cmdline does
        // not apply). devtmpfs auto-mounts /dev in the guest, giving the
        // workload /dev/vsock for the READY marker and bridge.
        let cmdline = format!(
            "console=hvc0 root=/dev/vda rootfstype=ext4 ro init={}",
            self.exec_target
        );
        ctx.set_kernel(
            &self.kernel_path,
            crate::image::kernel_format(),
            None::<&std::path::Path>,
            Some(&cmdline),
        )?;
        ctx.add_disk(
            "root",
            &self.rootfs_path,
            crate::krun::KRUN_DISK_FORMAT_RAW,
            true,
        )?;
        // Optional writable data disk, added second so it enumerates as
        // /dev/vdb (read_only = false). The guest formats + mounts it.
        if let Some(data) = &self.data_disk {
            ctx.add_disk("data", data, crate::krun::KRUN_DISK_FORMAT_RAW, false)?;
        }
        // R2.5: no network device in v0.1.

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
            "/sbin/minvmd-stub-init".to_string(),
        );
        assert_eq!(cfg.num_vcpus, 2);
        assert_eq!(cfg.ram_mib, 512);
        assert_eq!(cfg.kernel_path, PathBuf::from("/boot/Image.gz"));
        assert_eq!(cfg.rootfs_path, PathBuf::from("/var/lib/rootfs.img"));
        assert_eq!(cfg.exec_target, "/sbin/minvmd-stub-init");
    }

    #[test]
    fn vm_config_clone() {
        let cfg = VmConfig::new(
            1,
            256,
            PathBuf::from("/k"),
            PathBuf::from("/r"),
            "/sbin/init".to_string(),
        );
        let cfg2 = cfg.clone();
        assert_eq!(cfg.num_vcpus, cfg2.num_vcpus);
        assert_eq!(cfg.ram_mib, cfg2.ram_mib);
        assert_eq!(cfg.exec_target, cfg2.exec_target);
    }
}
