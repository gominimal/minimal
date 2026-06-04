//! VM configuration builder.
//!
//! [`VmConfig`] collects the parameters needed to configure a libkrun context
//! (vcpus, RAM, kernel, rootfs). No network device is added in v0.1; gvproxy/
//! TSI integration is tracked in #160.

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
    /// Rootfs directory path.
    pub rootfs_path: PathBuf,
}

impl VmConfig {
    /// Construct a new `VmConfig`.
    #[must_use]
    pub fn new(num_vcpus: u8, ram_mib: u32, kernel_path: PathBuf, rootfs_path: PathBuf) -> Self {
        Self {
            num_vcpus,
            ram_mib,
            kernel_path,
            rootfs_path,
        }
    }

    /// Apply this configuration to an existing libkrun [`Context`][crate::krun::Context].
    ///
    /// Configures vcpus, RAM, kernel (with arch-appropriate format), and
    /// rootfs. No network device is added (R2.5).
    #[cfg(target_os = "macos")]
    pub fn apply(&self, ctx: &mut crate::krun::Context) -> Result<(), crate::error::VmError> {
        ctx.set_vm_config(self.num_vcpus, self.ram_mib)?;
        ctx.set_kernel(
            &self.kernel_path,
            crate::image::kernel_format(),
            None::<&std::path::Path>,
            None,
        )?;
        ctx.set_root(&self.rootfs_path)?;
        // R2.5: no network device in v0.1.
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
            PathBuf::from("/var/lib/alpine"),
        );
        assert_eq!(cfg.num_vcpus, 2);
        assert_eq!(cfg.ram_mib, 512);
        assert_eq!(cfg.kernel_path, PathBuf::from("/boot/Image.gz"));
        assert_eq!(cfg.rootfs_path, PathBuf::from("/var/lib/alpine"));
    }

    #[test]
    fn vm_config_clone() {
        let cfg = VmConfig::new(1, 256, PathBuf::from("/k"), PathBuf::from("/r"));
        let cfg2 = cfg.clone();
        assert_eq!(cfg.num_vcpus, cfg2.num_vcpus);
        assert_eq!(cfg.ram_mib, cfg2.ram_mib);
    }
}
