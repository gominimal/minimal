//! `minvmd config` subcommand (#747, R9.5, R9.6).
//!
//! `config show` prints the effective per-VM resource configuration; `config
//! set` validates resource parameters against host capacity and persists them to
//! `config.toml` for consumption at the next boot (R9.7). Validation rejects
//! structurally invalid values and *warns* (non-fatally) on over-allocation —
//! the proactive half of #747's warnings pillar.

use anyhow::{Context as _, Result, bail};

use crate::cmd::{DEFAULT_VM_RAM_MIB, DEFAULT_VM_VCPUS, env_ram_mib, env_vcpus};
use crate::config::ResourceConfig;
use crate::state::provider_dir;

/// Minimum guest RAM in MiB; below this the guest cannot reach userspace (see
/// [`crate::cmd::DEFAULT_VM_RAM_MIB`]).
pub const MIN_RAM_MIB: u32 = 512;

/// Host resource capacity used to gate `config set` (R9.6).
#[derive(Debug, Clone, Copy)]
pub struct HostCapacity {
    /// Logical CPU count.
    pub logical_cores: u32,
    /// Total physical memory in MiB.
    pub total_mib: u32,
}

impl HostCapacity {
    /// Probe the host: logical cores via std, total memory via sysinfo.
    #[must_use]
    pub fn probe() -> Self {
        let logical_cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1);
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let total_mib = u32::try_from(sys.total_memory() / (1024 * 1024)).unwrap_or(u32::MAX);
        Self {
            logical_cores,
            total_mib,
        }
    }
}

/// Validate requested resource parameters against `host` (R9.6). Returns the
/// (possibly empty) list of non-fatal over-allocation warnings, or an error for
/// a structurally invalid value. Pure — capacity is injected so it is testable
/// without probing the real host.
fn validate_resources(
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    host: HostCapacity,
) -> Result<Vec<String>> {
    let mut warnings = Vec::new();

    if let Some(v) = vcpus {
        if v == 0 {
            bail!("--vcpus must be at least 1");
        }
        if u32::from(v) > host.logical_cores {
            warnings.push(format!(
                "requested {v} vcpus exceeds the host's {} logical cores; the VM will \
                 oversubscribe and contend for CPU",
                host.logical_cores
            ));
        }
    }

    if let Some(m) = ram_mib {
        if m < MIN_RAM_MIB {
            bail!("--ram-mib must be at least {MIN_RAM_MIB} (the floor to reach userspace)");
        }
        if m > host.total_mib {
            warnings.push(format!(
                "requested {m} MiB RAM exceeds the host's {} MiB of memory; the VM may fail \
                 to boot or thrash",
                host.total_mib
            ));
        }
        // The x86_64 guest RAM must avoid the 32-bit MMIO/PCI hole (~3–4 GiB),
        // which mis-places the initramfs and panics the kernel (see
        // DEFAULT_VM_RAM_MIB). aarch64 has no such low hole.
        #[cfg(target_arch = "x86_64")]
        if (3073..=6143).contains(&m) {
            warnings.push(format!(
                "{m} MiB straddles the x86_64 MMIO hole (~3–4 GiB) and can panic the guest \
                 kernel at boot; use ≤3072 or ≥6144 MiB"
            ));
        }
    }

    Ok(warnings)
}

/// Run `minvmd config set`: validate, merge into the persisted config, and save.
pub fn run_set(vcpus: Option<u8>, ram_mib: Option<u32>) -> Result<()> {
    if vcpus.is_none() && ram_mib.is_none() {
        bail!("nothing to set: pass --vcpus and/or --ram-mib");
    }

    let warnings = validate_resources(vcpus, ram_mib, HostCapacity::probe())?;

    let dir = provider_dir();
    // The provider dir may not exist yet (no boot has run); `StateDir::new`
    // normally creates it, but `config set` can precede any lifecycle command.
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating state dir {}", dir.display()))?;
    let mut cfg = ResourceConfig::read(&dir).context("reading existing resource config")?;
    if let Some(v) = vcpus {
        cfg.vcpus = Some(v);
    }
    if let Some(m) = ram_mib {
        cfg.ram_mib = Some(m);
    }
    cfg.write(&dir).context("persisting resource config")?;

    for w in &warnings {
        eprintln!("warning: {w}");
    }
    println!(
        "saved: vcpus={}, ram_mib={} (takes effect on next boot)",
        describe(cfg.vcpus, DEFAULT_VM_VCPUS),
        describe(cfg.ram_mib, DEFAULT_VM_RAM_MIB),
    );
    Ok(())
}

/// Run `minvmd config show`: print the effective configuration and each value's
/// source (`env` / `config` / `default`).
pub fn run_show(json: bool) -> Result<()> {
    let cfg = ResourceConfig::read(&provider_dir()).context("reading resource config")?;
    let vcpus = crate::cmd::effective_vcpus();
    let ram_mib = crate::cmd::effective_ram_mib();
    let vcpus_source = source(env_vcpus().is_some(), cfg.vcpus.is_some());
    let ram_source = source(env_ram_mib().is_some(), cfg.ram_mib.is_some());

    if json {
        let out = serde_json::json!({
            "vcpus": vcpus,
            "ram_mib": ram_mib,
            "vcpus_source": vcpus_source,
            "ram_mib_source": ram_source,
        });
        println!("{out}");
    } else {
        println!("vcpus   = {vcpus} ({vcpus_source})");
        println!("ram_mib = {ram_mib} ({ram_source})");
    }
    Ok(())
}

/// Render a persisted-or-default value for the confirmation line.
fn describe<T: std::fmt::Display>(value: Option<T>, default: impl std::fmt::Display) -> String {
    value.map_or_else(|| format!("{default} (default)"), |v| v.to_string())
}

/// Which layer supplied the effective value: env override, persisted config, or
/// the built-in default (matching [`crate::cmd::effective_ram_mib`] precedence).
fn source(from_env: bool, from_config: bool) -> &'static str {
    if from_env {
        "env"
    } else if from_config {
        "config"
    } else {
        "default"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: HostCapacity = HostCapacity {
        logical_cores: 8,
        total_mib: 16384,
    };

    #[test]
    fn valid_values_within_capacity_have_no_warnings() {
        let warns = validate_resources(Some(4), Some(8192), HOST).expect("valid");
        assert!(warns.is_empty(), "got: {warns:?}");
    }

    #[test]
    fn zero_vcpus_is_rejected() {
        let err = validate_resources(Some(0), None, HOST).unwrap_err();
        assert!(err.to_string().contains("at least 1"), "got: {err}");
    }

    #[test]
    fn ram_below_floor_is_rejected() {
        let err = validate_resources(None, Some(256), HOST).unwrap_err();
        assert!(err.to_string().contains("at least 512"), "got: {err}");
    }

    #[test]
    fn over_core_and_over_mem_warn_but_succeed() {
        let warns = validate_resources(Some(64), Some(65536), HOST).expect("warn, not error");
        assert!(
            warns.iter().any(|w| w.contains("vcpus")),
            "expected an over-core warning: {warns:?}"
        );
        assert!(
            warns.iter().any(|w| w.contains("memory")),
            "expected an over-memory warning: {warns:?}"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_mmio_hole_range_warns() {
        let warns = validate_resources(None, Some(4096), HOST).expect("warn, not error");
        assert!(
            warns.iter().any(|w| w.contains("MMIO hole")),
            "expected an MMIO-hole warning: {warns:?}"
        );
    }

    #[test]
    fn source_precedence_is_env_then_config_then_default() {
        assert_eq!(source(true, true), "env");
        assert_eq!(source(false, true), "config");
        assert_eq!(source(false, false), "default");
    }
}
