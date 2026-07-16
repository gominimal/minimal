//! `minvmd config` subcommand (#747, R9.5, R9.6).
//!
//! `config show` prints the effective per-VM resource configuration; `config
//! set` validates resource parameters against host capacity and persists them to
//! `config.toml` for consumption at the next boot (R9.7). Validation rejects
//! structurally invalid values and *warns* (non-fatally) on over-allocation —
//! the proactive half of #747's warnings pillar.

use anyhow::{Context as _, Result, bail};

use crate::cmd::{DEFAULT_VM_RAM_MIB, DEFAULT_VM_VCPUS};
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
        let logical_cores = crate::cmd::host_logical_cores();
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
        let max = crate::cmd::max_vm_vcpus(host.logical_cores);
        if v > max {
            bail!(
                "--vcpus must be at most {max} on this host ({} logical cores minus a \
                 {}-core reserve for the host side)",
                host.logical_cores,
                crate::cmd::VCPU_HOST_RESERVE
            );
        }
        // Reachable only when the DEFAULT_VM_VCPUS floor lifts the ceiling
        // above the core count (tiny hosts); otherwise the ceiling rejects
        // oversubscription before this warning can fire.
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
    // `StateDir::new` creates the provider dir (a `config set` can precede any
    // lifecycle command, so it may not exist yet). Serialize the whole
    // read-modify-write under the shared lifecycle lock so two concurrent
    // `config set`s cannot lose one field's update to a last-writer-wins rename.
    let state_dir = crate::state::StateDir::new(dir.clone()).context("opening state dir")?;
    let mut lock = state_dir
        .lifecycle_lock()
        .context("opening lifecycle lock")?;
    let _guard = lock.write().context("acquiring lifecycle write lock")?;

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
/// source (`env` / `config` / `default`). Values and sources come from the one
/// resolution pass boot itself uses ([`crate::cmd::resolve_resources`]) — a
/// single persisted-config read, so the labels cannot describe a different
/// `config.toml` version than the values, and a malformed file falls back to
/// the defaults (as boot would) instead of failing the one command that could
/// report the fallback.
pub fn run_show(json: bool) -> Result<()> {
    let resolved = crate::cmd::resolve_resources();

    if json {
        let out = serde_json::json!({
            "vcpus": resolved.vcpus,
            "ram_mib": resolved.ram_mib,
            "vcpus_source": resolved.vcpus_source.label(),
            "ram_mib_source": resolved.ram_mib_source.label(),
        });
        println!("{out}");
    } else {
        println!(
            "vcpus   = {} ({})",
            resolved.vcpus,
            resolved.vcpus_source.label()
        );
        println!(
            "ram_mib = {} ({})",
            resolved.ram_mib,
            resolved.ram_mib_source.label()
        );
    }
    Ok(())
}

/// Render a persisted-or-default value for the confirmation line.
fn describe<T: std::fmt::Display>(value: Option<T>, default: impl std::fmt::Display) -> String {
    value.map_or_else(|| format!("{default} (default)"), |v| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // 8 logical cores → a host-derived vcpu ceiling of 6 (cores minus the
    // 2-core host reserve), so the over-ceiling *rejection* is testable.
    const HOST: HostCapacity = HostCapacity {
        logical_cores: 8,
        total_mib: 16384,
    };

    // Small enough that the DEFAULT_VM_VCPUS floor lifts the ceiling above the
    // core count, keeping the oversubscription *warning* path reachable.
    const TINY_HOST: HostCapacity = HostCapacity {
        logical_cores: 1,
        total_mib: 16384,
    };

    #[test]
    fn valid_values_within_capacity_have_no_warnings() {
        let warns = validate_resources(Some(6), Some(8192), HOST).expect("valid");
        assert!(warns.is_empty(), "got: {warns:?}");
    }

    #[test]
    fn zero_vcpus_is_rejected() {
        let err = validate_resources(Some(0), None, HOST).unwrap_err();
        assert!(err.to_string().contains("at least 1"), "got: {err}");
    }

    #[test]
    fn vcpus_over_host_derived_ceiling_is_rejected() {
        let max = crate::cmd::max_vm_vcpus(HOST.logical_cores);
        let err = validate_resources(Some(max + 1), None, HOST).unwrap_err();
        assert!(err.to_string().contains("at most"), "got: {err}");
    }

    #[test]
    fn ram_below_floor_is_rejected() {
        let err = validate_resources(None, Some(256), HOST).unwrap_err();
        assert!(err.to_string().contains("at least 512"), "got: {err}");
    }

    #[test]
    fn over_core_and_over_mem_warn_but_succeed() {
        // 2 vcpus on a 1-core host: within the floored ceiling (2) but above
        // the core count, so it warns instead of rejecting.
        let warns = validate_resources(Some(2), Some(65536), TINY_HOST).expect("warn, not error");
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
        use crate::cmd::ValueSource;

        // Env beats a persisted value; a persisted value beats the default.
        let cfg = ResourceConfig {
            vcpus: Some(2),
            ram_mib: Some(1024),
        };
        let r = crate::cmd::resolve_from(Some(1), None, &cfg);
        assert_eq!(r.vcpus_source, ValueSource::Env);
        assert_eq!(r.vcpus, 1);
        assert_eq!(r.ram_mib_source, ValueSource::Config);
        assert_eq!(r.ram_mib, 1024);

        let r = crate::cmd::resolve_from(None, None, &ResourceConfig::default());
        assert_eq!(r.vcpus_source, ValueSource::Default);
        assert_eq!(r.vcpus, DEFAULT_VM_VCPUS);
        assert_eq!(r.ram_mib_source, ValueSource::Default);
        assert_eq!(r.ram_mib, DEFAULT_VM_RAM_MIB);
    }

    #[test]
    fn source_labels_match_the_show_schema() {
        use crate::cmd::ValueSource;
        assert_eq!(ValueSource::Env.label(), "env");
        assert_eq!(ValueSource::Config.label(), "config");
        assert_eq!(ValueSource::Default.label(), "default");
    }
}
