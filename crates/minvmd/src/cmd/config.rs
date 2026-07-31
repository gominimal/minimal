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

/// Reject a maintenance schedule the guest could not act on.
///
/// `HH:MM` is fixed-width and whitespace-free because it rides the kernel
/// command line, which the kernel splits on whitespace — a malformed value
/// would either be dropped silently or corrupt the boot line, and the user
/// would find out a reboot later by noticing maintenance never ran.
fn validate_maintenance(at: Option<&str>, older_than_secs: Option<u64>) -> Result<()> {
    if let Some(at) = at
        && !crate::cmd::is_valid_maintenance_at(at)
    {
        bail!("--maintenance-at must be HH:MM in 24-hour UTC, e.g. 03:00 (got `{at}`)");
    }
    if let Some(0) = older_than_secs {
        bail!("--maintenance-older-than-secs must be at least 1 (0 would sweep the whole cache)");
    }
    Ok(())
}

/// Run `minvmd config set`: validate, merge into the persisted config, and save.
pub fn run_set(
    vcpus: Option<u8>,
    ram_mib: Option<u32>,
    maintenance_at: Option<String>,
    maintenance_older_than_secs: Option<u64>,
) -> Result<()> {
    if vcpus.is_none()
        && ram_mib.is_none()
        && maintenance_at.is_none()
        && maintenance_older_than_secs.is_none()
    {
        bail!(
            "nothing to set: pass --vcpus, --ram-mib, --maintenance-at, \
             and/or --maintenance-older-than-secs"
        );
    }

    let warnings = validate_resources(vcpus, ram_mib, HostCapacity::probe())?;
    validate_maintenance(maintenance_at.as_deref(), maintenance_older_than_secs)?;

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
    if let Some(at) = maintenance_at {
        cfg.maintenance_at = Some(at);
    }
    if let Some(secs) = maintenance_older_than_secs {
        cfg.maintenance_older_than_secs = Some(secs);
    }
    cfg.write(&dir).context("persisting resource config")?;

    for w in &warnings {
        eprintln!("warning: {w}");
    }
    println!(
        "saved: vcpus={}, ram_mib={}, maintenance_at={}, \
         maintenance_older_than_secs={} (takes effect on next boot)",
        describe(cfg.vcpus, DEFAULT_VM_VCPUS),
        describe(cfg.ram_mib, DEFAULT_VM_RAM_MIB),
        describe(
            cfg.maintenance_at.as_deref(),
            crate::cmd::DEFAULT_MAINTENANCE_AT
        ),
        describe(
            cfg.maintenance_older_than_secs,
            crate::cmd::DEFAULT_MAINTENANCE_OLDER_THAN_SECS
        ),
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
    // Reported as seconds, `0` meaning "no timer", so the shown value matches
    // exactly what `config set` accepts back.
    let at = crate::cmd::effective_maintenance_at();
    let older_than = crate::cmd::effective_maintenance_older_than_secs();
    let at_source = source(
        std::env::var(crate::cmd::MAINTENANCE_AT_ENV).is_ok(),
        cfg.maintenance_at.is_some(),
    );
    let older_than_source = source(
        std::env::var(crate::cmd::MAINTENANCE_OLDER_THAN_ENV).is_ok(),
        cfg.maintenance_older_than_secs.is_some(),
    );

    if json {
        let out = serde_json::json!({
            "vcpus": vcpus,
            "ram_mib": ram_mib,
            "maintenance_at": at,
            "maintenance_older_than_secs": older_than,
            "vcpus_source": vcpus_source,
            "ram_mib_source": ram_source,
            "maintenance_at_source": at_source,
            "maintenance_older_than_secs_source": older_than_source,
        });
        println!("{out}");
    } else {
        println!("vcpus                       = {vcpus} ({vcpus_source})");
        println!("ram_mib                     = {ram_mib} ({ram_source})");
        println!(
            "maintenance_at              = {} ({at_source})",
            at.as_deref().unwrap_or("unscheduled")
        );
        println!("maintenance_older_than_secs = {older_than} ({older_than_source})");
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
    fn a_well_formed_schedule_is_accepted() {
        validate_maintenance(Some("03:00"), Some(14 * 24 * 60 * 60)).expect("valid");
        validate_maintenance(Some("00:00"), None).expect("midnight is valid");
        validate_maintenance(Some("23:59"), None).expect("last minute is valid");
    }

    /// The value rides the kernel command line, which the kernel splits on
    /// whitespace — so a malformed schedule has to be refused here, not
    /// discovered a reboot later by noticing maintenance never ran.
    #[test]
    fn a_malformed_schedule_is_rejected() {
        for bad in ["3:00", "03:0", "24:00", "03:60", "0300", "03 00", "", "3am"] {
            let err =
                validate_maintenance(Some(bad), None).expect_err(&format!("should reject {bad:?}"));
            assert!(err.to_string().contains("HH:MM"), "got: {err}");
        }
    }

    #[test]
    fn zero_retention_is_rejected() {
        let err = validate_maintenance(None, Some(0)).unwrap_err();
        assert!(err.to_string().contains("at least 1"), "got: {err}");
    }

    #[test]
    fn is_valid_maintenance_at_requires_fixed_width_fields() {
        assert!(crate::cmd::is_valid_maintenance_at("03:00"));
        assert!(!crate::cmd::is_valid_maintenance_at("3:00"));
        assert!(!crate::cmd::is_valid_maintenance_at("03:0"));
    }

    #[test]
    fn source_precedence_is_env_then_config_then_default() {
        assert_eq!(source(true, true), "env");
        assert_eq!(source(false, true), "config");
        assert_eq!(source(false, false), "default");
    }
}
