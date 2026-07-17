//! `min bug` — collect a diagnostic bundle for the minimal dev team.
//!
//! One command, one artifact: a `minimal-diag-<timestamp>.tar.zst` containing
//! the logs, config (redacted), and state listings needed to root-cause
//! field issues. Every collector is independent and failure-isolated: a
//! fully broken install still yields a valid archive whose `manifest.json`
//! explains what's missing. Nothing here mutates state or autospawns
//! daemons — diagnosing a wedged system must not change it.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;

pub mod collect;
pub mod redact;

use collect::DiagPaths;
use diagnostics::{BundleWriter, Redaction};

use crate::GlobalArgs;

#[derive(Debug, Args)]
pub struct BugArgs {
    /// Output path (default: ./minimal-diag-<timestamp>.tar.zst)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

/// A collector timeout generous enough for slow disks, small enough that a
/// hung collector can't stall the whole run.
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs one collector future with [`COLLECTOR_TIMEOUT`]; failure or timeout
/// is recorded in the manifest and the run continues. A macro (not a
/// function) so the future's borrow of the writer ends before the
/// error-recording arms re-borrow it.
macro_rules! collect_step {
    ($w:expr, $name:expr, $fut:expr) => {{
        let name: String = $name.into();
        let started = std::time::Instant::now();
        let result = tokio::time::timeout(COLLECTOR_TIMEOUT, $fut).await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => $w.error(name, format!("{e:#}"), started.elapsed()),
            Err(_) => $w.error(
                name,
                format!("timed out after {COLLECTOR_TIMEOUT:?}"),
                started.elapsed(),
            ),
        }
    }};
}

pub async fn cmd_bug(global: &GlobalArgs, args: BugArgs) -> Result<(), anyhow::Error> {
    let created_at = chrono::Utc::now();
    let started = std::time::Instant::now();

    let bundle_name = format!("minimal-diag-{}", created_at.format("%Y%m%dT%H%M%SZ"));
    let out_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{bundle_name}.tar.zst")));

    let paths = resolve_paths(global);
    let mut w = BundleWriter::create(&out_path, &bundle_name, version::LONG_VERSION).await?;

    // ── Host-side collectors: independent, each failure becomes a
    // manifest error rather than aborting the run.
    collect_step!(w, "host.system", collect::system(&mut w, &paths));
    collect_step!(w, "host.env", collect::env(&mut w));
    collect_step!(w, "host.dirs", dirs_report(&mut w, global));
    collect_step!(w, "config", collect::config(&mut w, &paths));
    collect_step!(w, "state", collect::state(&mut w, &paths));
    collect_step!(w, "logs", collect::logs(&mut w, &paths));

    // Daemon-side state (socket probes, guest bundles, per-provider status)
    // is collected over the daemon connection, not from the host bundle;
    // record what exists so the manifest is honest about coverage.
    let providers = collect::provider_dirs(&paths.state).await;
    if providers.is_empty() {
        w.skip(
            "providers/",
            "no provider instances found — no daemon was ever spawned here",
        );
    } else {
        w.skip(
            "providers/",
            format!(
                "{} provider instance(s) present — only run.log/boot.log captured; \
                 daemon-side state not collected",
                providers.len()
            ),
        );
    }

    let entries = w.entry_count();
    let errors = w.error_count();
    w.finish(created_at, started.elapsed())
        .await
        .context("finalizing diagnostic bundle")?;

    println!(
        "Wrote {} ({entries} entries, {errors} error{}{})",
        out_path.display(),
        if errors == 1 { "" } else { "s" },
        if errors > 0 {
            " — see manifest.json"
        } else {
            ""
        },
    );
    println!("Review the contents before sharing; send it to the minimal dev team.");
    Ok(())
}

/// Resolve every base path the collectors need, honoring the same overrides
/// (`--minimal-dir`, `--config-dir`) the rest of the CLI uses.
fn resolve_paths(global: &GlobalArgs) -> DiagPaths {
    DiagPaths {
        config: crate::config::resolve_minimal_config_dir(global),
        state: match &global.minimal_dir {
            Some(dir) => dir.clone(),
            None => paths::minimal_state_dir()
                .as_utf8_path()
                .as_std_path()
                .to_path_buf(),
        },
        cache: paths::minimal_cache_dir()
            .as_utf8_path()
            .as_std_path()
            .to_path_buf(),
        mesh_enrolment: crate::mesh_enrolment_path(global),
        cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    }
}

/// The `min dirs` table, captured as `host/dirs.txt`.
async fn dirs_report(w: &mut BundleWriter, global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let report = crate::dirs::report(global);
    w.add_bytes("host/dirs.txt", report.as_bytes(), Redaction::None)
        .await
}
