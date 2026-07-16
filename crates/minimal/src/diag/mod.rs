//! `min bug` — collect a diagnostic bundle for the minimal dev team.
//!
//! One command, one artifact: a `minimal-diag-<timestamp>.tar.zst` containing
//! the logs, config (redacted), state listings, process/network state, and
//! per-provider daemon bundles needed to root-cause field issues. Every
//! collector is independent and failure-isolated: a fully broken install
//! still yields a valid archive whose `manifest.json` explains what's
//! missing. Nothing here mutates state or autospawns daemons — diagnosing a
//! wedged system must not change it.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;

pub mod bundle;
pub mod collect;
pub mod guest;
pub mod manifest;
pub mod net;
pub mod procs;
pub mod redact;

use bundle::BundleWriter;
use collect::DiagPaths;
use manifest::Redaction;

use crate::GlobalArgs;

#[derive(Debug, Args)]
pub struct BugArgs {
    /// Output path (default: ./minimal-diag-<timestamp>.tar.zst)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Skip contacting daemons; collect host-side state only
    #[arg(long)]
    pub no_guest: bool,
    /// Deadline in seconds for each provider's daemon-bundle download
    #[arg(long, default_value_t = 60)]
    pub guest_timeout_secs: u64,
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
    let mut w = BundleWriter::create(&out_path, &bundle_name).await?;

    // ── Host-side collectors: independent, each failure becomes a
    // manifest error rather than aborting the run.
    collect_step!(w, "host.system", collect::system(&mut w, &paths));
    collect_step!(w, "host.env", collect::env(&mut w));
    collect_step!(w, "host.dirs", dirs_report(&mut w, global));
    collect_step!(w, "host.process-tree", procs::process_tree(&mut w));
    collect_step!(w, "host.net.listening", net::listening_sockets(&mut w));
    collect_step!(w, "host.net.interfaces", net::interfaces(&mut w));
    collect_step!(w, "host.net.routes", net::routes(&mut w));
    collect_step!(w, "config", collect::config(&mut w, &paths));
    collect_step!(w, "state", collect::state(&mut w, &paths));
    collect_step!(w, "logs", collect::logs(&mut w, &paths));

    // ── Per-provider: files, then the staged socket probe, then (when the
    // probe handshook and --no-guest wasn't given) the daemon's own bundle
    // over the connection the probe already opened.
    let providers = collect::provider_dirs(&paths.state).await;
    if providers.is_empty() {
        w.skip(
            "providers/",
            "no provider instances found — no daemon was ever spawned here",
        );
    }
    for (name, dir) in &providers {
        collect_step!(
            w,
            format!("providers.{name}"),
            collect::provider_files(&mut w, name, dir)
        );

        let sock = dir.join(paths::SSH_SOCK_FILE);
        let (probe, client) = net::probe_socket(&sock).await;
        collect_step!(
            w,
            format!("providers.{name}.socket-probe"),
            net::add_probe(&mut w, name, &probe)
        );

        let guest_started = std::time::Instant::now();
        let guest_result = match (args.no_guest, client) {
            (true, _) => {
                guest::record_skipped(&mut w, name, "guest collection skipped: --no-guest").await
            }
            (false, None) => {
                // The daemon being unreachable is the volume fallback's
                // marquee case: nothing else can say what the guest was
                // doing when it died.
                match guest::record_skipped(
                    &mut w,
                    name,
                    "guest collection skipped: daemon not reachable (see socket-probe.json)",
                )
                .await
                {
                    Ok(()) => guest::volume_fallback(&mut w, name, dir).await,
                    err => err,
                }
            }
            (false, Some(mut client)) => {
                guest::collect(
                    &mut w,
                    name,
                    dir,
                    &mut client,
                    Duration::from_secs(args.guest_timeout_secs),
                )
                .await
            }
        };
        if let Err(e) = guest_result {
            w.error(
                format!("guest.{name}"),
                format!("{e:#}"),
                guest_started.elapsed(),
            );
        }
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
