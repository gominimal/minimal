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

pub mod collect;
pub mod guest;
pub mod net;
pub mod redact;

use collect::DiagPaths;
use diagnostics::{BundleWriter, Redaction};

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

/// Process names (argv0 basenames) that mark a process as one of ours. This is
/// minimal's policy — the *data*; the matching mechanic lives in
/// [`diagnostics::procs`], which takes this list as an argument so the same
/// code serves the daemon-side capture.
const PROCESS_MARKERS: &[&str] = &[
    "min",
    "minimal",
    "minimald",
    "minvmd",
    "__krun-vmm",
    "gvproxy",
];

// The collector-step contract — the deadline, the manifest recording, the
// failure isolation — is `diagnostics::collect_step!`, shared with the daemon
// bundle so the two cannot drift. The CLI takes the silent form: a collector
// failure is already in the manifest and in the summary line `cmd_bug` prints,
// and this binary's tracing goes to the user's terminal.
use diagnostics::collect_step;

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
    // Incident collectors: the wedged-system captures. The mechanics live in
    // `diagnostics`; minimal supplies the marker list and the "host" group.
    collect_step!(
        w,
        "host.process-tree",
        diagnostics::procs::process_tree(&mut w, "host", PROCESS_MARKERS)
    );
    collect_step!(
        w,
        "host.hang-triage",
        diagnostics::procs::hang_triage(&mut w, "host", PROCESS_MARKERS)
    );
    collect_step!(
        w,
        "host.net.listening",
        diagnostics::net::listening_sockets(&mut w, "host")
    );
    collect_step!(
        w,
        "host.net.interfaces",
        diagnostics::net::interfaces(&mut w, "host")
    );
    collect_step!(
        w,
        "host.net.routes",
        diagnostics::net::routes(&mut w, "host")
    );
    collect_step!(w, "host.power", diagnostics::power::power(&mut w, "host"));
    collect_step!(w, "config", collect::config(&mut w, &paths));
    collect_step!(w, "state", collect::state(&mut w, &paths));
    collect_step!(w, "logs", collect::logs(&mut w, &paths));

    // ── Per-provider: files and liveness, then the staged socket probe, then
    // (when the probe handshook and --no-guest wasn't given) the daemon's own
    // bundle over the connection the probe already opened. An unreadable
    // providers dir is an error, not absence.
    let providers_started = std::time::Instant::now();
    let providers = match collect::provider_dirs(&paths.state).await {
        Ok(providers) => {
            if providers.is_empty() {
                w.skip(
                    "providers/",
                    "no provider instances found — no daemon was ever spawned here",
                );
            }
            providers
        }
        Err(e) => {
            w.error(
                "providers".to_string(),
                format!("listing provider dirs: {e}"),
                providers_started.elapsed(),
            );
            Vec::new()
        }
    };
    for (name, dir) in &providers {
        collect_step!(
            w,
            format!("providers.{name}"),
            collect::provider_files(&mut w, name, dir)
        );
        collect_guest(&mut w, &args, name, dir).await;
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

/// Probes one provider's daemon socket and, when it answers, nests the
/// daemon's own bundle; otherwise falls back to the data volume image.
///
/// Never fails: every outcome — including "this collector itself broke" —
/// becomes a manifest record. The download is not wrapped in
/// [`collect_step!`]: it carries its own, longer `--guest-timeout-secs`
/// deadline, since a large bundle over a slow bridge is not a hang.
async fn collect_guest(w: &mut BundleWriter, args: &BugArgs, name: &str, dir: &std::path::Path) {
    // `--no-guest` means "collect host-side state only" — the socket probe
    // handshakes with the daemon (a GetVersion RPC), so it is a guest contact
    // and must be skipped too, not just the bundle download (R7.4).
    let started = std::time::Instant::now();
    if args.no_guest {
        if let Err(e) = guest::record_skipped(w, name, "guest collection skipped: --no-guest").await
        {
            w.error(format!("guest.{name}"), format!("{e:#}"), started.elapsed());
        }
        return;
    }

    let sock = dir.join(paths::SSH_SOCK_FILE);
    let (probe, client) = net::probe_socket(&sock).await;
    collect_step!(
        w,
        format!("providers.{name}.socket-probe"),
        net::add_probe(w, name, &probe)
    );

    let started = std::time::Instant::now();
    let result = match client {
        // The daemon being unreachable is the volume fallback's marquee case:
        // nothing else can say what the guest was doing when it died (R7.5).
        None => match guest::record_skipped(
            w,
            name,
            "guest collection skipped: daemon not reachable (see socket-probe.json)",
        )
        .await
        {
            Ok(()) => guest::volume_fallback(w, name, dir).await,
            err => err,
        },
        Some(mut client) => {
            guest::collect(
                w,
                name,
                dir,
                &mut client,
                Duration::from_secs(args.guest_timeout_secs),
            )
            .await
        }
    };
    if let Err(e) = result {
        w.error(format!("guest.{name}"), format!("{e:#}"), started.elapsed());
    }
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
