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
use diagnostics::{BundleWriter, LOG_TAIL_CAP, MAX_LOG_TAIL_BYTES, Redaction};

use crate::GlobalArgs;

#[derive(Debug, Args)]
pub struct BugArgs {
    /// Output path (default: ./minimal-diag-<timestamp>.tar.zst)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Bytes of each log file to capture, counted from the end
    ///
    /// Raise this when the interesting window is older than the tail the
    /// default buys you. A daemon running at `RUST_LOG=debug` fills 5 MiB in
    /// minutes, and the current day's file is not size-rotated, so the
    /// default tail can start well after the incident.
    #[arg(long, default_value_t = LOG_TAIL_CAP, value_parser = parse_log_tail_bytes)]
    pub log_tail_bytes: u64,
}

/// Parses `--log-tail-bytes`, refusing anything the bundle writer cannot
/// honor.
///
/// Refusing rather than clamping is the point. A clamp reports success while
/// quietly capturing less than was asked for, so the resulting short log
/// reads as a fact about the system instead of a fact about the flag — the
/// exact shape of mistake that makes a diagnostic bundle actively misleading.
fn parse_log_tail_bytes(raw: &str) -> Result<u64, String> {
    let bytes: u64 = raw
        .parse()
        .map_err(|_| format!("`{raw}` is not a whole number of bytes"))?;
    match bytes {
        0 => Err("must be at least 1 byte; 0 would collect empty log files".to_string()),
        b if b > MAX_LOG_TAIL_BYTES => Err(format!(
            "{b} exceeds the maximum of {MAX_LOG_TAIL_BYTES} bytes ({} MiB)",
            MAX_LOG_TAIL_BYTES / (1024 * 1024)
        )),
        b => Ok(b),
    }
}

/// A collector timeout generous enough for slow disks, small enough that a
/// hung collector can't stall the whole run.
const COLLECTOR_TIMEOUT: Duration = Duration::from_secs(30);

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
    collect_step!(
        w,
        "logs",
        collect::logs(&mut w, &paths, args.log_tail_bytes)
    );

    // Daemon-side state (socket probes, guest bundles, per-provider status)
    // is collected over the daemon connection, not from the host bundle;
    // record what exists so the manifest is honest about coverage. An
    // unreadable providers dir is an error, not absence.
    let providers_started = std::time::Instant::now();
    match collect::provider_dirs(&paths.state).await {
        Ok(providers) if providers.is_empty() => w.skip(
            "providers/",
            "no provider instances found — no daemon was ever spawned here",
        ),
        Ok(providers) => w.skip(
            "providers/",
            format!(
                "{} provider instance(s) present — only run.log/boot.log captured; \
                 daemon-side state not collected",
                providers.len()
            ),
        ),
        Err(e) => w.error(
            "providers".to_string(),
            format!("listing provider dirs: {e}"),
            providers_started.elapsed(),
        ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    /// Parses `min bug`'s arguments the way the real CLI does, so these
    /// assertions cover the `value_parser` wiring and not just the function.
    #[derive(Debug, clap::Parser)]
    struct Harness {
        #[command(flatten)]
        args: BugArgs,
    }

    fn parse(argv: &[&str]) -> Result<BugArgs, clap::Error> {
        Harness::try_parse_from(std::iter::once("bug").chain(argv.iter().copied())).map(|h| h.args)
    }

    #[test]
    fn omitting_the_flag_keeps_the_historical_tail() {
        assert_eq!(parse(&[]).unwrap().log_tail_bytes, LOG_TAIL_CAP);
    }

    #[test]
    fn a_cap_within_the_contract_is_accepted_verbatim() {
        for bytes in [1, LOG_TAIL_CAP, MAX_LOG_TAIL_BYTES] {
            let args = parse(&["--log-tail-bytes", &bytes.to_string()]).unwrap();
            assert_eq!(args.log_tail_bytes, bytes, "{bytes} must survive intact");
        }
    }

    /// The whole point of the flag's validation: an over-large cap fails the
    /// command rather than being quietly reduced to the ceiling.
    #[test]
    fn an_over_large_cap_is_rejected_not_clamped() {
        for bytes in [MAX_LOG_TAIL_BYTES + 1, u64::MAX] {
            let Err(err) = parse(&["--log-tail-bytes", &bytes.to_string()]) else {
                panic!("{bytes} is above the ceiling and must be rejected, not clamped");
            };
            let err = err.to_string();
            assert!(
                err.contains(&MAX_LOG_TAIL_BYTES.to_string()) && err.contains("exceeds"),
                "the error must name the ceiling it broke: {err}"
            );
        }
    }

    #[test]
    fn a_zero_or_non_numeric_cap_is_rejected() {
        // 0 is the wire contract's "use the default" sentinel; taken
        // literally here it would bundle empty logs labelled tail-capped.
        assert!(parse(&["--log-tail-bytes", "0"]).is_err());
        assert!(parse(&["--log-tail-bytes", "5MiB"]).is_err());
        assert!(parse(&["--log-tail-bytes", "-1"]).is_err());
    }
}
