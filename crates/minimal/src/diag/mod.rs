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
pub mod project;
pub mod redact;

use collect::DiagPaths;
use diagnostics::{BundleWriter, LOG_TAIL_CAP, MAX_LOG_TAIL_BYTES, Redaction};

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
    /// Bytes of each log file to capture, counted from the end
    ///
    /// Raise this when the interesting window is older than the tail the
    /// default buys you. A daemon at `RUST_LOG=debug` can outrun any cap —
    /// most of that volume is dependency chatter, not minimal's own records —
    /// and the current day's file is not size-rotated, so a fixed tail can
    /// start well after the incident.
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
    // Both names: `gvproxy-min` is what an install stamps into `bin/` (see
    // `switch::GVPROXY_FILE`); a dev checkout and a system package still run
    // the binary under its upstream name.
    "gvproxy-min",
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
    collect_step!(w, "host.terminal", collect::terminal(&mut w));
    collect_step!(w, "host.env", collect::env(&mut w));
    collect_step!(w, "host.dirs", dirs_report(&mut w, global));
    // Which project this bundle is *about*. Runs early: it sets the
    // manifest's project scope, and a bundle that cannot be attributed to a
    // project is the failure this collector exists to prevent (#1211).
    collect_step!(
        w,
        "project",
        project::project(&mut w, &paths.cwd, global.repo_dir.as_deref())
    );
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
    collect_step!(
        w,
        "host.panic-report",
        diagnostics::power::panic_report(&mut w, "host")
    );
    collect_step!(w, "config", collect::config(&mut w, &paths));
    collect_step!(w, "state", collect::state(&mut w, &paths));
    // Log prefixes that matched nothing on the host come back rather than
    // becoming skips here: whether "not under <state>/logs" also means "not in
    // this bundle" is not known until the provider loop below has run.
    let mut absent_log_prefixes = Vec::new();
    collect_step!(
        w,
        "logs",
        collect::logs(
            &mut w,
            &paths,
            args.log_tail_bytes,
            &mut absent_log_prefixes
        )
    );

    // ── Per-provider: files and liveness, then the staged socket probe, then
    // (when the probe handshook and --no-guest wasn't given) the daemon's own
    // bundle over the connection the probe already opened. An unreadable
    // providers dir is an error, not absence.
    let providers_started = std::time::Instant::now();
    // `None` is "the listing failed", which is not the same fact as an empty
    // listing: one leaves provider existence unknown, the other settles it.
    // The log skips below turn on that difference.
    let providers = match collect::provider_dirs(&paths.state).await {
        Ok(providers) => {
            if providers.is_empty() {
                w.skip(
                    "providers/",
                    "no provider instances found — no daemon was ever spawned here",
                );
            }
            Some(providers)
        }
        Err(e) => {
            w.error(
                "providers".to_string(),
                format!("listing provider dirs: {e}"),
                providers_started.elapsed(),
            );
            None
        }
    };
    let mut carriers: Vec<&str> = Vec::new();
    let mut unconfirmed: Vec<&str> = Vec::new();
    for (name, dir) in providers.iter().flatten() {
        collect_step!(
            w,
            format!("providers.{name}"),
            collect::provider_files(&mut w, name, dir)
        );
        match collect_guest(&mut w, &args, name, dir).await {
            guest::GuestOutcome::BundleWithDaemonLogs => carriers.push(name),
            guest::GuestOutcome::BundleUnconfirmed => unconfirmed.push(name),
            guest::GuestOutcome::NoBundle => {}
        }
    }

    // The held-back log skips, now that the guest side has reported. A daemon
    // that logs inside the microVM leaves nothing under `<state>/logs`, and
    // saying so as plain absence would contradict the nested bundle this run
    // just collected.
    collect::explain_absent_log_prefixes(
        &mut w,
        &paths,
        &absent_log_prefixes,
        daemon_log_sources(providers.as_deref(), &carriers, &unconfirmed),
    );

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

/// Reduces what the provider loop learned to the single fact the held-back log
/// skips are read against.
///
/// `providers` is `None` when the listing itself failed. A confirmed carrier
/// outranks an unconfirmed one: if any nested bundle demonstrably holds the
/// daemon's logs, naming it is true whatever the others managed.
fn daemon_log_sources<'a>(
    providers: Option<&[(String, PathBuf)]>,
    carriers: &'a [&'a str],
    unconfirmed: &'a [&'a str],
) -> collect::DaemonLogSources<'a> {
    match (providers, carriers, unconfirmed) {
        (None, ..) => collect::DaemonLogSources::ProvidersUnknown,
        (Some([]), ..) => collect::DaemonLogSources::NoProviders,
        (Some(_), [], []) => collect::DaemonLogSources::NoneFetched,
        (Some(_), [], names) => collect::DaemonLogSources::NestedUnconfirmed(names),
        (Some(_), names, _) => collect::DaemonLogSources::Nested(names),
    }
}

/// Probes one provider's daemon socket and, when it answers, nests the
/// daemon's own bundle; otherwise falls back to the data volume image.
///
/// Never fails: every outcome — including "this collector itself broke" —
/// becomes a manifest record. The download is not wrapped in
/// [`collect_step!`]: it carries its own, longer `--guest-timeout-secs`
/// deadline, since a large bundle over a slow bridge is not a hang.
///
/// Returns what the archive can now be said to hold for this provider, which
/// is what the log collector's held-back skips are read against: not merely
/// whether a bundle arrived, but whether it was confirmed to carry the
/// daemon's own logs.
async fn collect_guest(
    w: &mut BundleWriter,
    args: &BugArgs,
    name: &str,
    dir: &std::path::Path,
) -> guest::GuestOutcome {
    // `--no-guest` means "collect host-side state only" — the socket probe
    // handshakes with the daemon (a GetVersion RPC), so it is a guest contact
    // and must be skipped too, not just the bundle download (R7.4).
    let started = std::time::Instant::now();
    if args.no_guest {
        if let Err(e) = guest::record_skipped(w, name, "guest collection skipped: --no-guest").await
        {
            w.error(format!("guest.{name}"), format!("{e:#}"), started.elapsed());
        }
        return guest::GuestOutcome::NoBundle;
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
            Ok(()) => guest::volume_fallback(w, name, dir)
                .await
                .map(|()| guest::GuestOutcome::NoBundle),
            Err(e) => Err(e),
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
    result.unwrap_or_else(|e| {
        w.error(format!("guest.{name}"), format!("{e:#}"), started.elapsed());
        guest::GuestOutcome::NoBundle
    })
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
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt as _;
    use tokio_stream::StreamExt as _;

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

    /// The flag tracks the shared default rather than restating it, so
    /// raising `LOG_TAIL_CAP` raises what an unflagged `min bug` collects.
    #[test]
    fn omitting_the_flag_uses_the_shared_default() {
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

    // ── cmd_bug integration tests ─────────────────────────────────────────

    /// Unpacks a written bundle to `bundle-relative path -> contents`.
    ///
    /// `cmd_bug` writes entries under a single top-level directory (the
    /// timestamped bundle name), so the first path component is stripped to
    /// yield the collector-relative keys the assertions use. The `root`
    /// parameter is accepted for symmetry with the `collect.rs` helper but is
    /// not used: the bundle name is timestamped and unknown to the caller.
    async fn unpack(out: &std::path::Path, _root: &str) -> BTreeMap<String, Vec<u8>> {
        let bytes = tokio::fs::read(out).await.unwrap();
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]);
        let mut entries = async_tar::Archive::new(decoder).entries().unwrap();
        let mut files = BTreeMap::new();
        while let Some(entry) = entries.next().await {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).await.unwrap();
            // Drop the leading `<bundle-name>/` component.
            let key = path
                .split_once('/')
                .map(|(_, rest)| rest.to_string())
                .unwrap_or(path);
            files.insert(key, contents);
        }
        files
    }

    /// `cmd_bug` with `--no-guest` produces a valid bundle with a manifest
    /// and the expected host-side collectors.
    #[tokio::test]
    async fn cmd_bug_no_guest_produces_valid_bundle() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("manifest.json"),
            "bundle must contain manifest.json"
        );
        assert!(
            files.contains_key("host/system.json"),
            "bundle must contain host/system.json"
        );
        assert!(
            files.contains_key("host/terminal.json"),
            "bundle must contain host/terminal.json"
        );
        assert!(
            files.contains_key("host/env.json"),
            "bundle must contain host/env.json"
        );
        assert!(
            files.contains_key("host/dirs.txt"),
            "bundle must contain host/dirs.txt"
        );
        assert!(
            files.contains_key("project/project.json"),
            "bundle must contain project/project.json"
        );

        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        assert_eq!(manifest["schema_version"], 1);
        assert!(manifest["duration_ms"].as_u64().unwrap() > 0);
        assert!(manifest["collected"].as_array().unwrap().len() > 0);
    }

    /// `cmd_bug` with `--no-guest` records the skip reason in the manifest.
    #[tokio::test]
    async fn cmd_bug_no_guest_records_skip() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let skipped = manifest["skipped"].as_array().unwrap();
        let guest_skip = skipped
            .iter()
            .find(|s| s["what"].as_str().unwrap().starts_with("providers/"))
            .or_else(|| {
                skipped
                    .iter()
                    .find(|s| s["reason"].as_str().unwrap().contains("no-guest"))
            });
        assert!(
            guest_skip.is_some(),
            "manifest must record that guest collection was skipped: {skipped:?}"
        );
    }

    /// `cmd_bug` with a state dir that has a `logs/` directory collects log
    /// tails.
    #[tokio::test]
    async fn cmd_bug_collects_log_tails_when_log_dir_exists() {
        let state = tempfile::TempDir::new().unwrap();
        let log_dir = state.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("minimald.log"), b"daemon log content\n").unwrap();
        std::fs::write(log_dir.join("minvmd.log"), b"vmm log content\n").unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("logs/minimald.log"),
            "bundle must contain minimald.log"
        );
        assert!(
            files.contains_key("logs/minvmd.log"),
            "bundle must contain minvmd.log"
        );
        assert_eq!(
            &files["logs/minimald.log"][..],
            b"daemon log content\n",
            "log content must be captured verbatim"
        );
    }

    /// `cmd_bug` with a missing log directory records the absence as a skip,
    /// not an error.
    #[tokio::test]
    async fn cmd_bug_missing_log_dir_is_skip_not_error() {
        let state = tempfile::TempDir::new().unwrap();
        // No logs/ directory at all.

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let skipped = manifest["skipped"].as_array().unwrap();
        let log_skip = skipped
            .iter()
            .find(|s| s["what"].as_str().unwrap() == "logs/");
        assert!(
            log_skip.is_some(),
            "missing log dir must be recorded as a skip: {skipped:?}"
        );
        assert!(
            log_skip.unwrap()["reason"]
                .as_str()
                .unwrap()
                .contains("no log directory"),
            "skip reason must explain absence"
        );
    }

    /// `cmd_bug` with a state dir that has provider directories records
    /// provider files.
    #[tokio::test]
    async fn cmd_bug_collects_provider_files() {
        let state = tempfile::TempDir::new().unwrap();
        let providers_dir = state.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&providers_dir).unwrap();
        // A minvmd.toml so the provider-files collector has something to
        // read.
        std::fs::write(
            providers_dir.join("minvmd.toml"),
            b"state = \"running\"\npid = 42\n",
        )
        .unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("providers/local-minvmd0/dir-listing.txt"),
            "bundle must contain provider dir listing"
        );
        assert!(
            files.contains_key("providers/local-minvmd0/minvmd.toml"),
            "bundle must contain minvmd.toml"
        );
    }

    /// `cmd_bug` with a state dir that has no providers records the absence
    /// as a skip.
    #[tokio::test]
    async fn cmd_bug_no_providers_is_skip() {
        let state = tempfile::TempDir::new().unwrap();
        // No providers/ directory.

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let skipped = manifest["skipped"].as_array().unwrap();
        let providers_skip = skipped
            .iter()
            .find(|s| s["what"].as_str().unwrap() == "providers/");
        assert!(
            providers_skip.is_some(),
            "no providers must be recorded as a skip: {skipped:?}"
        );
    }

    /// `cmd_bug` with `--no-guest` records the skip for each provider.
    #[tokio::test]
    async fn cmd_bug_no_guest_records_per_provider_skip() {
        let state = tempfile::TempDir::new().unwrap();
        let providers_dir = state.path().join("providers").join("local-minvmd0");
        std::fs::create_dir_all(&providers_dir).unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("providers/local-minvmd0/guest/error.txt"),
            "bundle must contain guest skip record"
        );
        let error_txt =
            String::from_utf8(files["providers/local-minvmd0/guest/error.txt"].clone()).unwrap();
        assert!(
            error_txt.contains("no-guest"),
            "guest skip must mention --no-guest: {error_txt}"
        );
    }

    /// `cmd_bug` with `--log-tail-bytes` set to a small value tail-caps
    /// large log files.
    #[tokio::test]
    async fn cmd_bug_tail_caps_large_logs() {
        let state = tempfile::TempDir::new().unwrap();
        let log_dir = state.path().join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        // Write a log file larger than the cap.
        let content = vec![b'A'; 2048];
        std::fs::write(log_dir.join("minimald.log"), &content).unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: 1024,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        let log_contents = &files["logs/minimald.log"];
        assert_eq!(
            log_contents.len(),
            1024,
            "log must be tail-capped to 1024 bytes"
        );
        // The tail of the file (last 1024 bytes of all 'A's).
        assert!(
            log_contents.iter().all(|&b| b == b'A'),
            "tail-capped content must be the last bytes of the file"
        );

        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let collected = manifest["collected"].as_array().unwrap();
        let log_entry = collected
            .iter()
            .find(|e| e["path"].as_str().unwrap() == "logs/minimald.log")
            .unwrap();
        assert_eq!(
            log_entry["redaction"].as_str().unwrap(),
            "tail-capped",
            "large log must be marked tail-capped"
        );
    }

    /// `cmd_bug` with a config dir that has a `config.toml` collects it
    /// redacted. `--config-dir` names the *parent* of the `minimal/`
    /// subdirectory, so the file lives at `<config-dir>/minimal/config.toml`.
    #[tokio::test]
    async fn cmd_bug_collects_config_redacted() {
        let state = tempfile::TempDir::new().unwrap();
        let config_parent = state.path().join("config");
        let config_dir = config_parent.join("minimal");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.toml"),
            b"token = \"secret-value\"\n",
        )
        .unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            config_dir: Some(config_parent),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("config/config.toml.redacted"),
            "bundle must contain redacted config"
        );
        let redacted = String::from_utf8(files["config/config.toml.redacted"].clone()).unwrap();
        assert!(
            !redacted.contains("secret-value"),
            "redacted config must not contain the secret: {redacted}"
        );
    }

    /// `cmd_bug` with a state dir that has a `state/` subdirectory collects
    /// a state listing.
    #[tokio::test]
    async fn cmd_bug_collects_state_listing() {
        let state = tempfile::TempDir::new().unwrap();
        // Create a minimal state structure.
        std::fs::create_dir_all(state.path().join("sessions")).unwrap();
        std::fs::write(state.path().join("sessions").join("active"), b"session-1\n").unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("state/listing.txt"),
            "bundle must contain state listing"
        );
    }

    /// `cmd_bug` with a state dir that has a `mesh-enrolment` file collects
    /// it under `config/mesh-enrolment`.
    #[tokio::test]
    async fn cmd_bug_collects_mesh_enrolment() {
        let state = tempfile::TempDir::new().unwrap();
        std::fs::write(
            state.path().join("mesh-enrolment"),
            b"mesh enrolment data\n",
        )
        .unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("config/mesh-enrolment"),
            "bundle must contain mesh-enrolment under config/"
        );
        assert_eq!(
            &files["config/mesh-enrolment"][..],
            b"mesh enrolment data\n",
            "mesh-enrolment must be captured verbatim"
        );
    }

    /// `cmd_bug` with no `mesh-enrolment` file omits it without error: an
    /// un-enrolled install is a normal state, not a finding.
    #[tokio::test]
    async fn cmd_bug_missing_mesh_enrolment_is_absent_not_error() {
        let state = tempfile::TempDir::new().unwrap();
        // No mesh-enrolment file.

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            !files.contains_key("config/mesh-enrolment"),
            "an un-enrolled install must not produce a mesh-enrolment entry"
        );
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let errors = manifest["errors"].as_array().unwrap();
        assert!(
            errors.is_empty(),
            "missing mesh-enrolment must not be recorded as an error: {errors:?}"
        );
    }

    /// `cmd_bug` with a `config/loadouts/` directory under the resolved
    /// config dir collects loadout definitions.
    #[tokio::test]
    async fn cmd_bug_collects_loadout_definitions() {
        let state = tempfile::TempDir::new().unwrap();
        // `--config-dir` names the *parent* of the `minimal/` subdirectory.
        let loadouts_dir = state.path().join("minimal").join("loadouts");
        std::fs::create_dir_all(&loadouts_dir).unwrap();
        std::fs::write(loadouts_dir.join("default.toml"), b"name = \"default\"\n").unwrap();

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");

        let global = GlobalArgs {
            minimal_dir: Some(state.path().to_path_buf()),
            config_dir: Some(state.path().to_path_buf()),
            ..Default::default()
        };
        let args = BugArgs {
            output: Some(out.clone()),
            no_guest: true,
            guest_timeout_secs: 60,
            log_tail_bytes: diagnostics::LOG_TAIL_CAP,
        };

        cmd_bug(&global, args).await.unwrap();

        let files = unpack(&out, "r").await;
        assert!(
            files.contains_key("config/loadouts/default.toml.redacted"),
            "bundle must contain redacted loadout definition"
        );
    }
}
