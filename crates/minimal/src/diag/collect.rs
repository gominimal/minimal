//! Host-side collectors for the `min bug` diagnostic bundle.
//!
//! Each collector is independent: it reads what it can, adds entries to the
//! [`BundleWriter`], and returns an error only for genuinely unexpected
//! failures (an absent file is data, not an error). The orchestrator records
//! collector errors in the manifest and moves on.

use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Context as _;
use serde::Serialize;

use super::redact::is_env_value_allowlisted;
use diagnostics::redact::{masked_process_env, redact_toml};
use diagnostics::{BundleWriter, Redaction, open_regular_nofollow};

/// Cap on entries in a recursive state-dir listing; a runaway tree (huge
/// session workspaces) is truncated with a marker line, not walked forever.
const LISTING_MAX_ENTRIES: usize = 100_000;

/// Everything the host collectors need, resolved once so collection is a
/// pure function of these paths plus the filesystem.
pub struct DiagPaths {
    /// `<config>/minimal`.
    pub config: PathBuf,
    /// `<state>/minimal` (or the `--minimal-dir` override).
    pub state: PathBuf,
    /// `<cache>/minimal`.
    pub cache: PathBuf,
    /// Where `min mesh join` writes its enrolment file.
    pub mesh_enrolment: PathBuf,
    /// The invoking directory (disk-full there breaks the bundle write).
    pub cwd: PathBuf,
}

// ── host/system.json ─────────────────────────────────────────────────────────

pub async fn system(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Which filesystems matter is this binary's policy: the state dir, the
    // cache dir, and the invoking directory the archive is written into.
    let info = diagnostics::system_info(&[&paths.state, &paths.cache, &paths.cwd]).await;
    let json = serde_json_lenient::to_vec_pretty(&info).context("serializing system info")?;
    w.add_bytes("host/system.json", &json, Redaction::None)
        .await?;

    // NET-122/NET-123: the host's naming surface — the resolver hook state
    // (the macOS resolver file or the Linux routing-domain link), the
    // reserved range's loopback aliases as a bind probe found them, and
    // whether the host is on the 127.0.0.1 interim. Ports, interface names
    // and loopback addresses are all it holds — the hook's detail never
    // echoes a foreign nameserver — so nothing needs redacting.
    let naming = crate::resolver::naming_surface().await;
    let json = serde_json_lenient::to_vec_pretty(&naming)
        .context("serializing the host naming surface")?;
    w.add_bytes("host/net-naming.json", &json, Redaction::None)
        .await
}

// ── host/terminal.json ───────────────────────────────────────────────────────

/// The terminal `min bug` itself ran on. Interactive rendering complaints
/// (#950) cannot be judged without it, and it costs three ioctls.
pub async fn terminal(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let info = diagnostics::terminal_info();
    let json = serde_json_lenient::to_vec_pretty(&info).context("serializing terminal info")?;
    w.add_bytes("host/terminal.json", &json, Redaction::None)
        .await
}

// ── host/env.json ────────────────────────────────────────────────────────────

pub async fn env(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let env = masked_process_env(is_env_value_allowlisted);
    let json = serde_json_lenient::to_vec_pretty(&env).context("serializing env")?;
    w.add_bytes("host/env.json", &json, Redaction::Keys).await
}

// ── config/ ──────────────────────────────────────────────────────────────────

pub async fn config(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    add_redacted_toml(
        w,
        &paths.config.join("config.toml"),
        "config/config.toml.redacted",
    )
    .await;
    add_redacted_toml(
        w,
        &paths.config.join("user_policy.toml"),
        "config/user_policy.toml.redacted",
    )
    .await;

    // Both loadout layouts: `<name>.toml` and `<name>/loadout.toml`. Only
    // the definition file either way — the rest of a loadout's directory
    // ($LOADOUT_ROOT assets, hook scripts) is the user's own content and
    // has never been collected.
    match tokio::fs::read_dir(paths.config.join("loadouts")).await {
        Ok(mut entries) => loop {
            match entries.next_entry().await {
                Ok(Some(entry)) => {
                    let path = entry.path();
                    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    // `DirEntry::file_type` does not follow symlinks, and
                    // that is the point: descending into a symlinked
                    // `<name>/` would read a `loadout.toml` from wherever
                    // it pointed, and `open_regular_nofollow` could not
                    // stop it — `O_NOFOLLOW` guards only the final
                    // component. A symlinked directory is therefore not a
                    // directory here, matching the daemon-side refusal of
                    // a symlinked hook anchor.
                    let is_dir = match entry.file_type().await {
                        Ok(ft) => ft.is_dir(),
                        Err(e) => {
                            w.skip(
                                format!("config/loadouts/{name}"),
                                format!("unreadable: {e}"),
                            );
                            continue;
                        }
                    };
                    if is_dir {
                        let file = path.join(sessions::client::disk::LOADOUT_FILE_NAME);
                        // Existence only. Whether this is a *safe* file to
                        // read is `add_redacted_toml`'s call, and it makes
                        // it independently — a symlinked `loadout.toml` is
                        // refused at open and the refusal recorded, the
                        // same way a symlinked `<name>.toml` is below.
                        if tokio::fs::metadata(&file).await.is_ok_and(|m| m.is_file()) {
                            add_redacted_toml(
                                w,
                                &file,
                                &format!(
                                    "config/loadouts/{name}/{}.redacted",
                                    sessions::client::disk::LOADOUT_FILE_NAME
                                ),
                            )
                            .await;
                        }
                    } else if path.extension().is_some_and(|e| e == "toml") {
                        add_redacted_toml(w, &path, &format!("config/loadouts/{name}.redacted"))
                            .await;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    w.skip("config/loadouts/", format!("listing interrupted: {e}"));
                    break;
                }
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => w.skip("config/loadouts/", format!("unreadable: {e}")),
    }

    // mTLS material: cert/CA metadata only, private key never touched.
    w.skip(
        "config/client.key",
        "private key material — never collected",
    );
    let certs: std::collections::BTreeMap<&str, Option<FileMeta>> = [
        (
            "client.pem",
            file_meta(&paths.config.join("client.pem")).await,
        ),
        ("ca.pem", file_meta(&paths.config.join("ca.pem")).await),
    ]
    .into_iter()
    .collect();
    let json = serde_json_lenient::to_vec_pretty(&certs).context("serializing cert metadata")?;
    w.add_bytes("config/client-cert.json", &json, Redaction::ListingOnly)
        .await?;

    // Mesh enrolment holds only a host:port endpoint. No-follow like every
    // other content read: it ships verbatim, so a symlink here would
    // exfiltrate an arbitrary file byte-for-byte.
    match read_string_nofollow(&paths.mesh_enrolment).await {
        Ok(content) => {
            w.add_bytes("config/mesh-enrolment", content.as_bytes(), Redaction::None)
                .await?
        }
        Err(e) if is_not_found(&e) => {}
        Err(e) => w.skip("config/mesh-enrolment", format!("unreadable: {e:#}")),
    }
    Ok(())
}

/// Adds a TOML file with values redacted; a missing file is silently fine,
/// an unparseable, unreadable, or symlinked one is withheld with a manifest
/// note (the no-follow discipline covers content reads, not just log tails —
/// a symlinked "config" file must not steer unrelated data into the bundle).
async fn add_redacted_toml(w: &mut BundleWriter, src: &Path, dest: &str) {
    let content = match read_string_nofollow(src).await {
        Ok(c) => c,
        Err(e) if is_not_found(&e) => return,
        Err(e) => {
            w.skip(dest, format!("unreadable: {e:#}"));
            return;
        }
    };
    match redact_toml(&content) {
        Ok(redacted) => {
            if let Err(e) = w
                .add_bytes(dest, redacted.as_bytes(), Redaction::Keys)
                .await
            {
                w.skip(dest, format!("bundling failed: {e}"));
            }
        }
        Err(e) => w.skip(
            dest,
            format!("withheld: does not parse as TOML, cannot redact safely: {e}"),
        ),
    }
}

/// Reads a regular file to a string without following symlinks.
async fn read_string_nofollow(src: &Path) -> Result<String, anyhow::Error> {
    use tokio::io::AsyncReadExt as _;
    let (mut file, _) = open_regular_nofollow(src).await?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .await
        .with_context(|| format!("reading {}", src.display()))?;
    Ok(content)
}

#[derive(Serialize)]
struct FileMeta {
    bytes: u64,
    mtime_unix: Option<u64>,
}

async fn file_meta(path: &Path) -> Option<FileMeta> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some(FileMeta {
        bytes: meta.len(),
        mtime_unix: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
    })
}

// ── state/ ───────────────────────────────────────────────────────────────────

pub async fn state(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    // Recursive listing: names, sizes, and metadata only — session workspace
    // *contents* stay on the user's machine. The walk is synchronous, so it
    // runs on a blocking thread: a wedged filesystem must strand that
    // thread, not the worker whose collect_step! timeout is the failsafe.
    let state_dir = paths.state.clone();
    let listing =
        tokio::task::spawn_blocking(move || diagnostics::listing(&state_dir, LISTING_MAX_ENTRIES))
            .await
            .context("listing worker")?
            .context("listing state dir")?;
    w.add_bytes(
        "state/listing.txt",
        listing.text.as_bytes(),
        Redaction::ListingOnly,
    )
    .await
}

// ── logs/ ────────────────────────────────────────────────────────────────────

/// How many rotated files per log prefix make it into the bundle.
const LOG_FILES_PER_PREFIX: usize = 5;

/// The one phrasing that asserts a file simply is not there.
///
/// A skip may only carry it when nothing in the bundle — at any nesting level
/// — holds the path it names. [`explain_absent_log_prefixes`] is where that is
/// decided for the log prefixes; the constant exists so the invariant test can
/// find every skip that makes the claim.
const NO_SUCH_FILES: &str = "no files with this prefix";

/// Where the daemon behind a log prefix runs — which decides whether the
/// absence of its files under `<state>/logs` is the whole story.
#[derive(Debug, Clone, Copy)]
enum Locality {
    /// A host process. Nothing under `<state>/logs` means nothing was written.
    Host,
    /// Not necessarily a host process at all: on macOS minimald runs *inside*
    /// the microVM and logs to the guest data volume, so its records reach the
    /// bundle through the per-provider guest fetch and never through this
    /// directory. "Not here" is then a fact about this directory only.
    HostOrGuest,
}

/// One searched log prefix and where its writer lives. Only obtainable from
/// [`LOG_PREFIXES`], so a caller cannot invent a prefix with the wrong
/// locality.
#[derive(Debug, Clone, Copy)]
pub struct LogPrefix {
    name: &'static str,
    locality: Locality,
}

/// The prefixes [`logs`] harvests from `<state>/logs`.
const LOG_PREFIXES: [LogPrefix; 2] = [
    LogPrefix {
        name: "minimald.log",
        locality: Locality::HostOrGuest,
    },
    LogPrefix {
        name: "minvmd.log",
        locality: Locality::Host,
    },
];

/// What the provider loop established about the daemon's own logs reaching
/// the bundle by another route — the fact a host-side absence has to be read
/// against.
///
/// Every variant is a distinct epistemic state, because the skip reason is a
/// claim and only two of these license the strong one. "The listing failed"
/// is not "there are none", and "a bundle arrived" is not "the logs are in
/// it": collapsing either into its neighbour is how the manifest ends up
/// asserting something the archive does not back.
#[derive(Debug, Clone, Copy)]
pub enum DaemonLogSources<'a> {
    /// The provider directory could not be listed, so whether any daemon
    /// logged elsewhere is *unknown*. Absence may not be claimed.
    ProvidersUnknown,
    /// No provider instance exists, so no daemon could have logged elsewhere.
    NoProviders,
    /// Providers exist, but none yielded a daemon bundle this run.
    NoneFetched,
    /// These providers' nested bundles verified and were observed to hold
    /// `logs/minimald.log*`. Non-empty by construction.
    Nested(&'a [&'a str]),
    /// A nested bundle arrived from these providers, but this run could not
    /// confirm it holds the daemon's logs — truncated, failed verification,
    /// or verified with no such entry. Non-empty by construction.
    NestedUnconfirmed(&'a [&'a str]),
}

/// Collects the host-side log tails.
///
/// Prefixes that matched no file are *reported back* through `absent` rather
/// than skipped on the spot: whether "nothing under `<state>/logs`" also means
/// "nothing in this bundle" depends on what the provider loop finds
/// afterwards, and the shared collector contract (`collect_step!`) fixes this
/// signature's return type at `Result<(), _>`.
/// [`explain_absent_log_prefixes`] records those skips once the answer is in.
///
/// `tail_bytes` is the per-file cap, already validated by the caller against
/// [`diagnostics::MAX_LOG_TAIL_BYTES`].
pub async fn logs(
    w: &mut BundleWriter,
    paths: &DiagPaths,
    tail_bytes: u64,
    absent: &mut Vec<LogPrefix>,
) -> Result<(), anyhow::Error> {
    let log_dir = paths.state.join("logs");
    // Absence and inaccessibility are different facts: "no log directory"
    // may only be claimed on a real NotFound, never on EACCES or I/O errors.
    match tokio::fs::metadata(&log_dir).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No log dir at all — nothing ever detached. Absence is data.
            w.skip("logs/", "no log directory — no daemon has ever logged here");
        }
        Err(e) => w.skip("logs/", format!("unreadable: {e}")),
        Ok(_) => {
            for prefix in LOG_PREFIXES {
                let files =
                    diagnostics::newest_rotated(&log_dir, prefix.name, LOG_FILES_PER_PREFIX).await;
                if files.is_empty() {
                    absent.push(prefix);
                    continue;
                }
                for path in files {
                    let name = path.file_name().unwrap_or_default().to_string_lossy();
                    let dest = format!("logs/{name}");
                    if let Err(e) = w.add_file_tail(&dest, &path, tail_bytes).await {
                        w.skip(&dest, format!("unreadable: {e}"));
                    }
                }
            }
        }
    }

    // Provider-scoped files. run.log: the detached supervisor's stderr
    // redirect (panics, the final error print of a failed boot). boot.log:
    // the VMM's hvc0 console capture — kernel prints and the guest pid-1's
    // stdout, the only evidence when the guest wedges before (or its
    // transport dies after) the daemon is reachable. zone.json: the VM
    // host daemon's zone-table dump (NET-138) — the table its answerer
    // answered from, written at start and on every change — so a bundle
    // holds the table the answers were given by, not only its name in the
    // dir listing. Absent the same way a log that never appeared is: a
    // provider dir with no daemon (or a daemon predating the dump) records
    // absence, not an error.
    for (name, dir) in provider_dirs(&paths.state).await? {
        for file_name in ["run.log", "boot.log", minvmd::diag::ZONE_TABLE_FILE] {
            let dest = format!("providers/{name}/{file_name}");
            match w
                .add_file_tail(&dest, &dir.join(file_name), tail_bytes)
                .await
            {
                Ok(()) => {}
                Err(e) if is_not_found(&e) => w.skip(&dest, "absent"),
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
    }

    // The legend for everything above, plus the daemon logs that arrive
    // nested from the guest: two overlapping copies of the same output, each
    // systematically missing what the other has.
    w.add_bytes(
        "logs/PROVENANCE.txt",
        LOG_PROVENANCE.as_bytes(),
        Redaction::None,
    )
    .await
}

/// The host-side telemetry spool: the CLI's and minvmd's records (spec 25
/// TEL-044). One directory is read, [`spool_dir`] resolved from `min bug`'s
/// own environment and state directory: its `MINIMAL_OTEL_SPOOL_DIR` when
/// set, else `<state>/telemetry/spool`. A producer picks its directory from
/// its own environment, so a minvmd or CLI whose `MINIMAL_OTEL_SPOOL_DIR`
/// (a systemd unit's, say) or state directory differs from `min bug`'s
/// wrote elsewhere, and its files are not collected; `host/telemetry.json`
/// names the directory read ([`SPOOL_DIR_NOTE`]). The daemon's spool
/// travels in its own nested bundle. The newest [`LOG_FILES_PER_PREFIX`]
/// `*.jsonl` files of each producer ([`diagnostics::spool::producer`]), each
/// tail-capped and line-scrubbed like a log, behind the same symlink guards
/// ([`spool_in`]).
pub async fn spool(
    w: &mut BundleWriter,
    paths: &DiagPaths,
    tail_bytes: u64,
) -> Result<(), anyhow::Error> {
    let dir = spool_dir(paths, std::env::var_os("MINIMAL_OTEL_SPOOL_DIR"));
    let headers = diagnostics::redact::exporter_header_values(|n| std::env::var(n).ok());
    spool_in(w, &dir, tail_bytes, &headers).await
}

/// The spool directory `min bug` reads: `override_dir`, the value of
/// `MINIMAL_OTEL_SPOOL_DIR` in `min bug`'s own environment, when set and not
/// empty, else `<state>/telemetry/spool`. mlog's writer applies the same
/// rule, but each producer to its own environment and state directory, so
/// this is where processes that share `min bug`'s settings wrote, not
/// every spool on the host.
pub fn spool_dir(paths: &DiagPaths, override_dir: Option<std::ffi::OsString>) -> PathBuf {
    match override_dir {
        Some(d) if !d.is_empty() => PathBuf::from(d),
        _ => paths.state.join("telemetry").join("spool"),
    }
}

/// [`diagnostics::spool::collect`] with the host bundle's policy: the newest
/// [`LOG_FILES_PER_PREFIX`] files of each producer, so a chatty minvmd cannot
/// push the CLI's only file out of the bundle.
async fn spool_in(
    w: &mut BundleWriter,
    dir: &Path,
    tail_bytes: u64,
    header_values: &[String],
) -> Result<(), anyhow::Error> {
    diagnostics::spool::collect(
        w,
        dir,
        tail_bytes,
        diagnostics::spool::SpoolKeep::NewestPerProducer(LOG_FILES_PER_PREFIX),
        header_values,
        "no spool directory — telemetry never ran on this host",
    )
    .await
}

// ── host/telemetry.json ──────────────────────────────────────────────────────

/// What telemetry was set to in the `min bug` process's environment when the
/// bundle was collected (spec 25 TEL-051): the switch and the variable that
/// decided it, each signal's exporter, each endpoint as its origin only (the
/// TEL-040 form), the spool, and the trace id of the newest `cmd` span the
/// CLI spooled. This is the CLI's state as the shell running `min bug` sets
/// it, not the whole host's: a daemon or minvmd keeps the switches it was
/// started with (TEL-009), so it can export while this says off, or the
/// reverse; [`Self::source`] says so in the file. Nothing here is a
/// credential: no header, no endpoint path or query.
#[derive(Debug, Serialize)]
pub struct TelemetryState {
    /// Whose state this is: always [`TELEMETRY_STATE_SOURCE`].
    pub source: &'static str,
    /// The opt-in: `MINIMAL_TELEMETRY` truthy and no veto.
    pub enabled: bool,
    /// The variable that settled [`Self::enabled`]: `DO_NOT_TRACK` or
    /// `OTEL_SDK_DISABLED` when either vetoes, else `MINIMAL_TELEMETRY`.
    pub decided_by: &'static str,
    pub traces: SignalState,
    pub logs: SignalState,
    /// Finished records are spooled locally.
    pub spool: bool,
    /// The spool directory the bundle read ([`spool_dir`]).
    pub spool_dir: PathBuf,
    /// Always [`SPOOL_DIR_NOTE`]: [`Self::spool_dir`] is the only spool
    /// directory read.
    pub spool_dir_note: &'static str,
    /// The `traceId` of the newest `cmd` span in the CLI's spool files.
    pub newest_cmd_trace_id: Option<String>,
}

/// One signal's part of a [`TelemetryState`].
#[derive(Debug, Serialize)]
pub struct SignalState {
    /// The signal is exported to [`Self::endpoint`].
    pub exporting: bool,
    /// The signal's exporter variable is `none`.
    pub exporter_none: bool,
    /// The endpoint's `scheme://host[:port]`, never its userinfo, path,
    /// query or fragment (TEL-040).
    pub endpoint: Option<String>,
    /// The configured endpoint was refused, so the signal is not exported.
    pub refused: bool,
}

/// [`TelemetryState::spool_dir_note`]: the bundle reads one spool
/// directory, and a spool another process pinned elsewhere is not in it.
pub const SPOOL_DIR_NOTE: &str = "the only spool directory read: MINIMAL_OTEL_SPOOL_DIR from the \
     min bug process environment, else <state>/telemetry/spool; a spool another process placed \
     elsewhere through its own environment is not collected";

/// [`TelemetryState::source`]: the record is the `min bug` process's own
/// environment, not the daemon's or minvmd's.
pub const TELEMETRY_STATE_SOURCE: &str =
    "min bug process environment (a daemon or minvmd may run with other settings)";

pub async fn telemetry(w: &mut BundleWriter, paths: &DiagPaths) -> Result<(), anyhow::Error> {
    let state = telemetry_state(paths, |n| std::env::var_os(n)).await;
    let json = serde_json_lenient::to_vec_pretty(&state).context("serializing telemetry state")?;
    w.add_bytes("host/telemetry.json", &json, Redaction::None)
        .await
}

/// [`TelemetryState`] over the variables `var` gives. The exporter, endpoint
/// and spool decision is mlog's own ([`mlog::otel::guest_exports`]). The
/// switch's deciding variable mirrors mlog's private `Switches::enabled`,
/// which mlog does not export; `the_mirrored_switch_agrees_with_mlog` holds
/// the two together.
async fn telemetry_state(
    paths: &DiagPaths,
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> TelemetryState {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    let text = |name: &str| var(name).and_then(|v| v.into_string().ok());
    let (enabled, decided_by) = if set("DO_NOT_TRACK") {
        (false, "DO_NOT_TRACK")
    } else if text("OTEL_SDK_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        (false, "OTEL_SDK_DISABLED")
    } else {
        let on = text("MINIMAL_TELEMETRY").is_some_and(|v| {
            ["1", "true", "yes", "on"]
                .iter()
                .any(|t| v.eq_ignore_ascii_case(t))
        });
        (on, "MINIMAL_TELEMETRY")
    };
    let exports = mlog::otel::guest_exports(|n| text(n));
    let signal = |s: &mlog::otel::GuestSignal| SignalState {
        exporting: matches!(s.url, Some(Ok(_))),
        exporter_none: s.off,
        endpoint: match &s.url {
            Some(Ok(u)) => url::Url::parse(u)
                .ok()
                .map(|u| u.origin().ascii_serialization()),
            _ => None,
        },
        refused: matches!(s.url, Some(Err(_))),
    };
    let dir = spool_dir(paths, var("MINIMAL_OTEL_SPOOL_DIR"));
    TelemetryState {
        source: TELEMETRY_STATE_SOURCE,
        enabled,
        decided_by,
        traces: signal(&exports.traces),
        logs: signal(&exports.logs),
        spool: exports.spool,
        newest_cmd_trace_id: newest_cmd_trace_id(&dir).await,
        spool_dir: dir,
        spool_dir_note: SPOOL_DIR_NOTE,
    }
}

/// The most a trace-id lookup reads from the end of one spool file.
const TRACE_LOOKUP_TAIL: u64 = 1 << 20;

/// The `traceId` of the newest `cmd` span (by `endTimeUnixNano`) in the
/// newest of the CLI's spool files that holds one. It reads at most the
/// newest [`LOG_FILES_PER_PREFIX`] files, [`TRACE_LOOKUP_TAIL`] bytes of
/// each, through the bundle's no-follow open. A line that is not JSON is
/// passed over.
async fn newest_cmd_trace_id(dir: &Path) -> Option<String> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    let mut files: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = rd.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".jsonl") || diagnostics::spool::producer(&name) != "minimal-cli" {
            continue;
        }
        if let Ok(m) = tokio::fs::symlink_metadata(entry.path()).await
            && m.is_file()
        {
            files.push((m.modified().unwrap_or(UNIX_EPOCH), entry.path()));
        }
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.0));
    for (_, path) in files.into_iter().take(LOG_FILES_PER_PREFIX) {
        let Ok((mut file, meta)) = open_regular_nofollow(&path).await else {
            continue;
        };
        if meta.len() > TRACE_LOOKUP_TAIL {
            let back = i64::try_from(TRACE_LOOKUP_TAIL).unwrap_or(i64::MAX);
            if file.seek(std::io::SeekFrom::End(-back)).await.is_err() {
                continue;
            }
        }
        let mut bytes = Vec::new();
        if (&mut file)
            .take(TRACE_LOOKUP_TAIL)
            .read_to_end(&mut bytes)
            .await
            .is_err()
        {
            continue;
        }
        if let Some(id) = newest_cmd_trace_id_in(&String::from_utf8_lossy(&bytes)) {
            return Some(id);
        }
    }
    None
}

/// [`newest_cmd_trace_id`] over one file's text.
fn newest_cmd_trace_id_in(text: &str) -> Option<String> {
    use serde_json_lenient::Value;
    let end = |s: &Value| match s.get("endTimeUnixNano") {
        Some(Value::String(n)) => n.parse::<u64>().unwrap_or(0),
        Some(n) => n.as_u64().unwrap_or(0),
        None => 0,
    };
    let mut best: Option<(u64, String)> = None;
    for line in text.lines() {
        let Ok(v) = serde_json_lenient::from_str::<Value>(line) else {
            continue;
        };
        let spans = v
            .get("resourceSpans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| r.get("scopeSpans").and_then(Value::as_array))
            .flatten()
            .filter_map(|s| s.get("spans").and_then(Value::as_array))
            .flatten();
        for span in spans {
            if span.get("name").and_then(Value::as_str) != Some("cmd") {
                continue;
            }
            let Some(id) = span.get("traceId").and_then(Value::as_str) else {
                continue;
            };
            let t = end(span);
            if best.as_ref().is_none_or(|(b, _)| t >= *b) {
                best = Some((t, id.to_owned()));
            }
        }
    }
    best.map(|(_, id)| id)
}

/// Records the skips [`logs`] held back, now that the provider loop has said
/// whether the daemon's own logs reached the bundle another way.
///
/// The plain absence claim ([`NO_SUCH_FILES`]) is made only where it is true
/// of the *bundle*, not merely of `<state>/logs`. On macOS a `min bug` run
/// finds no `minimald.log*` on the host — the daemon lives inside the microVM
/// — while the very same bundle nests those logs under
/// `providers/<name>/guest/`. A manifest that answers "no files with this
/// prefix" there teaches a reader to stop looking, which is how a real
/// incident's daemon logs went unread with 178 KB of them on the volume.
pub fn explain_absent_log_prefixes(
    w: &mut BundleWriter,
    paths: &DiagPaths,
    absent: &[LogPrefix],
    sources: DaemonLogSources<'_>,
) {
    let log_dir = paths.state.join("logs");
    let log_dir = log_dir.display();
    // Where in the bundle a named provider's nested daemon bundle sits.
    let carriers = |providers: &[&str]| {
        providers
            .iter()
            .map(|p| format!("providers/{p}/guest/daemon-diag.tar.zst"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for prefix in absent {
        let reason = match (prefix.locality, sources) {
            // A host process that wrote nothing here wrote nothing anywhere —
            // including when the provider listing failed, which says nothing
            // about a host writer. And with no provider instance there is no
            // guest to have logged in either. Both are genuine absence.
            (Locality::Host, _) | (Locality::HostOrGuest, DaemonLogSources::NoProviders) => {
                format!("{NO_SUCH_FILES} in {log_dir}")
            }
            // The listing failed, so whether a guest daemon logged elsewhere
            // was never established. Saying "absent" here would be asserting
            // the one thing this run did not find out.
            (Locality::HostOrGuest, DaemonLogSources::ProvidersUnknown) => format!(
                "none in {log_dir}, and whether any exist elsewhere is unknown — the \
                 provider directory could not be listed this run (see the `providers` \
                 error in this manifest). Where minimald runs inside the microVM it \
                 logs to the guest data volume, not to this host"
            ),
            (Locality::HostOrGuest, DaemonLogSources::Nested(providers)) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs \
                 to the guest data volume, not to this host. Its own logs are in \
                 this bundle, nested in {} (see logs/PROVENANCE.txt)",
                carriers(providers)
            ),
            // A bundle came back, so "no daemon bundle was fetched" would be
            // false; but it was truncated, failed its checks, or held no such
            // entry, so naming it as the carrier would be false too.
            (Locality::HostOrGuest, DaemonLogSources::NestedUnconfirmed(providers)) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs \
                 to the guest data volume, not to this host. A daemon bundle was \
                 collected at {}, but this run could not confirm it carries them; \
                 see the guest.* entries in this manifest (see logs/PROVENANCE.txt)",
                carriers(providers)
            ),
            (Locality::HostOrGuest, DaemonLogSources::NoneFetched) => format!(
                "none in {log_dir} — where minimald runs inside the microVM it logs to \
                 the guest data volume, not to this host, and no daemon bundle was \
                 fetched this run; see providers/*/guest/ for why"
            ),
        };
        w.skip(format!("logs/{}*", prefix.name), reason);
    }
}

/// Which log is which, and what each one systematically lacks.
///
/// Two overlapping copies of the daemon's output can reach a bundle, and
/// nothing in the archive said so: a reader who found the same lines in both
/// had no way to know that the console holds the boot prologue and shutdown
/// epilogue the volume appender can never see, nor that the two are no longer
/// diffable without normalising format.
const LOG_PROVENANCE: &str = "\
Log provenance
==============

Where each log in this bundle came from, how long it is kept, and what it is
known to be missing. Two overlapping copies of the daemon's output can appear
here: they are not duplicates, and neither is a superset of the other.

providers/<name>/boot.log
  source     the VMM's hvc0 console, mirrored to this file by the VMM child
  retention  truncated at every boot (created afresh per boot) — only the
             current boot is present
  format     human-readable tracing output
  holds      the boot prologue: every record written before the state volume
             is mounted (pseudo filesystems mounted, switch to the upstream
             rootfs, writable state volume mounted, cache + state relocated),
             and the shutdown epilogue after the volume appender is released
             (state volume quiesced, connections drained, the final close)
  lacks      nothing observed; a measured incident window showed no console
             record absent under saturation

providers/<name>/guest/daemon-diag.tar.zst -> logs/minimald.log.<date>
  source     the on-volume file appender inside the guest, attached once the
             state volume mounts
  retention  daily rotation, 14 files
  format     JSON lines
  lacks      the boot prologue (the appender does not exist yet) and the
             shutdown epilogue (it is released before the volume is quiesced,
             so a clean shutdown's last records exist only on the console)

providers/<name>/guest/volume-logs/*
  source     the same on-volume appender, read straight off the ext4 image by
             the degraded-mode harvest when the daemon could not be reached
  lacks      the same as above, and may be torn mid-write

An absent minimald.log* under logs/ is a fact about this host's state
directory, not about the daemon: where minimald runs inside the microVM it
never writes there. manifest.json's skip entry for that prefix names whichever
of the sources above carries it instead.

Over the window the console and the volume appender share, their records
match — but the console is human-format and the volume log is JSON lines, so
comparing them requires normalising one to the other first.
";

/// True when an `add_file_tail` failure was a plain missing file.
fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
}

// ── providers/local-<kind><n>/ discovery ───────────────────────────────────────────

/// Provider instance dirs under `<state>/providers`, sorted, plus every named
/// VM nested in a minvmd instance dir as its own `local-minvmd0/<vm>` entry
/// (NET-052) — so the bundle lists every VM by name. The default VM keeps the
/// bare provider entry; a named VM's state dir is the per-name subdirectory
/// (NET-054). Empty when the providers dir doesn't exist (nothing was ever
/// spawned); any other filesystem error is an `Err` — "no daemon was ever
/// spawned here" must never be claimed on the strength of an EACCES.
pub async fn provider_dirs(state: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
    let mut entries = match tokio::fs::read_dir(state.join("providers")).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if name.starts_with("local-") {
            dirs.push((name.clone(), entry.path()));
            // Only the minvmd backend hosts VMs; a native minimald instance
            // dir has no per-name subdirectories to descend into.
            if name.starts_with("local-minvmd") {
                dirs.extend(named_vms(&name, &entry.path()).await);
            }
        }
    }
    dirs.sort();
    Ok(dirs)
}

/// The named VMs under one minvmd provider dir, as
/// (`<provider>/<vm>`, state dir) entries. A subdirectory is a VM only when
/// its name is a valid VM name — an unnamed directory a tool left behind must
/// not be reported as a VM, and the in-guest diagnostic bundle's `guest/`
/// directory is among the names the validator reserves, so it never reads as
/// a VM either. An unreadable provider dir yields no VMs rather than failing
/// the whole listing: the provider entry above still says what it holds.
async fn named_vms(provider: &str, dir: &Path) -> Vec<(String, PathBuf)> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    let mut vms: Vec<(String, PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Some(vm) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if paths::validate_vm_name(&vm).is_err() {
            continue;
        }
        vms.push((format!("{provider}/{vm}"), entry.path()));
    }
    vms
}

/// Non-log per-provider evidence: what the instance dir holds, its raw
/// lifecycle state, and whether anything is still alive behind it (R7.6).
///
/// `run.log`/`boot.log` are deliberately *not* collected here — [`logs`]
/// already tail-caps them for every discovered provider, and a second copy
/// would be a duplicate archive entry.
pub async fn provider_files(
    w: &mut BundleWriter,
    name: &str,
    dir: &Path,
) -> Result<(), anyhow::Error> {
    // Shallow inventory of the instance dir: which sockets, locks, keys and
    // images exist. Metadata only — the walk is synchronous, so it runs on a
    // blocking thread like every other listing.
    let listing_dir = dir.to_path_buf();
    let listing = tokio::task::spawn_blocking(move || {
        diagnostics::listing(&listing_dir, LISTING_MAX_ENTRIES)
    })
    .await
    .context("provider listing worker")?;
    let dest = format!("providers/{name}/dir-listing.txt");
    match listing {
        Ok(listing) => {
            w.add_bytes(&dest, listing.text.as_bytes(), Redaction::ListingOnly)
                .await?
        }
        Err(e) => w.skip(&dest, format!("unreadable: {e:#}")),
    }

    w.skip(
        format!("providers/{name}/ssh_host_ed25519_key"),
        "private key material — never collected",
    );

    // Lifecycle state, verbatim (nothing sensitive: enum + pid + timestamp).
    //
    // Read through the same `O_NOFOLLOW` discipline as every other bundled
    // file: `tokio::fs::read` would follow a symlink planted here and copy an
    // unrelated readable host file into a bundle meant for sharing.
    let dest = format!("providers/{name}/minvmd.toml");
    match diagnostics::open_regular_nofollow(&dir.join("minvmd.toml")).await {
        Ok((mut file, _)) => {
            let mut bytes = Vec::new();
            match tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes).await {
                Ok(_) => w.add_bytes(&dest, &bytes, Redaction::None).await?,
                Err(e) => w.skip(&dest, format!("unreadable: {e}")),
            }
        }
        Err(e) => match e.downcast_ref::<std::io::Error>() {
            Some(io) if io.kind() == std::io::ErrorKind::NotFound => {}
            _ => w.skip(&dest, format!("unreadable: {e:#}")),
        },
    }

    let status_dir = dir.to_path_buf();
    // The entry's VM name, resolved before the move: status.json names the
    // VM this state belongs to alongside its state directory and socket, so
    // every VM in the bundle is identifiable at a glance (NET-052).
    let status_vm = vm_of_entry(name);
    let status =
        tokio::task::spawn_blocking(move || provider_status(status_vm.as_deref(), &status_dir))
            .await
            .context("provider status worker")?;
    let json = serde_json_lenient::to_vec_pretty(&status).context("serializing provider status")?;
    w.add_bytes(
        &format!("providers/{name}/status.json"),
        &json,
        Redaction::None,
    )
    .await?;

    // The data volume's apparent vs allocated size. A sparse `data-vol.raw`
    // reports its full 256 GiB to `len()`, while `st_blocks * 512` is what it
    // actually occupies — the number that says whether a machine holding tens
    // of GB is healthy or silently full.
    let volume_dir = dir.to_path_buf();
    let volume = tokio::task::spawn_blocking(move || volume_info(&volume_dir))
        .await
        .context("volume info worker")?;
    let json = serde_json_lenient::to_vec_pretty(&volume).context("serializing volume info")?;
    w.add_bytes(
        &format!("providers/{name}/volume.json"),
        &json,
        Redaction::None,
    )
    .await
}

/// The data volume image's apparent and allocated sizes. `apparent_bytes` is
/// `Metadata::len()` — the full sparse size — while `allocated_bytes` is
/// `st_blocks * 512`, what the image actually occupies on disk.
#[derive(Serialize)]
struct VolumeInfo {
    path: String,
    exists: bool,
    apparent_bytes: Option<u64>,
    allocated_bytes: Option<u64>,
    /// A non-`NotFound` stat failure (permission, I/O). "Absent" and
    /// "unreadable" are different diagnoses and must not collapse into the
    /// same `exists: false`, mirroring `guest::volume_fallback`.
    error: Option<String>,
}

/// Reads the data volume image's sizes, best-effort: an absent image is
/// `exists: false` with `None` sizes, while a non-`NotFound` stat failure is
/// preserved in `error` rather than reported as a missing image.
fn volume_info(dir: &Path) -> VolumeInfo {
    use std::os::unix::fs::MetadataExt as _;
    let image = dir.join("data-vol.raw");
    let (meta, error) = match std::fs::metadata(&image) {
        Ok(m) => (Some(m), None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    VolumeInfo {
        path: image.display().to_string(),
        exists: meta.is_some(),
        apparent_bytes: meta.as_ref().map(std::fs::Metadata::len),
        allocated_bytes: meta.as_ref().map(|m| m.blocks() * 512),
        error,
    }
}

#[derive(Serialize)]
struct ProviderStatus {
    /// The VM this entry serves: `default` for a bare minvmd provider dir,
    /// the per-name subdirectory for a named VM (`local-minvmd0/alpha`), and
    /// `None` for the native minimald backend, which hosts no VMs.
    vm: Option<String>,
    /// The VM's state directory — the dir this status was read from.
    state_dir: PathBuf,
    /// The daemon's UDS: `<state dir>/ssh.sock`.
    socket: PathBuf,
    /// Raw lifecycle from `minvmd.toml` — never repaired/written back.
    state: Option<toml::Table>,
    state_read_error: Option<String>,
    /// A live minvmd (or its VMM child) holds `minvmd.lock`.
    minvmd_alive: Option<bool>,
    /// A live native minimald holds `minimald.lock`.
    minimald_alive: Option<bool>,
}

/// The VM a provider entry names: the per-name subdirectory of a nested entry
/// (`local-minvmd0/alpha` → `alpha`), the default VM for a bare minvmd
/// provider dir, and `None` for the native minimald backend, which hosts no
/// VMs.
fn vm_of_entry(name: &str) -> Option<String> {
    if let Some((_, vm)) = name.rsplit_once('/') {
        return Some(vm.to_owned());
    }
    name.starts_with("local-minvmd")
        .then(|| paths::DEFAULT_VM_NAME.to_owned())
}

/// Reads the provider's lifecycle state and probes the advisory locks.
///
/// Deliberately *not* `StateDir::effective_state()`, which repairs stale state
/// by writing `Stopped` back — a diagnostic must never mutate what it reads.
/// Synchronous (file locks and `std::fs`); callers run it on a blocking thread.
fn provider_status(vm: Option<&str>, dir: &Path) -> ProviderStatus {
    // `StateDir::new` runs `create_dir_all`, so probing a provider whose
    // directory had been deleted would recreate it — leaving ghost state
    // behind and making this collector a mutation, which the paragraph above
    // says it must never be.
    let state_dir = minvmd::state::StateDir::open_existing(dir.to_path_buf());
    let (state, state_read_error) = match std::fs::read_to_string(state_dir.state_path()) {
        Ok(s) => match s.parse::<toml::Table>() {
            Ok(table) => (Some(table), None),
            Err(e) => (None, Some(e.to_string())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, None),
        Err(e) => (None, Some(e.to_string())),
    };
    ProviderStatus {
        vm: vm.map(str::to_owned),
        state_dir: dir.to_path_buf(),
        socket: dir.join(paths::SSH_SOCK_FILE),
        state,
        state_read_error,
        minvmd_alive: state_dir.daemon_alive().ok(),
        minimald_alive: state_dir.minimald_alive().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::AsyncReadExt as _;
    use tokio_stream::StreamExt as _;

    /// Every entry path in a tar+zstd blob.
    async fn entry_paths(bytes: &[u8]) -> Vec<String> {
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(bytes);
        let mut entries = async_tar::Archive::new(decoder).entries().unwrap();
        let mut paths = Vec::new();
        while let Some(entry) = entries.next().await {
            paths.push(
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        paths
    }

    /// Unpacks a written bundle to `bundle-relative path -> contents`.
    async fn unpack(out: &Path, root: &str) -> BTreeMap<String, Vec<u8>> {
        let bytes = tokio::fs::read(out).await.unwrap();
        let decoder = async_compression::tokio::bufread::ZstdDecoder::new(&bytes[..]);
        let mut entries = async_tar::Archive::new(decoder).entries().unwrap();
        let mut files = BTreeMap::new();
        while let Some(entry) = entries.next().await {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut contents = Vec::new();
            entry.read_to_end(&mut contents).await.unwrap();
            files.insert(
                path.strip_prefix(&format!("{root}/"))
                    .unwrap_or(&path)
                    .to_string(),
                contents,
            );
        }
        files
    }

    fn paths(state: &Path) -> DiagPaths {
        DiagPaths {
            config: state.join("config"),
            state: state.to_path_buf(),
            cache: state.join("cache"),
            mesh_enrolment: state.join("enrolment"),
            cwd: state.to_path_buf(),
        }
    }

    /// Records the held-back skips for `sources` over both log prefixes and
    /// returns the manifest's `what -> reason` map.
    async fn reasons_for(sources: DaemonLogSources<'_>) -> BTreeMap<String, String> {
        let dir = tempfile::TempDir::new().unwrap();
        let out = dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        explain_absent_log_prefixes(&mut w, &paths(dir.path()), &LOG_PREFIXES, sources);
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "r").await;
        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        manifest["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                (
                    s["what"].as_str().unwrap().to_string(),
                    s["reason"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// The strong claim ([`NO_SUCH_FILES`]) is licensed by only some of the
    /// states a run can end in. A run that could not list the provider
    /// directory has not established absence, it has established nothing —
    /// and "I did not find out" recorded as "it is not there" is the same
    /// defect as the one this whole path exists to correct.
    #[tokio::test]
    async fn plain_absence_is_claimed_only_where_the_run_established_it() {
        let all = [
            DaemonLogSources::ProvidersUnknown,
            DaemonLogSources::NoProviders,
            DaemonLogSources::NoneFetched,
            DaemonLogSources::Nested(&["local-minvmd0"]),
            DaemonLogSources::NestedUnconfirmed(&["local-minvmd0"]),
        ];

        // minvmd is a host process wherever the providers are: nothing under
        // <state>/logs is the whole story in every state.
        for sources in all {
            let reasons = reasons_for(sources).await;
            assert!(
                reasons["logs/minvmd.log*"].starts_with(NO_SUCH_FILES),
                "a host-only writer's absence is plain absence under {sources:?}: {reasons:?}"
            );
        }

        // minimald may be inside the microVM, so only a *settled* empty
        // provider list rules out its logs having gone elsewhere.
        for sources in all {
            let reasons = reasons_for(sources).await;
            let claims_absence = reasons["logs/minimald.log*"].starts_with(NO_SUCH_FILES);
            let established = matches!(sources, DaemonLogSources::NoProviders);
            assert_eq!(
                claims_absence,
                established,
                "{sources:?} must {} claim absence: {reasons:?}",
                if established { "" } else { "not" }
            );
        }
    }

    /// Naming a carrier is a claim too. A bundle that arrived truncated or
    /// failed its checks may be offered as somewhere to look, never as the
    /// answer — sending a reader to a file that does not hold what they were
    /// told it holds recreates the dead end in the other direction.
    #[tokio::test]
    async fn only_a_confirmed_nested_bundle_is_named_as_the_carrier() {
        let carrier = "providers/local-minvmd0/guest/daemon-diag.tar.zst";

        let confirmed = reasons_for(DaemonLogSources::Nested(&["local-minvmd0"])).await;
        let reason = &confirmed["logs/minimald.log*"];
        assert!(reason.contains(carrier), "got: {reason}");
        assert!(reason.contains("are in this bundle"), "got: {reason}");

        let unconfirmed =
            reasons_for(DaemonLogSources::NestedUnconfirmed(&["local-minvmd0"])).await;
        let reason = &unconfirmed["logs/minimald.log*"];
        assert!(reason.contains(carrier), "got: {reason}");
        assert!(reason.contains("could not confirm"), "got: {reason}");
        assert!(
            !reason.contains("are in this bundle"),
            "an unconfirmed carrier must not be asserted as the answer: {reason}"
        );
    }

    /// True when a skip's `what` — a bundle path, possibly a `*` suffix glob —
    /// names `path`.
    fn names(what: &str, path: &str) -> bool {
        match what.strip_suffix('*') {
            Some(prefix) => path.starts_with(prefix),
            None => path == what,
        }
    }

    /// The manifest's contract is that an absent file is always explainable,
    /// and a reader who trusts it stops looking. So no skip may claim plain
    /// absence for something the bundle is *carrying* — including inside a
    /// nested bundle, which is exactly where the guest daemon's logs arrive
    /// while `<state>/logs` on a macOS host holds none of them.
    ///
    /// The invariant is the fix; the wording is only its expression, so this
    /// asserts over every skip rather than over one message.
    #[tokio::test]
    async fn no_skip_claims_absence_for_a_path_the_bundle_carries() {
        let state = tempfile::TempDir::new().unwrap();
        // The macOS shape: a log directory with neither prefix in it, because
        // minimald is inside the microVM and minvmd never ran detached.
        std::fs::create_dir_all(state.path().join("logs")).unwrap();
        let paths = paths(state.path());

        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();

        let mut absent = Vec::new();
        logs(&mut w, &paths, diagnostics::LOG_TAIL_CAP, &mut absent)
            .await
            .unwrap();
        assert_eq!(absent.len(), 2, "both prefixes matched nothing on the host");

        // The guest fetch nested the daemon's own bundle, which carries the
        // very files the host state dir lacks.
        let nested = crate::diag::guest::tests::pack(&[
            ("manifest.json", b"{}"),
            ("logs/minimald.log.2026-07-16", b"guest daemon log\n"),
        ])
        .await;
        w.add_bytes(
            "providers/local-minvmd0/guest/daemon-diag.tar.zst",
            &nested,
            Redaction::None,
        )
        .await
        .unwrap();

        explain_absent_log_prefixes(
            &mut w,
            &paths,
            &absent,
            DaemonLogSources::Nested(&["local-minvmd0"]),
        );
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let mut carried: Vec<String> = files.keys().cloned().collect();
        for (path, bytes) in &files {
            if path.ends_with(".tar.zst") {
                carried.extend(entry_paths(bytes).await);
            }
        }

        let manifest: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["manifest.json"]).unwrap();
        let skipped = manifest["skipped"].as_array().unwrap();
        for skip in skipped {
            let (what, reason) = (
                skip["what"].as_str().unwrap(),
                skip["reason"].as_str().unwrap(),
            );
            if !reason.starts_with(NO_SUCH_FILES) {
                continue;
            }
            assert!(
                !carried.iter().any(|p| names(what, p)),
                "manifest claims `{what}` is absent ({reason:?}), but the bundle \
                 carries it: {carried:?}"
            );
        }

        // Non-vacuous in both directions: the claim is still made where it is
        // true, and the prefix the guest carries points at its carrier.
        let reason = |what: &str| {
            skipped
                .iter()
                .find(|s| s["what"] == what)
                .unwrap_or_else(|| panic!("no skip for {what}: {skipped:?}"))["reason"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert!(
            reason("logs/minvmd.log*").starts_with(NO_SUCH_FILES),
            "a host-only daemon's absence is still plain absence"
        );
        assert!(
            reason("logs/minimald.log*")
                .contains("providers/local-minvmd0/guest/daemon-diag.tar.zst"),
            "the skip must name where the logs actually are"
        );
    }

    /// A reader cannot tell the console mirror and the on-volume appender
    /// apart, or know what each is missing, unless the bundle says so.
    #[tokio::test]
    async fn the_log_provenance_note_distinguishes_the_two_daemon_log_sources() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();
        logs(
            &mut w,
            &paths(state.path()),
            diagnostics::LOG_TAIL_CAP,
            &mut Vec::new(),
        )
        .await
        .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let note = String::from_utf8(files["logs/PROVENANCE.txt"].clone()).unwrap();
        for expected in [
            "providers/<name>/boot.log",
            "hvc0 console",
            "truncated at every boot",
            "on-volume file appender",
            "JSON lines",
            "boot prologue",
            "shutdown epilogue",
        ] {
            assert!(
                note.contains(expected),
                "provenance note lacks {expected:?}"
            );
        }
    }

    /// One provider dir with two named VMs beside the guest payload and the
    /// default VM, plus a native instance dir: `provider_dirs` must list every
    /// VM as its own entry (`local-minvmd0/<vm>`), keep the default VM as the
    /// bare provider entry, and never report the guest payload as a VM.
    #[tokio::test]
    async fn provider_dirs_lists_named_vms() {
        let state = tempfile::TempDir::new().unwrap();
        let providers = state.path().join("providers");
        let minvmd = providers.join("local-minvmd0");
        for dir in ["guest", "alpha", "beta"] {
            std::fs::create_dir_all(minvmd.join(dir)).unwrap();
        }
        std::fs::create_dir_all(providers.join("local-minimald0")).unwrap();

        let listed = provider_dirs(state.path()).await.unwrap();
        let names: Vec<&str> = listed.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "local-minimald0",
                "local-minvmd0",
                "local-minvmd0/alpha",
                "local-minvmd0/beta",
            ],
            "every VM must be listed by name"
        );
        for (name, dir) in &listed {
            assert_eq!(
                dir,
                &providers.join(name),
                "each entry's dir must be the entry path under providers/"
            );
        }
    }

    /// The bundle must identify every VM it collected: status.json names the
    /// VM, its state directory, and its socket (NET-052's diagnostics).
    #[tokio::test]
    async fn status_json_names_the_vm_its_state_dir_and_socket() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();

        // A default VM's bare provider dir and a named VM's per-name subdir.
        let alpha = state.path().join("providers/local-minvmd0/alpha");
        std::fs::create_dir_all(&alpha).unwrap();
        std::fs::create_dir_all(state.path().join("providers/local-minvmd0")).unwrap();
        provider_files(
            &mut w,
            "local-minvmd0",
            &state.path().join("providers/local-minvmd0"),
        )
        .await
        .unwrap();
        provider_files(&mut w, "local-minvmd0/alpha", &alpha)
            .await
            .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let default_status =
            String::from_utf8(files["providers/local-minvmd0/status.json"].clone()).unwrap();
        assert!(
            default_status.contains(&format!("\"vm\": \"{}\"", paths::DEFAULT_VM_NAME)),
            "the default VM's status must name it: {default_status}"
        );
        let alpha_status =
            String::from_utf8(files["providers/local-minvmd0/alpha/status.json"].clone()).unwrap();
        assert!(
            alpha_status.contains("\"vm\": \"alpha\""),
            "the named VM's status must name it: {alpha_status}"
        );
        assert!(
            alpha_status.contains(&format!("\"state_dir\": \"{}\"", alpha.display())),
            "the named VM's status must give its state directory: {alpha_status}"
        );
        assert!(
            alpha_status.contains(&format!(
                "\"socket\": \"{}\"",
                alpha.join("ssh.sock").display()
            )),
            "the named VM's status must give its socket: {alpha_status}"
        );
    }

    /// A sparse data volume must report both its apparent and allocated sizes:
    /// `len()` alone makes a 256 GiB sparse image look full when it occupies
    /// almost nothing.
    #[tokio::test]
    async fn volume_json_records_apparent_and_allocated_sizes() {
        let state = tempfile::TempDir::new().unwrap();
        let out_dir = tempfile::TempDir::new().unwrap();
        let out = out_dir.path().join("diag.tar.zst");
        let mut w = BundleWriter::create(&out, "r", "v").await.unwrap();

        let provider = state.path().join("providers/local-minvmd0");
        std::fs::create_dir_all(&provider).unwrap();
        // A sparse file: 1 MiB apparent, one 4 KiB block allocated. Write
        // without truncation so the apparent size stays 1 MiB.
        let image = provider.join("data-vol.raw");
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&image)
            .unwrap();
        f.set_len(1024 * 1024).unwrap();
        f.write_all(&[0u8; 4096]).unwrap();

        provider_files(&mut w, "local-minvmd0", &provider)
            .await
            .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();

        let files = unpack(&out, "r").await;
        let volume: serde_json_lenient::Value =
            serde_json_lenient::from_slice(&files["providers/local-minvmd0/volume.json"]).unwrap();
        assert_eq!(volume["exists"], true);
        assert_eq!(volume["apparent_bytes"], 1024 * 1024);
        assert!(
            volume["allocated_bytes"].as_u64().unwrap() < 1024 * 1024,
            "a sparse image's allocated size must be far below its apparent size: {volume}"
        );
        assert!(
            volume["allocated_bytes"].as_u64().unwrap() >= 4096,
            "the written block must be counted: {volume}"
        );
    }

    /// The host bundle carries the CLI's and minvmd's spool records
    /// (spec 25 TEL-044) as the newest `*.jsonl` files under
    /// `telemetry/spool/`, and nothing else from that directory.
    #[tokio::test]
    async fn bundle_carries_the_host_telemetry_spool() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = tmp.path().join("state");
        let spool_dir = state.join("telemetry").join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(
            spool_dir.join("minimal-cli-1-1.jsonl"),
            b"{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"name\":\"cmd\"}]}]}]}\n",
        )
        .unwrap();
        std::fs::write(
            spool_dir.join("minvmd-2-1.jsonl"),
            b"{\"resourceLogs\":[]}\n",
        )
        .unwrap();
        std::fs::write(spool_dir.join("notes.txt"), b"not a spool file").unwrap();
        let paths = DiagPaths {
            config: tmp.path().join("config"),
            state: state.clone(),
            cache: tmp.path().join("cache"),
            mesh_enrolment: tmp.path().join("mesh"),
            cwd: tmp.path().to_path_buf(),
        };
        let out = tmp.path().join("bundle.tar.zst");
        let mut w = BundleWriter::create(&out, "root", "test").await.unwrap();
        spool(&mut w, &paths, 1 << 20).await.unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "root").await;
        let cli = files
            .get("telemetry/spool/minimal-cli-1-1.jsonl")
            .unwrap_or_else(|| panic!("missing the CLI spool: {:?}", files.keys()));
        assert!(std::str::from_utf8(cli).unwrap().contains("resourceSpans"));
        assert!(files.contains_key("telemetry/spool/minvmd-2-1.jsonl"));
        assert!(
            !files.contains_key("telemetry/spool/notes.txt"),
            "only *.jsonl spool files travel"
        );
    }

    /// `MINIMAL_OTEL_SPOOL_DIR` names the spool (the writer's rule), the
    /// state directory is the default, and an empty value is unset.
    #[test]
    fn spool_dir_honours_the_override() {
        let paths = DiagPaths {
            config: PathBuf::from("/c"),
            state: PathBuf::from("/s"),
            cache: PathBuf::from("/k"),
            mesh_enrolment: PathBuf::from("/m"),
            cwd: PathBuf::from("/w"),
        };
        assert_eq!(spool_dir(&paths, None), PathBuf::from("/s/telemetry/spool"));
        assert_eq!(
            spool_dir(&paths, Some("".into())),
            PathBuf::from("/s/telemetry/spool")
        );
        assert_eq!(
            spool_dir(&paths, Some("/elsewhere/spool".into())),
            PathBuf::from("/elsewhere/spool")
        );
    }

    /// The cap is per producer: six newer minvmd files do not push the
    /// CLI's older file out, and the oldest minvmd file is the one dropped.
    #[tokio::test]
    async fn spool_keeps_the_newest_files_of_each_producer() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool_dir = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&spool_dir).unwrap();
        let base =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let put = |name: &str, age_s: u64| {
            let p = spool_dir.join(name);
            std::fs::write(&p, b"{}\n").unwrap();
            std::fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(base - std::time::Duration::from_secs(age_s))
                .unwrap();
        };
        put("minimal-cli-7-1700000000000.jsonl", 100);
        for n in 0..6u64 {
            put(&format!("minvmd-9-1700000000000-{}.jsonl", n + 1), 60 - n);
        }
        let out = tmp.path().join("bundle.tar.zst");
        let mut w = BundleWriter::create(&out, "root", "test").await.unwrap();
        spool_in(&mut w, &spool_dir, 1 << 20, &[]).await.unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "root").await;
        assert!(
            files.contains_key("telemetry/spool/minimal-cli-7-1700000000000.jsonl"),
            "the older CLI file survives minvmd's churn: {:?}",
            files.keys()
        );
        let minvmd: Vec<_> = files
            .keys()
            .filter(|k| k.starts_with("telemetry/spool/minvmd-"))
            .collect();
        assert_eq!(minvmd.len(), LOG_FILES_PER_PREFIX, "{minvmd:?}");
        assert!(
            !files.contains_key("telemetry/spool/minvmd-9-1700000000000-1.jsonl"),
            "the oldest minvmd file is the one dropped: {:?}",
            files.keys()
        );
    }

    /// TEL-044's two security claims over the host spool collector: a spool
    /// line holding the configured exporter header value (under a harmless
    /// attribute name) and a secret-shaped attribute reaches the bundle
    /// without either value.
    #[tokio::test]
    async fn a_host_bundle_never_carries_a_header_value_or_a_secret_attribute() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool_dir = tmp.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(
            spool_dir.join("minimal-cli-1-1.jsonl"),
            concat!(
                r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"name":"cmd","attributes":["#,
                r#"{"key":"note","value":{"stringValue":"hcaik_s3cr3tINGEST"}},"#,
                r#"{"key":"vendor.api_key","value":{"stringValue":"opensesame"}},"#,
                r#"{"key":"cmd.name","value":{"stringValue":"build"}}]}]}]}]}"#,
                "\n"
            ),
        )
        .unwrap();
        let headers = diagnostics::redact::exporter_header_values(|n| {
            (n == "MINIMAL_OTEL_EXPORTER_OTLP_HEADERS")
                .then(|| "x-honeycomb-team=hcaik_s3cr3tINGEST".to_owned())
        });
        let out = tmp.path().join("bundle.tar.zst");
        let mut w = BundleWriter::create(&out, "root", "test").await.unwrap();
        spool_in(&mut w, &spool_dir, 1 << 20, &headers)
            .await
            .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "root").await;
        let body = std::str::from_utf8(&files["telemetry/spool/minimal-cli-1-1.jsonl"]).unwrap();
        assert!(body.contains("\"build\""), "the record travels: {body}");
        for (path, bytes) in &files {
            let text = String::from_utf8_lossy(bytes);
            assert!(
                !text.contains("hcaik_s3cr3tINGEST"),
                "header value in {path}"
            );
            assert!(!text.contains("opensesame"), "secret attribute in {path}");
        }
    }

    /// TEL-044 per producer: a header that only the producer's
    /// environment holds (minvmd started with it, the `min bug` shell
    /// without it) is scrubbed from that producer's spool file while the
    /// producer runs. Linux reads the producer's environment through /proc;
    /// the macOS read (`sysctl(KERN_PROCARGS2)`) is proved in `diagnostics`
    /// (`a_live_producers_headers_are_scrubbed_from_its_spool_file`), since
    /// the kernel there withholds a platform binary's environment and this
    /// test's `sleep` producer is one.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_producers_own_header_value_never_reaches_the_host_bundle() {
        let mut producer = std::process::Command::new("sleep")
            .arg("30")
            .env(
                "OTEL_EXPORTER_OTLP_HEADERS",
                "authorization=Bearer%20minvmdONLYtoken42",
            )
            .spawn()
            .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let spool_dir = tmp.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        let name = format!("minvmd-{}-1700000000000.jsonl", producer.id());
        std::fs::write(
            spool_dir.join(&name),
            concat!(
                r#"{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"sent minvmdONLYtoken42"},"#,
                r#""attributes":[{"key":"vm","value":{"stringValue":"keep-me"}}]}]}]}]}"#,
                "\n"
            ),
        )
        .unwrap();
        let out = tmp.path().join("bundle.tar.zst");
        let mut w = BundleWriter::create(&out, "root", "test").await.unwrap();
        spool_in(&mut w, &spool_dir, 1 << 20, &[]).await.unwrap();
        producer.kill().unwrap();
        producer.wait().unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "root").await;
        let body = std::str::from_utf8(&files[&format!("telemetry/spool/{name}")]).unwrap();
        assert!(body.contains("keep-me"), "the record travels: {body}");
        assert!(!body.contains("minvmdONLYtoken42"), "{body}");
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |n| pairs.iter().find(|(k, _)| k == n).map(|(_, v)| v.into())
    }

    /// TEL-051: the bundle records the switch and the variable that decided
    /// it, each signal's exporter, each endpoint as its origin only, the
    /// spool, and the trace id of the newest `cmd` span in the CLI spool.
    #[tokio::test]
    async fn the_bundle_records_the_telemetry_state() {
        let tmp = tempfile::TempDir::new().unwrap();
        let spool_dir = tmp.path().join("spool");
        std::fs::create_dir_all(&spool_dir).unwrap();
        std::fs::write(
            spool_dir.join("minimal-cli-1-1.jsonl"),
            concat!(
                r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"cmd","endTimeUnixNano":"200"}]}]}]}"#,
                "\n",
                r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"cmd","endTimeUnixNano":"300"},{"traceId":"cccccccccccccccccccccccccccccccc","name":"rpc","endTimeUnixNano":"400"}]}]}]}"#,
                "\n"
            ),
        )
        .unwrap();
        let paths = paths(tmp.path());
        let dir = spool_dir.to_str().unwrap();
        let state = telemetry_state(
            &paths,
            env_of(&[
                ("MINIMAL_TELEMETRY", "1"),
                ("MINIMAL_OTEL_SPOOL_DIR", dir),
                (
                    "MINIMAL_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    "https://u:p@collector.example:4318/ingest/abc?key=v",
                ),
                ("MINIMAL_OTEL_EXPORTER_OTLP_HEADERS", "x-key=s3cr3tvalue"),
                ("MINIMAL_OTEL_LOGS_EXPORTER", "none"),
            ]),
        )
        .await;
        assert!(state.enabled);
        assert_eq!(state.source, TELEMETRY_STATE_SOURCE, "whose state it is");
        assert_eq!(state.decided_by, "MINIMAL_TELEMETRY");
        assert!(state.traces.exporting);
        assert_eq!(
            state.traces.endpoint.as_deref(),
            Some("https://collector.example:4318")
        );
        assert!(!state.logs.exporting && state.logs.exporter_none);
        assert!(state.spool);
        assert_eq!(state.spool_dir, spool_dir);
        assert_eq!(state.spool_dir_note, SPOOL_DIR_NOTE);
        assert_eq!(
            state.newest_cmd_trace_id.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        let json = serde_json_lenient::to_string(&state).unwrap();
        for leak in ["u:p", "ingest", "key=v", "s3cr3tvalue"] {
            assert!(!json.contains(leak), "{leak} in {json}");
        }

        let off = telemetry_state(
            &paths,
            env_of(&[("MINIMAL_TELEMETRY", "1"), ("DO_NOT_TRACK", "0")]),
        )
        .await;
        assert!(!off.enabled && !off.spool && !off.traces.exporting);
        assert_eq!(off.decided_by, "DO_NOT_TRACK");
        assert_eq!(off.newest_cmd_trace_id, None);

        // A base endpoint with a query is refused (mlog's rule): recorded as
        // refused, with no endpoint.
        let refused = telemetry_state(
            &paths,
            env_of(&[
                ("MINIMAL_TELEMETRY", "1"),
                (
                    "MINIMAL_OTEL_EXPORTER_OTLP_ENDPOINT",
                    "https://c.example/x?k=v",
                ),
            ]),
        )
        .await;
        assert!(refused.traces.refused && !refused.traces.exporting);
        assert_eq!(refused.traces.endpoint, None);
    }

    /// TEL-051: the bundle reads one spool directory, the one `min bug`'s
    /// own environment names, and says so. A spool a producer pinned through
    /// its own `MINIMAL_OTEL_SPOOL_DIR` stays out, and `host/telemetry.json`
    /// records the directory read with [`SPOOL_DIR_NOTE`].
    #[tokio::test]
    async fn a_spool_pinned_only_in_another_process_is_not_collected() {
        let tmp = tempfile::TempDir::new().unwrap();
        let line = concat!(
            r#"{"resourceSpans":[{"scopeSpans":[{"spans":[{"traceId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"cmd","endTimeUnixNano":"1"}]}]}]}"#,
            "\n"
        );
        let ours = tmp.path().join("ours");
        let theirs = tmp.path().join("pinned-by-a-unit");
        for d in [&ours, &theirs] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(ours.join("minimal-cli-1-1.jsonl"), line).unwrap();
        std::fs::write(theirs.join("minvmd-2-1.jsonl"), line).unwrap();

        let paths = paths(tmp.path());
        let vars = [("MINIMAL_OTEL_SPOOL_DIR", ours.to_str().unwrap())];
        let env = env_of(&vars);
        let out = tmp.path().join("bundle.tar.zst");
        let mut w = BundleWriter::create(&out, "root", "test").await.unwrap();
        spool_in(
            &mut w,
            &spool_dir(&paths, env("MINIMAL_OTEL_SPOOL_DIR")),
            1 << 20,
            &[],
        )
        .await
        .unwrap();
        w.finish(chrono::Utc::now(), std::time::Duration::ZERO)
            .await
            .unwrap();
        let files = unpack(&out, "root").await;
        assert!(files.contains_key("telemetry/spool/minimal-cli-1-1.jsonl"));
        assert!(
            !files.keys().any(|k| k.contains("minvmd-2-1")),
            "only the directory min bug resolves is read: {:?}",
            files.keys()
        );

        let state = telemetry_state(&paths, env).await;
        assert_eq!(state.spool_dir, ours);
        let json = serde_json_lenient::to_string(&state).unwrap();
        assert!(
            json.contains(&format!("\"spool_dir_note\":\"{SPOOL_DIR_NOTE}\"")),
            "{json}"
        );
    }

    /// The deciding-variable mirror in [`telemetry_state`] says on exactly
    /// where mlog's own decision spools (with no exporter set to `none`,
    /// spooling is the switch).
    #[tokio::test]
    async fn the_mirrored_switch_agrees_with_mlog() {
        let paths = paths(Path::new("/nonexistent"));
        let cases: &[&[(&str, &str)]] = &[
            &[],
            &[("MINIMAL_TELEMETRY", "1")],
            &[("MINIMAL_TELEMETRY", "TRUE")],
            &[("MINIMAL_TELEMETRY", "yes")],
            &[("MINIMAL_TELEMETRY", "0")],
            &[("MINIMAL_TELEMETRY", "maybe")],
            &[("MINIMAL_TELEMETRY", "1"), ("DO_NOT_TRACK", "false")],
            &[("MINIMAL_TELEMETRY", "1"), ("OTEL_SDK_DISABLED", "TRUE")],
            &[("MINIMAL_TELEMETRY", "1"), ("OTEL_SDK_DISABLED", "1")],
        ];
        for case in cases {
            let state = telemetry_state(&paths, env_of(case)).await;
            let var = env_of(case);
            let mlog_on =
                mlog::otel::guest_exports(|n| var(n).and_then(|v| v.into_string().ok())).spool;
            assert_eq!(state.enabled, mlog_on, "{case:?}");
        }
    }

    #[test]
    fn a_trace_lookup_passes_over_torn_lines() {
        let text = "torn\"}]}\n{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"traceId\":\"dd\",\"name\":\"cmd\"}]}]}]}\n";
        assert_eq!(newest_cmd_trace_id_in(text).as_deref(), Some("dd"));
        assert_eq!(newest_cmd_trace_id_in("{}\n"), None);
    }
}
